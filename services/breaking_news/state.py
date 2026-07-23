# services/breaking_news/state.py
"""MonitorState + EventCluster — symbolic fingerprint clustering with sliding window.

Replaces the dead embeddings-based semantic dedup. The previous design had a
bootstrap deadlock: sent_embeddings was never populated because kept_vectors
was always [] in the no-prior-state branch, so add_sent() received vec=None
forever. Embeddings also measured semantic proximity, not factual identity
("צה\"ל תקף בביירות" vs "חיזבאללה תקף בחיפה" → high cosine, different events).

New design: deterministic fingerprint (event_type, location, actor) extracted
via regex maps (fingerprint.py). Two items with the same fingerprint within
a sliding window (default 120 min) are the same event → consolidate. Time is
NOT part of the hash — sliding-window validation avoids hard bucket boundary
failures (12:59 vs 13:01 falling into different buckets).
"""

import asyncio
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_STATE_TTL_SECONDS = 43200  # 12 hours — link/title cache TTL
_STATE_VERSION = 4  # bumped from 3 (embeddings removed, clusters added)

# Sliding window: two items with the same fingerprint are the same event if
# less than this many seconds have passed since the cluster's last_seen.
# 120 min covers cross-feed publication lag (Ynet 12:59, Walla 13:01).
CLUSTER_WINDOW_SECONDS = 7200

# After this many seconds with no new corroborating item, a cluster is
# considered stale and a new item with the same fingerprint starts a NEW
# cluster (e.g., a different stabbing in Jerusalem 24h later).
CLUSTER_STALE_SECONDS = 86400  # 24h


@dataclass
class EventCluster:
    """A group of items reporting the same event from different feeds.

    Built incrementally: first item creates the cluster, subsequent items
    with the same fingerprint within the sliding window are appended.
    The dispatcher consolidates all items into a single alert with
    corroboration count + source list.
    """

    fingerprint_key: str
    items: list[dict] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def source_names(self) -> list[str]:
        """Distinct source names, in insertion order."""
        seen: set[str] = set()
        names: list[str] = []
        for it in self.items:
            src = it.get("source", "") or ""
            if src and src not in seen:
                seen.add(src)
                names.append(src)
        return names

    @property
    def corroboration_count(self) -> int:
        """Number of distinct sources reporting this event."""
        return len(self.source_names)

    @property
    def best_item(self) -> dict:
        """Pick the canonical item for the consolidated alert.

        Preference order:
        1. Item with a real RSS image (_image_from_rss=True) — image is the
           highest-value UI element, prefer a real photo over a favicon.
        2. Item with the longest title (most informative headline).
        3. First item (earliest publication) as tiebreaker.
        """
        if not self.items:
            return {}
        with_rss_image = [it for it in self.items if it.get("_image_from_rss")]
        if with_rss_image:
            return max(with_rss_image, key=lambda it: len(it.get("title", "")))
        return max(self.items, key=lambda it: len(it.get("title", "")))

    @property
    def best_image(self) -> str:
        """Best image URL across all cluster items.

        Real RSS image > og:image fallback > default favicon. If multiple
        items have real RSS images, pick the first (they're all real photos
        of the same event).
        """
        for it in self.items:
            if it.get("_image_from_rss") and it.get("image"):
                return it["image"]
        for it in self.items:
            if it.get("image"):
                return it["image"]
        return ""

    @property
    def all_links(self) -> list[tuple[str, str]]:
        """List of (source_name, link) for inline source buttons."""
        return [(it.get("source", "") or "מקור", it.get("link", "") or "") for it in self.items if it.get("link")]

    def add(self, item: dict, now: float) -> None:
        """Append an item to the cluster, update last_seen."""
        self.items.append(item)
        if not self.first_seen:
            self.first_seen = now
        self.last_seen = now

    def is_active(self, now: float) -> bool:
        """True if the cluster is still within the consolidation window."""
        return (now - self.last_seen) < CLUSTER_WINDOW_SECONDS

    def is_stale(self, now: float) -> bool:
        """True if the cluster has aged past stale threshold — new item starts a new cluster."""
        return (now - self.last_seen) > CLUSTER_STALE_SECONDS


@dataclass
class MonitorState:
    """Centralized dedup state — link/title cache + event clusters.

    sent_links/sent_titles: per-item exact-match dedup (unchanged behavior).
    clusters: fingerprint → EventCluster, for cross-feed consolidation.
    """

    sent_links: dict[str, float] = field(default_factory=dict)
    sent_titles: dict[str, float] = field(default_factory=dict)
    clusters: dict[str, EventCluster] = field(default_factory=dict)

    # Hard caps to prevent unbounded growth
    MAX_LINKS = 800
    MAX_TITLES = 800
    MAX_CLUSTERS = 200

    def cleanup(self, ttl: int = _STATE_TTL_SECONDS, now: float | None = None) -> None:
        """Remove entries older than TTL and enforce hard caps."""
        if now is None:
            now = time.time()
        cutoff = now - ttl
        before_links = len(self.sent_links)
        before_titles = len(self.sent_titles)
        before_clusters = len(self.clusters)

        self.sent_links = {k: v for k, v in self.sent_links.items() if v > cutoff}
        self.sent_titles = {k: v for k, v in self.sent_titles.items() if v > cutoff}
        # Clusters: evict stale ones (past stale threshold, not just TTL)
        self.clusters = {k: c for k, c in self.clusters.items() if (now - c.last_seen) < _STATE_TTL_SECONDS}

        if len(self.sent_links) > self.MAX_LINKS:
            self.sent_links = dict(list(self.sent_links.items())[-self.MAX_LINKS :])
        if len(self.sent_titles) > self.MAX_TITLES:
            self.sent_titles = dict(list(self.sent_titles.items())[-self.MAX_TITLES :])
        if len(self.clusters) > self.MAX_CLUSTERS:
            # Evict oldest by last_seen
            sorted_clusters = sorted(self.clusters.items(), key=lambda kv: kv[1].last_seen)
            self.clusters = dict(sorted_clusters[-self.MAX_CLUSTERS :])

        removed_links = before_links - len(self.sent_links)
        removed_titles = before_titles - len(self.sent_titles)
        removed_clusters = before_clusters - len(self.clusters)
        if removed_links or removed_titles or removed_clusters:
            logger.info(
                "[BreakingNews] Cleaned up %d old links, %d old titles, %d stale clusters",
                removed_links,
                removed_titles,
                removed_clusters,
            )

    def is_link_sent(self, link: str) -> bool:
        return link in self.sent_links

    def is_title_sent(self, title_sig: str) -> bool:
        return title_sig in self.sent_titles

    def find_cluster(self, fingerprint_key: str, now: float) -> EventCluster | None:
        """Find an active cluster for this fingerprint, or None.

        Returns the cluster if it exists AND is still within the consolidation
        window (is_active). A stale cluster (past 24h) is treated as absent —
        the caller will start a new cluster for a genuinely new event.
        """
        cluster = self.clusters.get(fingerprint_key)
        if cluster is None:
            return None
        if cluster.is_stale(now):
            logger.info(
                "[Cluster] Fingerprint %s stale (%.0f min old) — new event, new cluster",
                fingerprint_key,
                (now - cluster.last_seen) / 60,
            )
            return None
        return cluster

    def get_or_create_cluster(self, fingerprint_key: str, now: float) -> EventCluster:
        """Get an active cluster, or create a new one (replacing any stale one)."""
        cluster = self.find_cluster(fingerprint_key, now)
        if cluster is None:
            cluster = EventCluster(fingerprint_key=fingerprint_key)
            self.clusters[fingerprint_key] = cluster
        return cluster

    def add_sent(self, link: str, title_sig: str, now: float) -> None:
        """Record a sent item (link + title signature) for exact-match dedup."""
        if link:
            self.sent_links[link] = now
        if title_sig:
            self.sent_titles[title_sig] = now


async def load_state(path: Path) -> MonitorState:
    """Load state from JSON file with backward compat across versions."""
    now = time.time()
    state = MonitorState()
    if not path.exists():
        return state
    try:

        def _read():
            with open(path, encoding="utf-8") as f:
                return json.load(f)

        data = await asyncio.to_thread(_read)

        # sent_links: v1 list → dict, v3+ dict
        raw_links = data.get("sent_links", [])
        if isinstance(raw_links, list):
            state.sent_links = {k: now for k in raw_links}
        else:
            state.sent_links = dict(raw_links)

        raw_titles = data.get("sent_titles", [])
        if isinstance(raw_titles, list):
            state.sent_titles = {k: now for k in raw_titles}
        else:
            state.sent_titles = dict(raw_titles)

        # v4+: clusters. v3 and below had sent_embeddings (now dead code — dropped).
        raw_clusters = data.get("clusters", [])
        if isinstance(raw_clusters, list):
            for c_data in raw_clusters:
                key = c_data.get("fingerprint_key", "")
                if not key:
                    continue
                cluster = EventCluster(
                    fingerprint_key=key,
                    items=c_data.get("items", []),
                    first_seen=c_data.get("first_seen", now),
                    last_seen=c_data.get("last_seen", now),
                )
                state.clusters[key] = cluster
    except Exception as e:
        logger.error("[BreakingNews] Failed to load state: %s", e)
    return state


_SAVE_LOCK: asyncio.Lock | None = None


def _get_save_lock() -> asyncio.Lock:
    """Lazy-init save lock — must be called inside event loop."""
    global _SAVE_LOCK
    if _SAVE_LOCK is None:
        _SAVE_LOCK = asyncio.Lock()
    return _SAVE_LOCK


async def save_state(state: MonitorState, path: Path) -> None:
    """Save state to JSON atomically. Lock prevents concurrent overwrites."""
    async with _get_save_lock():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)

            def _write():
                tmp = path.with_suffix(".tmp")
                clusters_serialized = [
                    {
                        "fingerprint_key": c.fingerprint_key,
                        "items": c.items,
                        "first_seen": c.first_seen,
                        "last_seen": c.last_seen,
                    }
                    for c in state.clusters.values()
                ]
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(
                        {
                            "version": _STATE_VERSION,
                            "sent_links": state.sent_links,
                            "sent_titles": state.sent_titles,
                            "clusters": clusters_serialized,
                        },
                        f,
                        ensure_ascii=False,
                    )
                import os

                os.replace(tmp, path)

            await asyncio.to_thread(_write)
            logger.info(
                "[BreakingNews] State saved. Total sent links: %d | titles: %d | clusters: %d",
                len(state.sent_links),
                len(state.sent_titles),
                len(state.clusters),
            )
        except Exception as e:
            logger.error("[BreakingNews] Failed to save state: %s", e)
