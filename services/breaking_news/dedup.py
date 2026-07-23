# services/breaking_news/dedup.py
"""Deduplication: link exact, fingerprint clustering, intra-batch.

Replaces the embeddings-based semantic_dedup (dead code — bootstrap deadlock
in the no-prior-state branch kept sent_embeddings empty forever, and embeddings
measure semantic proximity not factual identity). See state.py + fingerprint.py.
"""

import logging
import time

from .filtering import _title_signature
from .fingerprint import extract_fingerprint
from .state import EventCluster, MonitorState

logger = logging.getLogger(__name__)


def link_dedup(items: list[dict], state: MonitorState) -> list[dict]:
    """Step 1: exact link + title dedup against state (cross-cycle).

    Checks both link and normalized title signature — Telegram posts with
    different message IDs (different links) but the same headline are caught
    by the title check, which is_title_sent was never wired in before.
    """
    deduped = []
    title_dups = 0
    for it in items:
        if state.is_link_sent(it.get("link", "")):
            continue
        sig = _title_signature(it.get("title", "") or "")
        if sig and state.is_title_sent(sig):
            title_dups += 1
            logger.debug(
                "[BreakingNews] SKIP cross-cycle dup title: '%s...'",
                it.get("title", "")[:50],
            )
            continue
        deduped.append(it)
    logger.info(
        "[BreakingNews] Link+title dedup: %d -> %d (link/title dups filtered)",
        len(items),
        len(deduped),
    )
    return deduped


def cluster_dedup(items: list[dict], state: MonitorState, now: float | None = None) -> list[EventCluster]:
    """Step 2: cluster items by event fingerprint within sliding window.

    Each item is assigned to a cluster keyed by its fingerprint hash. If an
    active cluster exists for that fingerprint (within CLUSTER_WINDOW_SECONDS),
    the item is appended to it (corroboration). If the cluster is stale or
    absent, a new one is created.

    Returns the list of clusters that received at least one new item this
    cycle. The monitor dispatches one consolidated alert per cluster.
    """
    if now is None:
        now = time.time()
    touched: dict[str, EventCluster] = {}

    no_fp_count = 0
    for it in items:
        title = it.get("title", "") or ""
        summary = it.get("summary", "") or ""
        fp = extract_fingerprint(title, summary)
        # Require event_type for clustering — without it, location-only or
        # actor-only fingerprints merge unrelated events.
        # Require actor for ALL clustering — without actor, event_type+location
        # alone merge unrelated events that share a broad type (e.g. 15 different
        # "תקיפה_כללית|איראן|" headlines merged into one cluster).
        _SOFT_TYPES = {"הצהרה_דיפלומטית", "חקיקה", "מינוי_פוליטי"}
        if fp.is_empty or not fp.event_type:
            no_fp_count += 1
            logger.debug(
                "[BreakingNews] No fingerprint: title=%r summary=%r",
                title[:120],
                summary[:120],
            )
            link = it.get("link", "") or str(id(it))
            key = f"nolink:{hash(link) & 0xFFFFFFFF:08x}"
        elif not fp.actor:
            # No actor → cannot disambiguate events with same type+location
            no_fp_count += 1
            logger.debug(
                "[BreakingNews] No actor — singleton: type=%s loc=%s title=%r",
                fp.event_type,
                fp.location,
                title[:120],
            )
            link = it.get("link", "") or str(id(it))
            key = f"nolink:{hash(link) & 0xFFFFFFFF:08x}"
        elif fp.event_type in _SOFT_TYPES:
            # Soft type even with actor → too broad, singleton
            no_fp_count += 1
            logger.debug(
                "[BreakingNews] Soft type — singleton: type=%s title=%r",
                fp.event_type,
                title[:120],
            )
            link = it.get("link", "") or str(id(it))
            key = f"nolink:{hash(link) & 0xFFFFFFFF:08x}"
        else:
            key = fp.key

        cluster = state.get_or_create_cluster(key, now)
        cluster.add(it, now)
        touched[key] = cluster

    if no_fp_count:
        logger.info(
            "[BreakingNews] %d items had no extractable fingerprint — singleton clusters",
            no_fp_count,
        )
    logger.info(
        "[BreakingNews] Cluster dedup: %d items → %d clusters",
        len(items),
        len(touched),
    )
    return list(touched.values())


def intra_batch_dedup(items: list[dict]) -> list[dict]:
    """Step 3: dedup within the same fetch batch (exact link/title)."""
    seen_links: set = set()
    seen_sigs: set = set()
    deduped: list[dict] = []
    for it in items:
        link = it.get("link", "") or ""
        sig = _title_signature(it.get("title", "") or "")
        if link and link in seen_links:
            logger.info(
                "[BreakingNews] SKIP intra-batch dup link: %s...",
                it.get("title", "")[:50],
            )
            continue
        if sig and sig in seen_sigs:
            logger.info(
                "[BreakingNews] SKIP intra-batch dup title: %s...",
                it.get("title", "")[:50],
            )
            continue
        if link:
            seen_links.add(link)
        if sig:
            seen_sigs.add(sig)
        deduped.append(it)
    removed = len(items) - len(deduped)
    if removed:
        logger.info(
            "[BreakingNews] Intra-batch dedup removed %d duplicates",
            removed,
        )
    return deduped
