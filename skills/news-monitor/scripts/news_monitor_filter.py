"""News Monitor — Filter & dedup stage.

Link dedup, semantic dedup, auto-categorization, keyword matching, and
alert cooldown bookkeeping against persisted state.
"""

from __future__ import annotations

import hashlib
import logging
import time

from _news_utils import (
    Article,
    NewsMonitorArgs,
    _get_db,
    _get_state,
    _save_state,
)
from news_analyzer import semantic_dedup
from news_parser import auto_categorize, keyword_match

logger = logging.getLogger(__name__)


def _state_key(args: NewsMonitorArgs) -> str:
    """Deterministic 16-char key derived from the active source identifier."""
    return hashlib.sha256(
        (args.config or args.feed or args.site or "news").encode("utf-8")
    ).hexdigest()[:16]


def dedup_by_link(articles: list[Article]) -> list[Article]:
    """Stage 3: collapse articles sharing a link or title."""
    seen: set[str] = set()
    unique: list[Article] = []
    for art in articles:
        key = art.link or art.title
        if key in seen:
            continue
        seen.add(key)
        unique.append(art)
    return unique


async def apply_semantic_dedup(
    args: NewsMonitorArgs, articles: list[Article]
) -> list[Article]:
    """Stage 4: embedding-based semantic dedup against persisted state."""
    if not (args.semantic_dedup and articles):
        return articles
    return await semantic_dedup(articles, args.semantic_threshold, _state_key(args))


def apply_auto_categorize(
    args: NewsMonitorArgs, articles: list[Article]
) -> list[Article]:
    """Stage 5: rule-based auto categorization."""
    if not args.categorize:
        return articles
    return [auto_categorize(art) for art in articles]


async def apply_keyword_filter(
    args: NewsMonitorArgs, articles: list[Article]
) -> list[Article]:
    """Stage 6: keyword match, optionally gated by alert cooldown state."""
    if not args.keywords:
        return articles
    keywords = [k.strip() for k in args.keywords.split(",") if k.strip()]
    matched = keyword_match(articles, keywords)
    if not args.alert:
        return matched if matched else articles
    return await _alert_filter(args, matched)


async def _alert_filter(
    args: NewsMonitorArgs, matched: list[Article]
) -> list[Article]:
    """Return only fresh matches and persist updated seen-timestamps."""
    state_key = _state_key(args)
    seen_ts = await _load_seen_ts(state_key)
    now = time.time()
    cooldown = max(0, int(args.cooldown or 0))
    fresh = [m for m in matched if _is_fresh(m.link, seen_ts, now, cooldown)]
    for m in fresh:
        if m.link:
            seen_ts[m.link] = now
    if len(seen_ts) > 2000:
        seen_ts = dict(sorted(seen_ts.items(), key=lambda kv: kv[1])[-2000:])
    await _save_seen_ts(state_key, seen_ts)
    return fresh


async def _load_seen_ts(state_key: str) -> dict[str, float]:
    db = await _get_db()
    try:
        seen_ts_raw = await _get_state(db, f"news_monitor_{state_key}")
    finally:
        await db.close()
    if isinstance(seen_ts_raw, list):
        return {link: 0.0 for link in seen_ts_raw}
    if isinstance(seen_ts_raw, dict):
        return seen_ts_raw
    return {}


async def _save_seen_ts(state_key: str, seen_ts: dict[str, float]) -> None:
    db = await _get_db()
    try:
        await _save_state(db, f"news_monitor_{state_key}", seen_ts)
    finally:
        await db.close()


def _is_fresh(
    link: str, seen_ts: dict[str, float], now: float, cooldown: int
) -> bool:
    if not link:
        return False
    if cooldown == 0:
        return link not in seen_ts
    return (now - seen_ts.get(link, 0.0)) >= cooldown
