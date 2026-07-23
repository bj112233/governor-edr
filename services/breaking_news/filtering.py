# services/breaking_news/filtering.py
"""Keyword filtering + title normalization + freshness gate."""

import logging
import re
import time

from services.time_format import feed_timestamp_to_epoch

logger = logging.getLogger(__name__)

# Reject items older than this (seconds). Prevents stale RSS/Telegram posts
# from being re-sent after a bot restart or when they linger in the feed.
_MAX_AGE_SECONDS = 3600  # 60 min


def _title_signature(title: str) -> str:
    """Normalize title for deduplication — strip punctuation, numbers, collapse whitespace."""
    cleaned = re.sub(r"[^\u0590-\u05ffa-zA-Z0-9\s]", "", title.lower())
    return " ".join(cleaned.split())


def filter_by_keywords(
    items: list[dict],
    keyword_regex: re.Pattern | None,
    secondary_regex: re.Pattern | None = None,
    context_regex: re.Pattern | None = None,
) -> list[dict]:
    """Filter items by urgent keywords using Hebrew-aware regex boundaries.

    Two-Stage Classifier: when a matched keyword is a "secondary" identifier
    (location/entity like חיפה/ירושלים), it only triggers an alert if a
    context modifier (security-signal word like אזעקה/פיגוע/יירוט) is also
    present in the text. Primary keywords (פיגוע/מחבל/חיסול) always pass.
    """
    if not keyword_regex:
        return items
    now = time.time()
    matched = []
    for item in items:
        # Freshness gate — reject items older than _MAX_AGE_SECONDS
        ts = feed_timestamp_to_epoch(item)
        if ts is not None and (now - ts) > _MAX_AGE_SECONDS:
            logger.debug(
                "[BreakingNews] DROP stale (%.0f min old): '%s...'",
                (now - ts) / 60,
                item.get("title", "")[:50],
            )
            continue
        text = f"{item.get('title', '')} {item.get('summary', '')}"
        m = keyword_regex.search(text)
        if not m:
            continue
        kw = m.group(1)
        # Two-Stage: secondary keyword requires context modifier
        if secondary_regex and secondary_regex.match(kw) and context_regex:
            if not context_regex.search(text):
                logger.debug(
                    "[BreakingNews] DROP false positive: '%s' without context in '%s...'",
                    kw,
                    item.get("title", "")[:50],
                )
                continue
        item["matched_keyword"] = kw
        matched.append(item)
        logger.info(
            "[BreakingNews] MATCH: '%s' in '%s...' from %s",
            kw,
            item.get("title", "")[:50],
            item.get("source", "Unknown"),
        )
    logger.info(
        "[BreakingNews] Found %d urgent items out of %d",
        len(matched),
        len(items),
    )
    return matched
