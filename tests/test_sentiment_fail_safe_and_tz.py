# tests/test_sentiment_fail_safe_and_tz.py
"""Regression tests for:
1. Sentiment fallback off-by-one (positional mapping corruption)
2. Double timezone offset (feedparser UTC assumption for Israeli feeds)
"""

import calendar
import time
import zoneinfo
from datetime import UTC, datetime

from services.news_ai.prompts import parse_bulk_sentiment
from services.time_format import format_feed_time

_JERUSALEM = zoneinfo.ZoneInfo("Asia/Jerusalem")


# ── Sentiment fallback fail-safe ──


def test_sentiment_fallback_exact_match():
    """Fallback applies when found count == expected count."""
    text = "1. positive\n2. negative\n3. neutral"
    result = parse_bulk_sentiment(text, 3)
    assert result == ["positive", "negative", "neutral"]


def test_sentiment_fallback_length_mismatch_aborts():
    """Fallback aborts when LLM skipped an item (found < expected).

    Bug: positional mapping shifted all results by one, corrupting the batch.
    Fix: only apply if len(found) == n, else leave "unknown".
    """
    # LLM returned only 2 sentiments for 3 items (skipped item 2)
    text = "1. positive\n3. neutral"
    result = parse_bulk_sentiment(text, 3)
    assert result == ["positive", "unknown", "neutral"]  # item 2 stays unknown
    # Crucially: item 3 is NOT mapped to position 2
    assert result[1] == "unknown"  # not "neutral" (the old off-by-one bug)


def test_sentiment_fallback_too_many_aborts():
    """Fallback also aborts when found > expected (LLM hallucinated extra)."""
    text = "positive negative neutral positive"
    result = parse_bulk_sentiment(text, 2)
    # 4 found != 2 expected → don't apply positional mapping
    assert result == ["unknown", "unknown"]


def test_sentiment_numbered_format_works():
    """Normal numbered format still parses correctly."""
    text = "1. positive\n2. negative"
    result = parse_bulk_sentiment(text, 2)
    assert result == ["positive", "negative"]


# ── Double timezone offset fix ──


def test_israeli_feed_no_double_offset():
    """Israeli feed with naive pubDate should NOT get +3h double offset.

    Bug: feedparser labels naive IL time as UTC. time_format adds +3h
    for Jerusalem display → 16:00 IL becomes 19:00 IL.

    Fix: detect Israeli source, strip fake UTC, re-attach Jerusalem tz,
    convert to real UTC, then display in Jerusalem time.
    """
    # Simulate: Israeli feed publishes 16:00 IL time
    # feedparser gives published_parsed as struct_time for 16:00 (assumed UTC)
    fake_pp = time.struct_time((2026, 6, 22, 16, 0, 0, 0, 0, 0))
    item = {
        "published_parsed": fake_pp,
        "source": "walla",
        "category": "israel",
    }
    result = format_feed_time(item)
    # Should show 16:00 (the original IL time), NOT 19:00 (double offset)
    assert "16:00" in result, f"Expected 16:00, got {result} (double offset bug)"


def test_non_israeli_feed_uses_utc_correctly():
    """Non-Israeli feed with UTC pubDate should convert to Jerusalem time (+3h)."""
    # Reuters publishes 13:00 UTC
    fake_pp = time.struct_time((2026, 6, 22, 13, 0, 0, 0, 0, 0))
    item = {
        "published_parsed": fake_pp,
        "source": "reuters",
        "category": "world",
    }
    result = format_feed_time(item)
    # 13:00 UTC → 16:00 Jerusalem (IDT = UTC+3)
    assert "16:00" in result, f"Expected 16:00 (13:00 UTC +3), got {result}"


def test_israeli_feed_winter_time():
    """Israeli feed in winter (IDT → IST = UTC+2) should not double-offset."""
    # February = winter time (UTC+2)
    fake_pp = time.struct_time((2026, 2, 15, 10, 0, 0, 0, 0, 0))
    item = {
        "published_parsed": fake_pp,
        "source": "ynet",
        "category": "israel",
    }
    result = format_feed_time(item)
    # 10:00 IL time should stay 10:00, not become 12:00
    assert "10:00" in result, f"Expected 10:00, got {result} (winter double offset)"


# ── Numeric tz offset + mislabeled GMT fix (2026-07-05) ──


def test_israeli_feed_with_numeric_tz_no_correction():
    """Israeli feed that publishes with a real numeric tz offset (e.g. Ynet +0300)
    should NOT get the Israeli correction — feedparser already converted to UTC.

    Bug: the correction blindly treated published_parsed as naive local time,
    subtracting 3h from a properly timezone-aware date.
    16:42 +0300 → feedparser pp=13:42 UTC → correction → 13:42 IL (WRONG)
    Fix: detect numeric tz in raw string, skip correction → 16:42 IL (correct)
    """
    fake_pp = time.struct_time((2026, 7, 5, 13, 42, 2, 0, 0, 0))  # 16:42 +0300 → 13:42 UTC
    item = {
        "published": "Sun, 05 Jul 2026 16:42:02 +0300",
        "published_parsed": fake_pp,
        "source": "ynet",
        "category": "breaking",
    }
    result = format_feed_time(item)
    assert "16:42" in result, f"Expected 16:42 (real +0300), got {result} (wrong correction)"


def test_mislabeled_gmt_source_still_corrected():
    """Walla publishes local time mislabeled as 'GMT' — correction must still apply.

    16:48 'GMT' (actually IDT) → feedparser pp=16:48 UTC → correction → 16:48 IL
    Without correction it would show 19:48 IL (3h ahead).
    """
    fake_pp = time.struct_time((2026, 7, 5, 16, 48, 0, 0, 0, 0))
    item = {
        "published": "Sun, 05 Jul 2026 16:48:00 GMT",
        "published_parsed": fake_pp,
        "source": "walla",
        "category": "breaking",
    }
    result = format_feed_time(item)
    assert "16:48" in result, f"Expected 16:48 (mislabeled GMT), got {result}"


def test_real_gmt_source_not_corrected():
    """Maariv publishes real UTC labeled as 'GMT' — correction must NOT apply.

    13:44 GMT (real UTC) → feedparser pp=13:44 UTC → no correction → 16:44 IL
    With correction it would show 13:44 IL (3h behind).
    """
    fake_pp = time.struct_time((2026, 7, 5, 13, 44, 0, 0, 0, 0))
    item = {
        "published": "Sun, 05 Jul 2026 13:44:00 GMT",
        "published_parsed": fake_pp,
        "source": "maariv",
        "category": "breaking",
    }
    result = format_feed_time(item)
    assert "16:44" in result, f"Expected 16:44 (real GMT→IL +3), got {result} (wrong correction)"
