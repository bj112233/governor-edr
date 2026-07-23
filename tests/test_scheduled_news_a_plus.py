# tests/test_scheduled_news_a_plus.py
"""A+ format + 24h filter + message splitting tests."""

import re
from datetime import UTC, datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from services.scheduled_news._delivery import _split_for_telegram
from services.scheduled_news._fetcher import RssFetcher
from services.scheduled_news._formatter import _extract_domain, _truncate, format_digest


class TestIsRecent:
    """24h age filter in _fetcher.py."""

    def test_recent_item_passes(self):
        now = format_datetime(datetime.now(UTC))
        assert RssFetcher._is_recent(now) is True

    def test_old_item_filtered(self):
        old = format_datetime(datetime.now(UTC) - timedelta(hours=48))
        assert RssFetcher._is_recent(old) is False

    def test_no_date_kept(self):
        assert RssFetcher._is_recent("") is True

    def test_garbage_date_kept(self):
        assert RssFetcher._is_recent("not a date") is True

    def test_boundary_23h_passes(self):
        dt = datetime.now(UTC) - timedelta(hours=23)
        assert RssFetcher._is_recent(format_datetime(dt)) is True

    def test_boundary_25h_filtered(self):
        dt = datetime.now(UTC) - timedelta(hours=25)
        assert RssFetcher._is_recent(format_datetime(dt)) is False


class TestExtractDomain:
    """Domain extraction from URL."""

    def test_simple(self):
        assert _extract_domain("https://www.walla.co.il/item/123") == "walla.co.il"

    def test_no_www(self):
        assert _extract_domain("https://ynet.co.il/news/123") == "ynet.co.il"

    def test_empty(self):
        assert _extract_domain("") == ""

    def test_garbage(self):
        assert _extract_domain("not a url") == ""


class TestFormatDigest:
    """A+ format structure."""

    def test_empty_categories(self):
        msg = format_digest({})
        assert "עדכון יומי" in msg
        assert "📊" in msg

    def test_header_box(self):
        msg = format_digest({"security_mil": []})
        assert "╭" in msg
        assert "╯" in msg

    def test_category_separator(self):
        msg = format_digest(
            {"security_mil": [{"title": "test", "link": "", "source": "s", "summary": "", "published": ""}]}
        )
        assert "ביטחון" in msg
        assert "─" * 10 in msg

    def test_item_bullet(self):
        msg = format_digest(
            {"security_mil": [{"title": "test title", "link": "", "source": "s", "summary": "", "published": ""}]}
        )
        assert "▸" in msg
        assert "test title" in msg

    def test_no_keyword_tag(self):
        """A+ format must NOT show keyword tag."""
        item = {"title": "t", "link": "", "source": "s", "summary": "", "published": "", "matched_keyword": "חיפה"}
        msg = format_digest({"security_mil": [item]})
        assert "🔑" not in msg
        assert "חיפה" not in msg  # keyword not shown

    def test_domain_link(self):
        item = {"title": "t", "link": "https://www.walla.co.il/item/123", "source": "s", "summary": "", "published": ""}
        msg = format_digest({"security_mil": [item]})
        assert "↗ walla.co.il" in msg
        assert "https://" not in msg  # no full URL

    def test_summary_truncated(self):
        long_summary = "a" * 300
        item = {"title": "t", "link": "", "source": "s", "summary": long_summary, "published": ""}
        msg = format_digest({"security_mil": [item]})
        assert "..." in msg
        assert len(msg) < 500  # not the full 300 chars

    def test_no_summary_no_summary_line(self):
        item = {"title": "t", "link": "", "source": "s", "summary": "", "published": ""}
        msg = format_digest({"security_mil": [item]})
        lines = msg.split("\n")
        # Item should have: bullet+title, source line, (no summary), (no link)
        item_lines = [ln for ln in lines if "t" in ln and "▸" in ln]
        assert len(item_lines) == 1

    def test_category_order_security_first(self):
        items = [{"title": "x", "link": "", "source": "s", "summary": "", "published": ""}]
        msg = format_digest({"sports": items, "security_mil": items, "news_il": items})
        sec_pos = msg.find("ביטחון")
        news_pos = msg.find("חדשות")
        sport_pos = msg.find("ספורט")
        assert sec_pos < news_pos < sport_pos

    def test_footer_stats(self):
        items = [{"title": "x", "link": "", "source": "s", "summary": "", "published": ""}]
        msg = format_digest({"security_mil": items, "news_il": items})
        assert "📊" in msg
        assert "2" in msg  # 2 categories
        assert "2 פריטים" in msg


class TestSplitForTelegram:
    """Message splitting at category boundaries."""

    def test_short_message_one_chunk(self):
        assert len(_split_for_telegram("short")) == 1

    def test_long_message_splits(self):
        # Create a message with multiple category headers
        sep = "─" * 25
        category = f"🛡️ ביטחון {sep}\n\n"
        item = "  ▸ title\n    source\n\n"
        long_msg = "header\n\n" + (category + item * 50) * 5
        chunks = _split_for_telegram(long_msg)
        assert len(chunks) > 1
        for c in chunks:
            assert len(c) <= 4000

    def test_chunks_preserve_emoji(self):
        sep = "─" * 25
        item = "  ▸ title\n    source\n\n"
        cat1 = f"🛡️ ביטחון {sep}\n\n" + item * 30
        cat2 = f"🇮🇱 חדשות {sep}\n\n" + item * 30
        msg = "header\n\n" + cat1 + cat2
        chunks = _split_for_telegram(msg)
        # Find chunk with חדשות
        news_chunk = [c for c in chunks if "חדשות" in c][0]
        assert "🇮🇱" in news_chunk  # emoji preserved
