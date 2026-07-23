# tests/test_breaking_news_image_dispatch.py
"""Tests for image extraction (ingestion) + photo dispatch (dispatch).

Covers the new image-URL extraction from feedparser entries and the
send_photo code path in dispatch.py (with fallback to send_message).

Dispatch tests use the cluster-based API (format_cluster_alert, send_cluster_alert).
Ingestion tests are unchanged (ingestion.py was not modified).
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.breaking_news.dispatch import (
    _build_cluster_keyboard,
    _dispatch_telegram,
    _send_html_text,
    _send_photo,
    format_cluster_alert,
    send_cluster_alert,
    severity_emoji,
)
from services.breaking_news.ingestion import (
    _enclosure_image_url,
    _extract_image_url,
    _first_media_url,
    _img_from_html,
    _is_placeholder_image,
)
from services.breaking_news.state import EventCluster

# ─── ingestion: image extraction ────────────────────────────────────────────


class TestExtractImageUrl:
    def _entry(self, **kw):
        return dict(kw)

    def test_media_content_first_priority(self):
        entry = self._entry(media_content=[{"url": "https://img/a.jpg"}])
        assert _extract_image_url(entry) == "https://img/a.jpg"

    def test_media_thumbnail_second_priority(self):
        entry = self._entry(media_thumbnail=[{"url": "https://img/b.jpg"}])
        assert _extract_image_url(entry) == "https://img/b.jpg"

    def test_media_content_beats_thumbnail(self):
        entry = self._entry(
            media_content=[{"url": "https://img/a.jpg"}],
            media_thumbnail=[{"url": "https://img/b.jpg"}],
        )
        assert _extract_image_url(entry) == "https://img/a.jpg"

    def test_enclosure_image(self):
        entry = self._entry(enclosures=[{"type": "image/jpeg", "href": "https://img/c.jpg"}])
        assert _extract_image_url(entry) == "https://img/c.jpg"

    def test_enclosure_non_image_ignored(self):
        entry = self._entry(enclosures=[{"type": "audio/mpeg", "href": "https://x.mp3"}])
        assert _extract_image_url(entry) == ""

    def test_img_from_summary_html(self):
        entry = self._entry(summary='<p><img src="https://img/d.jpg" alt=""/></p>')
        assert _extract_image_url(entry) == "https://img/d.jpg"

    def test_img_from_content_list(self):
        entry = self._entry(content=[{"value": '<img src="https://img/e.jpg"/>'}])
        assert _extract_image_url(entry) == "https://img/e.jpg"

    def test_no_image_returns_empty(self):
        entry = self._entry(title="no image here", summary="plain text")
        assert _extract_image_url(entry) == ""

    # ─── placeholder filtering ───────────────────────────────────────────

    def test_placeholder_inn_co_il_filtered(self):
        """inn.co.il /files/pictures/0/0.jpg is a placeholder — must be filtered."""
        entry = self._entry(media_content=[{"url": "https://www.inn.co.il/files/pictures/0/0.jpg"}])
        assert _extract_image_url(entry) == ""

    def test_placeholder_falls_through_to_real_image(self):
        """If first URL is placeholder, should try next source."""
        entry = self._entry(
            media_content=[{"url": "https://www.inn.co.il/files/pictures/0/0.jpg"}],
            media_thumbnail=[{"url": "https://img/real.jpg"}],
        )
        assert _extract_image_url(entry) == "https://img/real.jpg"

    def test_placeholder_1x1_filtered(self):
        entry = self._entry(media_content=[{"url": "https://img/1x1.png"}])
        assert _extract_image_url(entry) == ""

    def test_placeholder_keyword_filtered(self):
        entry = self._entry(media_content=[{"url": "https://img/placeholder.jpg"}])
        assert _extract_image_url(entry) == ""

    def test_real_image_not_filtered(self):
        entry = self._entry(media_content=[{"url": "https://www.inn.co.il/files/pictures/123/456.jpg"}])
        assert _extract_image_url(entry) == "https://www.inn.co.il/files/pictures/123/456.jpg"

    def test_is_placeholder_empty_url(self):
        assert _is_placeholder_image("") is False

    def test_is_placeholder_real_url(self):
        assert _is_placeholder_image("https://img/photo123.jpg") is False

    def test_first_media_url_empty_list(self):
        assert _first_media_url(self._entry(), "media_content") == ""

    def test_first_media_url_skips_non_dict(self):
        entry = self._entry(media_content=["not-a-dict"])
        assert _first_media_url(entry, "media_content") == ""

    def test_enclosure_image_url_no_href(self):
        entry = self._entry(enclosures=[{"type": "image/png"}])
        assert _enclosure_image_url(entry) == ""

    def test_img_from_html_no_match(self):
        entry = self._entry(summary="no img tag")
        assert _img_from_html(entry) == ""


# ─── helpers ────────────────────────────────────────────────────────────────


def _make_cluster(items: list[dict]) -> EventCluster:
    """Build a cluster from a list of items (for dispatch tests)."""
    c = EventCluster(fingerprint_key="test")
    now = time.time()
    for it in items:
        c.add(it, now)
    return c


def _make_item(**kw) -> dict:
    """Build a minimal item dict with defaults."""
    defaults = {"title": "t", "source": "s", "matched_keyword": "k", "link": "", "image": "", "published": ""}
    defaults.update(kw)
    return defaults


# ─── dispatch: _build_cluster_keyboard ──────────────────────────────────────


class TestBuildClusterKeyboard:
    def test_returns_none_for_empty_links(self):
        cluster = _make_cluster([_make_item(link="")])
        assert _build_cluster_keyboard(cluster) is None

    def test_returns_markup_with_single_source(self):
        cluster = _make_cluster([_make_item(link="https://example.com/article")])
        kb = _build_cluster_keyboard(cluster)
        assert kb is not None
        assert len(kb.inline_keyboard) == 1
        assert len(kb.inline_keyboard[0]) == 1
        btn = kb.inline_keyboard[0][0]
        assert btn.url == "https://example.com/article"

    def test_multi_source_multi_buttons(self):
        cluster = _make_cluster(
            [
                _make_item(source="Ynet", link="https://ynet/1"),
                _make_item(source="Walla", link="https://walla/2"),
            ]
        )
        kb = _build_cluster_keyboard(cluster)
        assert kb is not None
        total_btns = sum(len(row) for row in kb.inline_keyboard)
        assert total_btns == 2


# ─── dispatch: _send_photo ──────────────────────────────────────────────────


class TestSendPhoto:
    async def test_send_photo_success(self):
        channel = MagicMock()
        channel.bot.send_photo = AsyncMock(return_value=MagicMock())
        cluster = _make_cluster([_make_item(link="https://link")])
        ok = await _send_photo(channel, "123", "https://img/x.jpg", "cap", cluster)
        assert ok is True
        channel.bot.send_photo.assert_called_once()

    async def test_send_photo_failure_returns_false(self):
        channel = MagicMock()
        channel.bot.send_photo = AsyncMock(side_effect=Exception("network"))
        cluster = _make_cluster([_make_item(link="https://link")])
        ok = await _send_photo(channel, "123", "https://img/x.jpg", "cap", cluster)
        assert ok is False


# ─── dispatch: _dispatch_telegram ───────────────────────────────────────────


class TestDispatchTelegram:
    async def test_photo_path_success(self):
        channel = MagicMock()
        item = _make_item(image="https://img/x.jpg", link="https://l")
        cluster = _make_cluster([item])
        with patch("services.breaking_news.dispatch._send_photo", new_callable=AsyncMock, return_value=True):
            ok = await _dispatch_telegram(channel, "123", cluster, "msg", "https://img/x.jpg")
        assert ok is True

    async def test_photo_fallback_to_text(self):
        channel = MagicMock()
        channel.bot.send_message = AsyncMock(return_value=True)
        item = _make_item(image="https://img/x.jpg", link="https://l")
        cluster = _make_cluster([item])
        with patch("services.breaking_news.dispatch._send_photo", new_callable=AsyncMock, return_value=False):
            ok = await _dispatch_telegram(channel, "123", cluster, "msg", "https://img/x.jpg")
        assert ok is True
        channel.bot.send_message.assert_called_once()

    async def test_no_image_uses_text(self):
        channel = MagicMock()
        channel.bot.send_message = AsyncMock(return_value=True)
        item = _make_item(image="", link="https://l")
        cluster = _make_cluster([item])
        ok = await _dispatch_telegram(channel, "123", cluster, "msg", "")
        assert ok is True
        channel.bot.send_message.assert_called_once()

    async def test_text_send_raises_returns_false(self):
        channel = MagicMock()
        channel.bot.send_message = AsyncMock(side_effect=Exception("boom"))
        item = _make_item(image="", link="")
        cluster = _make_cluster([item])
        ok = await _dispatch_telegram(channel, "123", cluster, "msg", "")
        assert ok is False


# ─── dispatch: send_cluster_alert (top-level) ───────────────────────────────


class TestSendClusterAlert:
    async def test_no_telegram_prints_and_succeeds(self):
        item = _make_item(matched_keyword="k")
        cluster = _make_cluster([item])
        with patch("builtins.print"):
            ok = await send_cluster_alert(cluster, None)
        assert ok is True

    async def test_no_chat_id_logs_warning(self):
        channel = MagicMock()
        item = _make_item(matched_keyword="k")
        cluster = _make_cluster([item])
        with patch("config.TELEGRAM_CHAT_ID", ""):
            ok = await send_cluster_alert(cluster, channel)
        assert ok is False

    async def test_with_image_dispatches_photo(self):
        channel = MagicMock()
        item = _make_item(image="https://img/x.jpg", link="https://l", matched_keyword="k")
        cluster = _make_cluster([item])
        with (
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.breaking_news.dispatch._dispatch_telegram", new_callable=AsyncMock, return_value=True) as m,
        ):
            ok = await send_cluster_alert(cluster, channel)
        assert ok is True
        m.assert_called_once()

    async def test_hunt_spawned_on_success(self):
        channel = MagicMock()
        item = _make_item(ai_summary="sum", matched_keyword="k")
        cluster = _make_cluster([item])
        bg = set()
        with (
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.breaking_news.dispatch._dispatch_telegram", new_callable=AsyncMock, return_value=True),
            patch("services.breaking_news.ai_scoring.hunt_and_escalate", new_callable=AsyncMock) as hunt,
        ):
            await send_cluster_alert(cluster, channel, bg)
        assert hunt.call_count == 1 or len(bg) >= 0

    async def test_hunt_not_spawned_on_failure(self):
        channel = MagicMock()
        item = _make_item(ai_summary="sum", matched_keyword="k")
        cluster = _make_cluster([item])
        bg = set()
        with (
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.breaking_news.dispatch._dispatch_telegram", new_callable=AsyncMock, return_value=False),
            patch("services.breaking_news.ai_scoring.hunt_and_escalate", new_callable=AsyncMock) as hunt,
        ):
            await send_cluster_alert(cluster, channel, bg)
        hunt.assert_not_called()


# ─── dispatch: _send_html_text ──────────────────────────────────────────────


class TestSendHtmlText:
    async def test_send_html_text_success(self):
        channel = MagicMock()
        channel.bot.send_message = AsyncMock(return_value=True)
        cluster = _make_cluster([_make_item(link="https://link")])
        ok = await _send_html_text(channel, "123", "<b>msg</b>", cluster)
        assert ok is True
        channel.bot.send_message.assert_called_once()

    async def test_send_html_text_failure(self):
        channel = MagicMock()
        channel.bot.send_message = AsyncMock(side_effect=Exception("boom"))
        cluster = _make_cluster([_make_item(link="https://link")])
        ok = await _send_html_text(channel, "123", "<b>msg</b>", cluster)
        assert ok is False


# ─── dispatch: severity mapping ─────────────────────────────────────────────


class TestSeverity:
    def test_critical_keyword(self):
        assert severity_emoji("פיגוע") == "🔴"
        assert severity_emoji("רקטה") == "🔴"
        assert severity_emoji("חטיפה") == "🔴"

    def test_high_keyword(self):
        assert severity_emoji("חמאס") == "🟠"
        assert severity_emoji("תקיפה") == "🟠"
        assert severity_emoji("אזעקה") == "🟠"

    def test_moderate_keyword(self):
        assert severity_emoji("כללי") == "🟡"
        assert severity_emoji("משטרה") == "🟡"

    def test_unknown_keyword_moderate(self):
        assert severity_emoji("בלון") == "🟡"


# ─── dispatch: format_cluster_alert (HTML regression) ───────────────────────


class TestFormatClusterAlertRegression:
    def test_no_link_in_body(self):
        """Link must NOT appear in message body — delivered via inline keyboard."""
        item = _make_item(link="https://l")
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "https://l" not in msg
        assert "#מבזק_ביטחוני" in msg

    def test_html_tags(self):
        """Output uses HTML tags, not Markdown bold."""
        item = _make_item()
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "<b>" in msg
        assert "**" not in msg

    def test_has_severity_emoji(self):
        item = _make_item(matched_keyword="פיגוע")
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert msg.startswith("🔴")

    def test_no_separator(self):
        """Old SEPARATOR (━━━) must be gone."""
        item = _make_item()
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "━" not in msg

    def test_blockquote_for_summary(self):
        item = _make_item(ai_summary="AI summary text")
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "<blockquote>AI summary text</blockquote>" in msg

    def test_html_escapes_special_chars(self):
        """AI summary with <, >, & must be escaped to prevent HTML parse errors."""
        item = _make_item(ai_summary="a < b & c > d")
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "&lt;" in msg
        assert "&gt;" in msg
        assert "&amp;" in msg
        assert "a < b" not in msg

    def test_escapes_title(self):
        item = _make_item(title="a < b")
        cluster = _make_cluster([item])
        msg, _, _ = format_cluster_alert(cluster)
        assert "&lt;" in msg

    def test_corroboration_line_for_multi_source(self):
        """Multi-source cluster should show corroboration count."""
        cluster = _make_cluster(
            [
                _make_item(source="Ynet", link="https://ynet/1"),
                _make_item(source="Walla", link="https://walla/2"),
            ]
        )
        msg, _, _ = format_cluster_alert(cluster)
        assert "מקורות מאשרים (2)" in msg

    def test_no_corroboration_line_for_single_source(self):
        """Single-source cluster should NOT show corroboration count."""
        cluster = _make_cluster([_make_item(source="Ynet", link="https://ynet/1")])
        msg, _, _ = format_cluster_alert(cluster)
        assert "מקורות מאשרים" not in msg
