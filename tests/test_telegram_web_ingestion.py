# tests/test_telegram_web_ingestion.py
"""Tests for Telegram web preview ingestion (t.me/s/{channel} HTML scrape)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.breaking_news.ingestion import _fetch_telegram_web, fetch_feed_items

# Minimal HTML mimicking t.me/s/{channel} structure
_SAMPLE_HTML = """
<div class="tgme_widget_message_wrap">
  <a class="tgme_widget_message_date" href="https://t.me/ramreports/210907">
    <time datetime="2026-07-07T11:44:00+00:00">11:44</time>
  </a>
  <div class="tgme_widget_message_text">
    *צה"ל ושב"כ חיסלו מפקד חוליית נוח'בה*
    צה"ל תקף שלשום בצפון רצועת עזה
    מבזקי ⚡️ רעם מבזקי חדשות בזמן אמת 📲 https://t.me/ramreports
  </div>
</div>
<div class="tgme_widget_message_wrap">
  <a class="tgme_widget_message_date" href="https://t.me/ramreports/210908">
    <time datetime="2026-07-07T11:46:00+00:00">11:46</time>
  </a>
  <div class="tgme_widget_message_text">
    כל הכבוד לצה"ל על החיסולים
    מבזקי ⚡️ רעם מבזקי חדשות בזמן אמת 📲 https://t.me/ramreports
  </div>
</div>
<div class="tgme_widget_message_wrap">
  <a class="tgme_widget_message_date" href="https://t.me/ramreports/210906">
    <time datetime="2026-07-07T11:28:00+00:00">11:28</time>
  </a>
  <div class="tgme_widget_message_video_player">
    <i class="tgme_widget_message_video_thumb"></i>
  </div>
</div>
<div class="tgme_widget_message_wrap">
  <a class="tgme_widget_message_date" href="https://t.me/ramreports/210919">
    <time datetime="2026-07-07T13:29:00+00:00">13:29</time>
  </a>
  <div class="tgme_widget_message_text">
    אנחנו אוהבים אותכם ❤️
    מבזקי ⚡️ רעם מבזקי חדשות בזמן אמת 📲 https://t.me/ramreports
  </div>
</div>
"""

_FEED = {
    "name": "מבזקי רעם",
    "channel": "ramreports",
    "type": "telegram_web",
    "category": "breaking",
    "default_image": "https://example.com/favicon.png",
}


class TestFetchTelegramWeb:
    """Core parsing + signature stripping + media-only skip."""

    @pytest.fixture
    def _mock_session(self):
        """aiohttp session mock that returns _SAMPLE_HTML."""
        session = MagicMock()
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=None)
        ctx.raise_for_status = MagicMock()
        ctx.text = AsyncMock(return_value=_SAMPLE_HTML)
        session.get = MagicMock(return_value=ctx)
        return session

    async def test_parses_text_messages(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=10)
        # 4 messages in HTML, 1 is media-only (no text) → 3 items
        assert len(items) == 3

    async def test_strips_signature_footer(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=10)
        for item in items:
            assert "מבזקי" not in item["title"]
            assert "רעם" not in item["title"]
            assert "t.me/ramreports" not in item["summary"]

    async def test_extracts_link_and_datetime(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=10)
        links = [it["link"] for it in items]
        assert "https://t.me/ramreports/210907" in links
        item_907 = next(it for it in items if "210907" in it["link"])
        assert item_907["published"] == "2026-07-07T11:44:00+00:00"

    async def test_skips_media_only_messages(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=10)
        links = [it["link"] for it in items]
        # 210906 is media-only (video, no text_el) → must not appear
        assert "https://t.me/ramreports/210906" not in links

    async def test_item_dict_structure(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=10)
        item = items[0]
        required_keys = {"title", "link", "published", "summary", "image", "_image_from_rss", "category", "source"}
        assert required_keys.issubset(item.keys())
        assert item["source"] == "מבזקי רעם"
        assert item["category"] == "breaking"
        assert item["_image_from_rss"] is False
        assert item["image"] == "https://example.com/favicon.png"

    async def test_title_truncated(self, _mock_session):
        long_text = "A" * 500 + " מבזקי ⚡️ רעם מבזקי חדשות בזמן אמת 📲 https://t.me/ramreports"
        html = f'<div class="tgme_widget_message_wrap"><a class="tgme_widget_message_date" href="https://t.me/x/1"><time datetime="2026-01-01T00:00:00+00:00"></time></a><div class="tgme_widget_message_text">{long_text}</div></div>'
        session = MagicMock()
        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=ctx)
        ctx.__aexit__ = AsyncMock(return_value=None)
        ctx.raise_for_status = MagicMock()
        ctx.text = AsyncMock(return_value=html)
        session.get = MagicMock(return_value=ctx)
        items = await _fetch_telegram_web(_FEED, session, limit=10)
        assert len(items) == 1
        assert len(items[0]["title"]) <= 200

    async def test_limit_respected(self, _mock_session):
        items = await _fetch_telegram_web(_FEED, _mock_session, limit=2)
        assert len(items) == 2

    async def test_empty_channel_returns_empty(self):
        feed = {"name": "test", "channel": "", "type": "telegram_web"}
        result = await _fetch_telegram_web(feed, session=None)
        assert result == []

    async def test_missing_channel_key_returns_empty(self):
        feed = {"name": "test", "type": "telegram_web"}
        result = await _fetch_telegram_web(feed, session=None)
        assert result == []


class TestFetchFeedItemsDispatch:
    """Verify dispatcher routes telegram_web correctly."""

    async def test_dispatch_routes_telegram_web(self):
        feed = {"name": "test", "channel": "test", "type": "telegram_web", "enabled": True}
        with patch(
            "services.breaking_news.ingestion._fetch_telegram_web",
            new_callable=AsyncMock,
            return_value=[{"title": "x"}],
        ) as mock:
            result = await fetch_feed_items(feed, session=None, limit=5)
            assert result == [{"title": "x"}]
            mock.assert_awaited_once()

    async def test_disabled_telegram_feed_skipped(self):
        feed = {"name": "test", "channel": "test", "type": "telegram_web", "enabled": False}
        result = await fetch_feed_items(feed, session=None)
        assert result == []
