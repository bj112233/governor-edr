# tests/test_coverage_batch2.py
"""Coverage tests for multiple high-gap modules.

Covers:
- services/breaking_news/{dedup,ai_scoring,ingestion,state,monitor}.py
- services/scheduled_news/{_service,_formatter,_fetcher}.py
- services/error_memory.py
- services/ip_enrich.py
- services/channel_loader.py
- services/ai_search.py
- services/formatters.py
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# breaking_news/dedup.py
# ═══════════════════════════════════════════════════════════════════════════


class TestLinkDedup:
    def test_filters_sent_links(self):
        from services.breaking_news.dedup import link_dedup
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        state.add_sent("http://old.com", "sig", now=0)
        items = [{"link": "http://old.com"}, {"link": "http://new.com"}]
        result = link_dedup(items, state)
        assert len(result) == 1
        assert result[0]["link"] == "http://new.com"

    def test_empty_items(self):
        from services.breaking_news.dedup import link_dedup
        from services.breaking_news.state import MonitorState

        assert link_dedup([], MonitorState()) == []


class TestClusterDedup:
    """Tests for cluster_dedup — replaces the deleted semantic_dedup."""

    def test_empty_items(self):
        from services.breaking_news.dedup import cluster_dedup
        from services.breaking_news.state import MonitorState

        assert cluster_dedup([], MonitorState(), now=0) == []

    def test_same_event_consolidated(self):
        from services.breaking_news.dedup import cluster_dedup
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        items = [
            {"title": "פיגוע דקירה בירושלים: מחבל דקר אזרח", "source": "Ynet", "link": "L1", "summary": ""},
            {"title": "מחבל דקר אזרח בירושלים: מצב קשה", "source": "Walla", "link": "L2", "summary": ""},
        ]
        clusters = cluster_dedup(items, state, now=0)
        assert len(clusters) == 1
        assert clusters[0].corroboration_count == 2

    def test_different_events_separate_clusters(self):
        from services.breaking_news.dedup import cluster_dedup
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        items = [
            {"title": "פיגוע דקירה בירושלים", "source": "Ynet", "link": "L1", "summary": ""},
            {"title": "רקטה נורתה לעבר אשקלון", "source": "Walla", "link": "L2", "summary": ""},
        ]
        clusters = cluster_dedup(items, state, now=0)
        assert len(clusters) == 2


class TestIntraBatchDedup:
    def test_dup_link_removed(self):
        from services.breaking_news.dedup import intra_batch_dedup

        items = [
            {"link": "http://a.com", "title": "A"},
            {"link": "http://a.com", "title": "B"},
        ]
        assert len(intra_batch_dedup(items)) == 1

    def test_dup_title_sig_removed(self):
        from services.breaking_news.dedup import intra_batch_dedup

        items = [
            {"link": "", "title": "Same Title"},
            {"link": "http://b.com", "title": "Same Title"},
        ]
        assert len(intra_batch_dedup(items)) == 1

    def test_unique_kept(self):
        from services.breaking_news.dedup import intra_batch_dedup

        items = [{"link": "http://a.com", "title": "A"}, {"link": "http://b.com", "title": "B"}]
        assert len(intra_batch_dedup(items)) == 2

    def test_empty(self):
        from services.breaking_news.dedup import intra_batch_dedup

        assert intra_batch_dedup([]) == []


# ═══════════════════════════════════════════════════════════════════════════
# breaking_news/ai_scoring.py
# ═══════════════════════════════════════════════════════════════════════════


class TestEnrichItems:
    async def test_enrich_success(self):
        from services.breaking_news.ai_scoring import enrich_items

        items = [{"title": "A", "summary": "s"}]
        enriched_data = [{"summary": "AI sum", "sentiment": "positive"}]
        bridge = MagicMock()
        bridge.should_accept_traffic.return_value = True
        with (
            patch("services.llm_bridge.LLMBridge") as mock_cls,
            patch("services.news_ai.bulk_enrich", AsyncMock(return_value=enriched_data)),
        ):
            mock_cls.get_instance.return_value = bridge
            result = await enrich_items(items)
            assert result[0]["ai_summary"] == "AI sum"
            assert result[0]["sentiment"] == "positive"

    async def test_enrich_bridge_not_ready(self):
        from services.breaking_news.ai_scoring import enrich_items

        items = [{"title": "A"}]
        bridge = MagicMock()
        bridge.should_accept_traffic.return_value = False
        with patch("services.llm_bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.return_value = bridge
            result = await enrich_items(items)
            assert result == items  # unchanged

    async def test_enrich_exception_swallowed(self):
        from services.breaking_news.ai_scoring import enrich_items

        items = [{"title": "A"}]
        with patch("services.llm_bridge.LLMBridge", side_effect=Exception("boom")):
            result = await enrich_items(items)
            assert result == items


class TestHuntAndEscalate:
    async def test_low_score_skipped(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        # No threat keywords → score 0
        await hunt_and_escalate("Weather update today", "text")

    async def test_high_score_no_channel(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        with patch("services.osint_hunter.hunt_and_analyze", AsyncMock(return_value={"critical_local_threat": True})):
            await hunt_and_escalate("CVE-2024 zero-day ransomware", "text")

    async def test_high_score_with_channel(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        channel = MagicMock()
        channel.send_message = AsyncMock()
        with (
            patch(
                "services.osint_hunter.hunt_and_analyze",
                AsyncMock(return_value={"critical_local_threat": True, "local_matches": ["match1"]}),
            ),
            patch("config.TELEGRAM_CHAT_ID", "123"),
        ):
            await hunt_and_escalate("CVE-2024 zero-day", "text", telegram_channel=channel)
            channel.send_message.assert_awaited()

    async def test_no_critical_threat(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        with patch("services.osint_hunter.hunt_and_analyze", AsyncMock(return_value={"critical_local_threat": False})):
            await hunt_and_escalate("ransomware attack", "text")

    async def test_false_positive_penalty(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        # "movie" → -5, "ransomware" → +3, net = -2 → skipped
        await hunt_and_escalate("ransomware movie", "text")

    async def test_exception_swallowed(self):
        from services.breaking_news.ai_scoring import hunt_and_escalate

        with patch("services.osint_hunter.hunt_and_analyze", AsyncMock(side_effect=Exception("boom"))):
            await hunt_and_escalate("ransomware", "text")  # should not raise


# ═══════════════════════════════════════════════════════════════════════════
# breaking_news/ingestion.py
# ═══════════════════════════════════════════════════════════════════════════


class TestIngestionHelpers:
    def test_is_placeholder_image(self):
        from services.breaking_news.ingestion import _is_placeholder_image

        assert _is_placeholder_image("http://x.com/placeholder.png")
        assert _is_placeholder_image("http://x.com/0/0.jpg")
        assert _is_placeholder_image("http://x.com/1x1.gif")
        assert not _is_placeholder_image("http://x.com/real.jpg")
        assert not _is_placeholder_image("")

    def test_first_media_url(self):
        from services.breaking_news.ingestion import _first_media_url

        entry = {"media_content": [{"url": "http://img.com/1.jpg"}, {"url": "http://img.com/2.jpg"}]}
        assert _first_media_url(entry, "media_content") == "http://img.com/1.jpg"
        assert _first_media_url({}, "media_content") == ""

    def test_enclosure_image_url(self):
        from services.breaking_news.ingestion import _enclosure_image_url

        entry = {"enclosures": [{"type": "image/jpeg", "href": "http://img.com/1.jpg"}]}
        assert _enclosure_image_url(entry) == "http://img.com/1.jpg"
        entry2 = {"enclosures": [{"type": "text/html", "href": "http://x.com"}]}
        assert _enclosure_image_url(entry2) == ""

    def test_img_from_html(self):
        from services.breaking_news.ingestion import _img_from_html

        entry = {"summary": '<p>Hello <img src="http://img.com/test.jpg"> world</p>'}
        assert _img_from_html(entry) == "http://img.com/test.jpg"
        assert _img_from_html({}) == ""

    def test_extract_image_url(self):
        from services.breaking_news.ingestion import _extract_image_url

        entry = {"media_content": [{"url": "http://real.com/1.jpg"}]}
        assert _extract_image_url(entry) == "http://real.com/1.jpg"
        # Placeholder filtered
        entry2 = {"media_content": [{"url": "http://x.com/placeholder.png"}]}
        assert _extract_image_url(entry2) == ""

    def test_extract_image_url_content_list(self):
        from services.breaking_news.ingestion import _img_from_html

        entry = {"content": [{"value": '<img src="http://x.com/img.jpg">'}]}
        assert _img_from_html(entry) == "http://x.com/img.jpg"


class TestFetchFeedItems:
    async def test_disabled_feed(self):
        from services.breaking_news.ingestion import fetch_feed_items

        session = MagicMock()
        assert await fetch_feed_items({"enabled": False, "url": "http://x.com"}, session) == []

    async def test_unsupported_type(self):
        from services.breaking_news.ingestion import fetch_feed_items

        session = MagicMock()
        assert await fetch_feed_items({"type": "atom", "url": "http://x.com"}, session) == []

    async def test_no_url(self):
        from services.breaking_news.ingestion import fetch_feed_items

        session = MagicMock()
        assert await fetch_feed_items({"type": "rss"}, session) == []


# ═══════════════════════════════════════════════════════════════════════════
# breaking_news/state.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMonitorState:
    def test_add_and_is_link_sent(self):
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        state.add_sent("http://link.com", "sig", now=0)
        assert state.is_link_sent("http://link.com")
        assert not state.is_link_sent("http://other.com")

    def test_is_title_sent(self):
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        state.add_sent("", "signature", now=0)
        assert state.is_title_sent("signature")
        assert not state.is_title_sent("other")

    def test_cleanup_removes_old(self):
        from services.breaking_news.state import MonitorState

        state = MonitorState()
        state.add_sent("http://old.com", "sig", now=0)
        state.cleanup(now=9999999999)
        # After cleanup, old entries should be gone
        assert not state.is_link_sent("http://old.com")


# ═══════════════════════════════════════════════════════════════════════════
# breaking_news/monitor.py
# ═══════════════════════════════════════════════════════════════════════════


class TestBreakingNewsMonitor:
    def test_singleton(self):
        from services.breaking_news.monitor import get_monitor

        m1 = get_monitor()
        m2 = get_monitor()
        assert m1 is m2

    async def test_check_breaking_news_empty(self):
        from services.breaking_news.monitor import BreakingNewsMonitor

        mon = BreakingNewsMonitor()
        with patch("services.breaking_news.ingestion.fetch_all_feeds", AsyncMock(return_value=[])):
            await mon.check_breaking_news()  # should not raise

    async def test_check_breaking_news_with_items(self):
        from services.breaking_news.monitor import BreakingNewsMonitor

        mon = BreakingNewsMonitor()
        items = [{"title": "Test", "link": "http://test.com", "summary": "s"}]
        with (
            patch("services.breaking_news.ingestion.fetch_all_feeds", AsyncMock(return_value=items)),
            patch("services.breaking_news.monitor.filter_by_keywords", return_value=items),
            patch("services.breaking_news.monitor.send_cluster_alert", AsyncMock(return_value=True)),
            patch("services.breaking_news.monitor.save_state", AsyncMock()),
            patch("services.breaking_news.ai_scoring.enrich_items", AsyncMock(return_value=items)),
            patch("services.breaking_news.og_image.enrich_missing_images", AsyncMock()),
        ):
            await mon.check_breaking_news()

    async def test_stop_monitor(self):
        from services.breaking_news.monitor import stop_monitor

        await stop_monitor()  # no-op


# ═══════════════════════════════════════════════════════════════════════════
# scheduled_news/_formatter.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatDigest:
    def test_empty(self):
        from services.scheduled_news._formatter import format_digest

        md = format_digest({})
        assert "עדכון יומי" in md

    def test_with_items(self):
        from services.scheduled_news._formatter import format_digest

        items = {"news_il": [{"title": "Test", "link": "http://x.com", "source": "Ynet", "summary": "Sum"}]}
        md = format_digest(items)
        assert "Test" in md
        assert "x.com" in md  # A+ shows domain, not full URL

    def test_empty_category_skipped(self):
        from services.scheduled_news._formatter import format_digest

        md = format_digest({"news_il": []})
        assert "חדשות" not in md  # A+ uses Hebrew labels

    def test_truncate(self):
        from services.scheduled_news._formatter import _truncate

        assert _truncate("short", 10) == "short"
        long_text = "a" * 200
        result = _truncate(long_text, 50)
        assert len(result) <= 53
        assert result.endswith("...")

    def test_truncate_at_space(self):
        from services.scheduled_news._formatter import _truncate

        text = "hello world foo bar baz"
        result = _truncate(text, 15)
        assert result.endswith("...")


# ═══════════════════════════════════════════════════════════════════════════
# scheduled_news/_fetcher.py
# ═══════════════════════════════════════════════════════════════════════════


class TestRssFetcher:
    async def test_disabled_feed(self):
        from services.scheduled_news._fetcher import RssFetcher

        f = RssFetcher()
        assert await f.fetch_feed({"enabled": False}) == []

    async def test_unsupported_type(self):
        from services.scheduled_news._fetcher import RssFetcher

        f = RssFetcher()
        assert await f.fetch_feed({"type": "atom", "url": "http://x.com"}) == []

    async def test_no_url(self):
        from services.scheduled_news._fetcher import RssFetcher

        f = RssFetcher()
        assert await f.fetch_feed({}) == []

    async def test_strip_html(self):
        from services.scheduled_news._fetcher import RssFetcher

        assert RssFetcher._strip_html("<p>hello</p>") == "hello"
        assert RssFetcher._strip_html("no html") == "no html"

    async def test_fetch_all_empty_profiles(self):
        from services.scheduled_news._fetcher import RssFetcher

        f = RssFetcher()
        result = await f.fetch_all([], 3)
        assert result == {}


# ═══════════════════════════════════════════════════════════════════════════
# scheduled_news/_service.py
# ═══════════════════════════════════════════════════════════════════════════


class TestScheduledNewsService:
    async def test_not_initialized(self):
        from services.scheduled_news._service import ScheduledNewsService

        svc = ScheduledNewsService()
        await svc.send_daily_digest()  # should log error, not raise

    async def test_initialize(self):
        from services.scheduled_news._service import ScheduledNewsService

        svc = ScheduledNewsService()
        with (
            patch("services.scheduled_news._service.load_delivery_config", return_value={}),
            patch("services.scheduled_news._service.load_profiles", return_value=[]),
            patch("services.scheduled_news._service.get_message_gateway", return_value=None, create=True),
        ):
            await svc.initialize()
            assert svc._delivery is not None

    async def test_send_daily_digest_with_items(self):
        from services.scheduled_news._service import ScheduledNewsService

        svc = ScheduledNewsService()
        svc._delivery = MagicMock()
        svc._delivery.fetch_all = AsyncMock(return_value={})
        svc._delivery.ai_enrich = AsyncMock()
        svc._delivery.send_digest = AsyncMock()
        svc._delivery.generate_sitrep = AsyncMock()
        svc._fetcher = MagicMock()
        svc._fetcher.fetch_all = AsyncMock(return_value={"news_il": [{"title": "T"}]})
        svc.profiles = [{"name": "news_il", "keywords": ["test"]}]
        svc.delivery_config = {"items_per_category": 3, "ai_digest": False}

        with patch("services.scheduled_news._service.format_digest", return_value="digest text"):
            await svc.send_daily_digest()
            svc._delivery.send_digest.assert_awaited()

    async def test_trigger_manual_digest(self):
        from services.scheduled_news._service import ScheduledNewsService

        svc = ScheduledNewsService()
        svc._delivery = None
        await svc.trigger_manual_digest()  # should log error


# ═══════════════════════════════════════════════════════════════════════════
# error_memory.py
# ═══════════════════════════════════════════════════════════════════════════


class TestErrorMemory:
    def test_embed_text(self):
        from services.error_memory import _embed_text

        assert _embed_text("err", "ctx") == "err\nctx"
        assert _embed_text("err", "") == "err"

    def test_format_lessons_empty(self):
        from services.error_memory import format_lessons_for_prompt

        assert format_lessons_for_prompt([]) == ""

    def test_format_lessons_basic(self):
        from services.error_memory import format_lessons_for_prompt

        lessons = [{"error_signature": "TimeoutError", "resolution": "Retry 3 times"}]
        result = format_lessons_for_prompt(lessons)
        assert "TimeoutError" in result
        assert "Retry 3 times" in result

    def test_format_lessons_truncation(self):
        from services.error_memory import format_lessons_for_prompt

        long_res = "x" * 300
        lessons = [{"error_signature": "err", "resolution": long_res}]
        result = format_lessons_for_prompt(lessons, max_resolution_chars=50)
        assert "…" in result
        assert len(result) < 200

    async def test_store_lesson_empty_skipped(self):
        from services.error_memory import store_lesson

        await store_lesson("", "ctx", "res")
        await store_lesson("err", "ctx", "")

    async def test_search_lessons_empty_query(self):
        from services.error_memory import search_lessons

        assert await search_lessons("") == []

    async def test_get_tool_stats_empty(self):
        from services.error_memory import get_tool_stats

        with patch("services.error_memory._ensure_table", AsyncMock()):
            with patch("services.error_memory._pool") as mock_pool:
                mock_db = AsyncMock()
                mock_cursor = AsyncMock()
                mock_cursor.__aenter__ = AsyncMock(return_value=mock_cursor)
                mock_cursor.__aexit__ = AsyncMock()
                mock_cursor.__aiter__ = MagicMock(return_value=iter([]))
                mock_db.execute = MagicMock(return_value=mock_cursor)
                mock_db.row_factory = None
                mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_pool.acquire.return_value.__aexit__ = AsyncMock()
                result = await get_tool_stats()
                assert result == {}

    async def test_get_errors_last_7d_empty(self):
        from services.error_memory import get_errors_last_7d

        with patch("services.error_memory._ensure_table", AsyncMock()):
            with patch("services.error_memory._pool") as mock_pool:
                mock_db = AsyncMock()
                mock_cursor = AsyncMock()
                mock_cursor.fetchall = AsyncMock(return_value=[])
                mock_db.execute = AsyncMock(return_value=mock_cursor)
                mock_db.row_factory = None
                mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db)
                mock_pool.acquire.return_value.__aexit__ = AsyncMock()
                result = await get_errors_last_7d()
                assert result == []


# ═══════════════════════════════════════════════════════════════════════════
# ip_enrich.py
# ═══════════════════════════════════════════════════════════════════════════


class TestIpEnrich:
    def test_localhost_returns_empty(self):
        from services.ip_enrich import enrich_ip

        enrich_ip.cache_clear()
        assert enrich_ip("127.0.0.1") == {}
        assert enrich_ip("::1") == {}

    def test_empty_ip(self):
        from services.ip_enrich import enrich_ip

        enrich_ip.cache_clear()
        assert enrich_ip("") == {}

    def test_no_geoip_available(self):
        from services.ip_enrich import _GeoIPReaders, enrich_ip

        enrich_ip.cache_clear()
        _GeoIPReaders.close()
        with patch("services.ip_enrich._GEOIP2_AVAILABLE", False):
            result = enrich_ip("8.8.8.8")
            assert result == {}

    def test_geoip_readers_close(self):
        from services.ip_enrich import _GeoIPReaders

        _GeoIPReaders.close()
        assert _GeoIPReaders._city is None
        assert _GeoIPReaders._asn is None


# ═══════════════════════════════════════════════════════════════════════════
# channel_loader.py
# ═══════════════════════════════════════════════════════════════════════════


class TestExpandEnvVars:
    def test_simple_var(self):
        import os

        from services.channel_loader import _expand_env_vars

        os.environ["TEST_CH_VAR"] = "hello"
        assert _expand_env_vars("${TEST_CH_VAR}") == "hello"
        del os.environ["TEST_CH_VAR"]

    def test_default_var(self):
        from services.channel_loader import _expand_env_vars

        assert _expand_env_vars("${UNKNOWN_VAR:-default}") == "default"

    def test_dict_recursive(self):
        import os

        from services.channel_loader import _expand_env_vars

        os.environ["TEST_CH_VAR2"] = "val"
        result = _expand_env_vars({"key": "${TEST_CH_VAR2}"})
        assert result["key"] == "val"
        del os.environ["TEST_CH_VAR2"]

    def test_list_recursive(self):
        import os

        from services.channel_loader import _expand_env_vars

        os.environ["TEST_CH_VAR3"] = "val"
        result = _expand_env_vars(["${TEST_CH_VAR3}"])
        assert result == ["val"]
        del os.environ["TEST_CH_VAR3"]

    def test_non_string_passthrough(self):
        from services.channel_loader import _expand_env_vars

        assert _expand_env_vars(42) == 42
        assert _expand_env_vars(None) is None


class TestLoadChannelsJson:
    def test_no_file_returns_defaults(self):
        from services.channel_loader import load_channels_json

        config = load_channels_json("/nonexistent/path.json")
        assert config is not None

    def test_valid_file(self, tmp_path):
        from services.channel_loader import load_channels_json

        p = tmp_path / "channels.json"
        p.write_text(json.dumps({"telegram": {"enabled": True, "bot_token": "test"}}), encoding="utf-8")
        config = load_channels_json(str(p))
        assert config.telegram.enabled is True

    def test_invalid_validation_returns_defaults(self, tmp_path):
        from services.channel_loader import load_channels_json

        p = tmp_path / "channels.json"
        p.write_text(json.dumps({"telegram": {"enabled": "not_a_bool"}}), encoding="utf-8")
        config = load_channels_json(str(p))
        assert config is not None


# ═══════════════════════════════════════════════════════════════════════════
# ai_search.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAiSearchQuota:
    def test_reserve_quota_within_limit(self):
        from services.ai_search import _quota_lock, _quota_state, _reserve_quota

        with _quota_lock:
            _quota_state["count"] = 0
        assert _reserve_quota() is True

    def test_reserve_quota_exhausted(self):
        from services.ai_search import _DAILY_QUOTA, _quota_lock, _quota_state, _reserve_quota

        with _quota_lock:
            _quota_state["count"] = _DAILY_QUOTA
        assert _reserve_quota() is False

    def test_get_quota_status(self):
        from services.ai_search import get_quota_status

        status = get_quota_status()
        assert "used" in status
        assert "limit" in status


class TestWebSearch:
    async def test_quota_exhausted(self):
        from services.ai_search import _DAILY_QUOTA, _quota_lock, _quota_state, web_search

        with _quota_lock:
            _quota_state["count"] = _DAILY_QUOTA
        result = await web_search("test")
        assert "מכסת" in result

    async def test_no_api_key_returns_raw(self):
        from services.ai_search import _quota_lock, _quota_state, web_search

        with _quota_lock:
            _quota_state["count"] = 0
        with (
            patch("services.ai_search.AI_SEARCH_API_KEY", None),
            patch("services.ai_search._simple_web_search", AsyncMock(return_value="raw results")),
        ):
            result = await web_search("test")
            assert "raw results" in result

    async def test_with_api_key(self):
        from services.ai_search import _quota_lock, _quota_state, web_search

        with _quota_lock:
            _quota_state["count"] = 0
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {"choices": [{"message": {"content": "AI answer"}}]}
        with (
            patch("services.ai_search.AI_SEARCH_API_KEY", "test-key"),
            patch("services.ai_search._simple_web_search", AsyncMock(return_value="raw results")),
            patch("services.ai_search.httpx.post", return_value=mock_response),
        ):
            result = await web_search("test")
            assert "AI answer" in result

    async def test_api_error_fallback(self):
        from services.ai_search import _quota_lock, _quota_state, web_search

        with _quota_lock:
            _quota_state["count"] = 0
        with (
            patch("services.ai_search.AI_SEARCH_API_KEY", "test-key"),
            patch("services.ai_search._simple_web_search", AsyncMock(return_value="raw results")),
            patch("services.ai_search.httpx.post", side_effect=Exception("network error")),
        ):
            result = await web_search("test")
            assert "raw results" in result


# ═══════════════════════════════════════════════════════════════════════════
# formatters.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatters:
    def test_header_emoji(self):
        from services.formatters import _header_emoji

        assert isinstance(_header_emoji("critical"), str)

    def test_format_proc(self):
        from services.formatters import _format_proc

        result = _format_proc({"name": "chrome", "cpu_percent": 50, "pid": 123})
        assert "chrome" in result

    def test_enrich_conn_line(self):
        from services.formatters import _enrich_conn_line

        result = _enrich_conn_line("chrome.exe (PID=123) | TCP -> 1.2.3.4:443")
        assert isinstance(result, str)

    def test_build_remediation_line(self):
        from services.formatters import _build_remediation_line

        result = _build_remediation_line({"action": "block_ip", "ip": "1.2.3.4"})
        assert isinstance(result, str)

    def test_build_intel_line(self):
        from services.formatters import _build_intel_line

        result = _build_intel_line({"trigger": "test", "report": "r"})
        assert isinstance(result, str)
