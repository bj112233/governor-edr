# tests/test_tools_news_coverage.py
"""Coverage tests for tools, news AI, translation bypass, and filesystem tools.

Covers uncovered functions/branches in:
  - services/tools/mcp_skill_handlers.py
  - services/tools/system_tools.py
  - services/tools/_infra_handler.py
  - services/news_ai/single.py
  - services/news_ai/prompts.py
  - services/agent/bypass/translation.py
  - services/agent/bypass/_translation_handlers.py
  - services/fs_tools.py

All network/LLM/subprocess calls are mocked. Real temp filesystem where possible.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── mcp_skill_handlers ──────────────────────────────────────────────────────


class TestTriggerNewsDigestTool:
    @patch("services.tools.mcp_skill_handlers.get_news_service", create=True)
    async def test_trigger_no_category(self, _mock_get):
        with patch("services.scheduled_news.get_news_service") as mock_get:
            svc = MagicMock()
            svc.initialize = AsyncMock()
            svc.trigger_manual_digest = AsyncMock()
            mock_get.return_value = svc
            from services.tools.mcp_skill_handlers import trigger_news_digest_tool

            result = await trigger_news_digest_tool()
            assert "הדייג׳סט התחיל" in result
            svc.initialize.assert_awaited_once()

    @patch("services.scheduled_news.get_news_service")
    async def test_trigger_with_category(self, mock_get):
        svc = MagicMock()
        svc.initialize = AsyncMock()
        svc.trigger_manual_digest = AsyncMock()
        mock_get.return_value = svc
        from services.tools.mcp_skill_handlers import trigger_news_digest_tool

        result = await trigger_news_digest_tool(category="cyber")
        assert "cyber" in result

    @patch("services.scheduled_news.get_news_service")
    async def test_trigger_failure_returns_error(self, mock_get):
        mock_get.side_effect = RuntimeError("boom")
        from services.tools.mcp_skill_handlers import trigger_news_digest_tool

        result = await trigger_news_digest_tool()
        assert "❌" in result
        assert "boom" in result


class TestRecentMemoryTool:
    async def test_no_entries(self):
        svc = MagicMock()
        svc._ensure_init = AsyncMock()
        svc.get_recent = AsyncMock(return_value=[])
        with (
            patch("services.bot_memory.crud.get_memory_service", return_value=svc),
            patch("services.tools.mcp_skill_handlers._get_memory_stats", new=AsyncMock(return_value="stats")),
        ):
            from services.tools.mcp_skill_handlers import recent_memory_tool

            result = await recent_memory_tool()
            assert "0" in result
            assert "אין זיכרונות" in result

    async def test_with_entries(self):
        entry = MagicMock()
        entry.ts = "2024-01-01T10:00:00"
        entry.query = "What is MITRE?"
        entry.response = "A framework."
        svc = MagicMock()
        svc._ensure_init = AsyncMock()
        svc.get_recent = AsyncMock(return_value=[entry])
        with (
            patch("services.bot_memory.crud.get_memory_service", return_value=svc),
            patch("services.tools.mcp_skill_handlers._get_memory_stats", new=AsyncMock(return_value="stats")),
        ):
            from services.tools.mcp_skill_handlers import recent_memory_tool

            result = await recent_memory_tool(limit=1)
            assert "MITRE" in result
            assert "framework" in result

    async def test_long_query_truncated(self):
        entry = MagicMock()
        entry.ts = "2024-01-01T10:00:00"
        entry.query = "x" * 200
        entry.response = "y" * 200
        svc = MagicMock()
        svc._ensure_init = AsyncMock()
        svc.get_recent = AsyncMock(return_value=[entry])
        with (
            patch("services.bot_memory.crud.get_memory_service", return_value=svc),
            patch("services.tools.mcp_skill_handlers._get_memory_stats", new=AsyncMock(return_value="stats")),
        ):
            from services.tools.mcp_skill_handlers import recent_memory_tool

            result = await recent_memory_tool()
            assert "…" in result

    async def test_failure_returns_error(self):
        with patch("services.bot_memory.crud.get_memory_service", side_effect=RuntimeError("db down")):
            from services.tools.mcp_skill_handlers import recent_memory_tool

            result = await recent_memory_tool()
            assert "❌" in result


class TestGetMemoryStats:
    async def test_stats_success(self):
        svc = MagicMock()
        db = AsyncMock()
        cursor = AsyncMock()
        # Simulate 4 sequential fetchone calls
        cursor.fetchone = AsyncMock(side_effect=[(5,), (2,), (1,), ("2024-01-01T00:00:00", "2024-06-01T00:00:00")])
        db.execute = AsyncMock(return_value=cursor)
        pool = MagicMock()
        pool.acquire.return_value.__aenter__ = AsyncMock(return_value=db)
        pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

        with patch("services.bot_memory.crud._pool", pool):
            from services.tools.mcp_skill_handlers import _get_memory_stats

            result = await _get_memory_stats(svc)
            assert "5" in result
            assert "2" in result

    async def test_stats_failure(self):
        pool = MagicMock()
        pool.acquire.side_effect = RuntimeError("no db")
        with patch("services.bot_memory.crud._pool", pool):
            from services.tools.mcp_skill_handlers import _get_memory_stats

            result = await _get_memory_stats(MagicMock())
            assert "לא זמינות" in result


class TestSkillFileAnalyst:
    async def test_no_path(self):
        from services.tools.mcp_skill_handlers import skill_file_analyst

        result = await skill_file_analyst("")
        assert "❌" in result

    async def test_success(self):
        engine = MagicMock()
        engine.execute = AsyncMock(return_value="analysis result")
        with patch("services.skills_engine.get_skills_engine", return_value=engine):
            from services.tools.mcp_skill_handlers import skill_file_analyst

            result = await skill_file_analyst("report.pdf")
            assert result == "analysis result"

    async def test_failure(self):
        with patch("services.skills_engine.get_skills_engine", side_effect=RuntimeError("no engine")):
            from services.tools.mcp_skill_handlers import skill_file_analyst

            result = await skill_file_analyst("report.pdf")
            assert "❌" in result


class TestSkillWebScraper:
    async def test_no_url(self):
        from services.tools.mcp_skill_handlers import skill_web_scraper

        result = await skill_web_scraper("")
        assert "❌" in result

    async def test_success(self):
        engine = MagicMock()
        engine.execute = AsyncMock(return_value="scraped content")
        with patch("services.skills_engine.get_skills_engine", return_value=engine):
            from services.tools.mcp_skill_handlers import skill_web_scraper

            result = await skill_web_scraper("https://example.com")
            assert result == "scraped content"


class TestSkillIntel:
    async def test_no_target(self):
        from services.tools.mcp_skill_handlers import skill_intel

        result = await skill_intel("")
        assert "❌" in result

    async def test_success(self):
        engine = MagicMock()
        engine.execute = AsyncMock(return_value="intel report")
        with patch("services.skills_engine.get_skills_engine", return_value=engine):
            from services.tools.mcp_skill_handlers import skill_intel

            result = await skill_intel("8.8.8.8")
            assert result == "intel report"


class TestOsintHuntTool:
    async def test_no_topic(self):
        from services.tools.mcp_skill_handlers import osint_hunt_tool

        result = await osint_hunt_tool("")
        assert "❌" in result

    async def test_with_critical_threat(self):
        result_dict = {
            "critical_local_threat": True,
            "local_matches": ["match1"],
            "report": "Threat report text",
            "iocs": {"ips": ["1.2.3.4"], "domains": []},
            "iterations": 3,
        }
        with patch("services.osint_hunter.hunt_and_analyze", new=AsyncMock(return_value=result_dict)):
            from services.tools.mcp_skill_handlers import osint_hunt_tool

            result = await osint_hunt_tool("CVE-2024-1234")
            assert "איום מקומי קריטי" in result
            assert "1.2.3.4" in result
            assert "3" in result

    async def test_no_critical_threat(self):
        result_dict = {
            "critical_local_threat": False,
            "report": "Some report",
            "iocs": {},
            "iterations": 1,
        }
        with patch("services.osint_hunter.hunt_and_analyze", new=AsyncMock(return_value=result_dict)):
            from services.tools.mcp_skill_handlers import osint_hunt_tool

            result = await osint_hunt_tool("test")
            assert "Some report" in result

    async def test_failure(self):
        with patch("services.osint_hunter.hunt_and_analyze", new=AsyncMock(side_effect=RuntimeError("fail"))):
            from services.tools.mcp_skill_handlers import osint_hunt_tool

            result = await osint_hunt_tool("test")
            assert "❌" in result


# ── system_tools ────────────────────────────────────────────────────────────


class TestTerminateProcessHandler:
    async def test_valid_pid(self):
        with patch("services.tools.system_tools.set_pending", new=AsyncMock()) as mock_set:
            from services.tools.system_tools import _terminate_process_handler

            result = await _terminate_process_handler(1234)
            assert "PENDING_APPROVAL" in result
            assert "1234" in result
            mock_set.assert_awaited_once()

    async def test_invalid_pid_string(self):
        from services.tools.system_tools import _terminate_process_handler

        result = await _terminate_process_handler("abc")
        assert "❌" in result
        assert "Invalid PID" in result

    async def test_pid_with_whitespace(self):
        with patch("services.tools.system_tools.set_pending", new=AsyncMock()) as mock_set:
            from services.tools.system_tools import _terminate_process_handler

            result = await _terminate_process_handler("  999  ")
            assert "999" in result
            mock_set.assert_awaited_once()


class TestFormatGpuInfo:
    def test_error_key(self):
        from services.tools.system_tools import _format_gpu_info

        result = _format_gpu_info({"error": "No GPU found"})
        assert "No GPU found" in result

    def test_full_info(self):
        from services.tools.system_tools import _format_gpu_info

        info = {
            "name": "RX 7900",
            "utilization_percent": 50,
            "temperature_c": 70,
            "adapter_ram_gb": 16,
            "engine_clock_mhz": 2000,
            "memory_clock_mhz": 1000,
            "fan_speed_percent": 40,
            "power_draw_w": 200,
            "driver_version": "23.10",
            "status": "OK",
        }
        result = _format_gpu_info(info)
        assert "RX 7900" in result
        assert "50%" in result
        assert "70°C" in result
        assert "16GB" in result
        assert "2000 MHz" in result
        assert "1000 MHz" in result
        assert "40%" in result
        assert "200W" in result
        assert "23.10" in result

    def test_minimal_info(self):
        from services.tools.system_tools import _format_gpu_info

        result = _format_gpu_info({})
        assert "AMD GPU" in result
        assert "Unknown" in result


class TestFormatKnownDevices:
    def test_empty_registry(self):
        with patch("services.tools.system_tools.load_registry", return_value={}):
            from services.tools.system_tools import _format_known_devices

            result = _format_known_devices()
            assert "אין מכשירים" in result

    def test_with_devices(self):
        registry = {
            "192.168.1.10": {"mac": "AA:BB:CC", "name": "Phone", "added": "2024-01-01"},
        }
        with patch("services.tools.system_tools.load_registry", return_value=registry):
            from services.tools.system_tools import _format_known_devices

            result = _format_known_devices()
            assert "192.168.1.10" in result
            assert "Phone" in result


class TestScanLanTool:
    async def test_no_new_devices(self):
        registry = {"192.168.1.1": {"name": "Router", "mac": "AA:BB:CC"}}
        with (
            patch("services.tools.system_tools.auto_discover_lan", new=AsyncMock(return_value=0)),
            patch("services.tools.system_tools.load_registry", return_value=registry),
        ):
            from services.tools.system_tools import _scan_lan_tool

            result = await _scan_lan_tool()
            assert "✅" in result
            assert "0" in result
            assert "Router" in result

    async def test_new_devices_found(self):
        with (
            patch("services.tools.system_tools.auto_discover_lan", new=AsyncMock(return_value=2)),
            patch("services.tools.system_tools.load_registry", return_value={}),
        ):
            from services.tools.system_tools import _scan_lan_tool

            result = await _scan_lan_tool()
            assert "🔔" in result
            assert "2" in result


class TestGetSystemTools:
    def test_returns_list(self):
        from services.tools.system_tools import get_system_tools

        tools = get_system_tools()
        assert isinstance(tools, list)
        assert len(tools) > 10
        names = [t.name for t in tools]
        assert "get_system_snapshot" in names
        assert "terminate_process" in names
        assert "scan_infrastructure" in names
        assert "final_answer" in names

    def test_terminate_process_safety_level(self):
        from services.tools.system_tools import get_system_tools

        tools = {t.name: t for t in get_system_tools()}
        assert tools["terminate_process"].safety_level == "critical"


# ── _infra_handler ──────────────────────────────────────────────────────────


class TestFormatCrtsh:
    def test_exception_result(self):
        from services.tools._infra_handler import _format_crtsh

        result = "\n".join(_format_crtsh(RuntimeError("502")))
        assert "❌" in result
        assert "502" in result

    def test_non_dict_result(self):
        from services.tools._infra_handler import _format_crtsh

        assert _format_crtsh("not a dict") == []

    def test_error_key(self):
        from services.tools._infra_handler import _format_crtsh

        result = "\n".join(_format_crtsh({"error": "rate limited"}))
        assert "⚠️" in result

    def test_with_subdomains(self):
        from services.tools._infra_handler import _format_crtsh

        result = "\n".join(_format_crtsh({"subdomains": ["a.example.com", "b.example.com"]}))
        assert "2 subdomains" in result
        assert "a.example.com" in result

    def test_many_subdomains_truncated(self):
        from services.tools._infra_handler import _format_crtsh

        subs = [f"s{i}.example.com" for i in range(15)]
        result = "\n".join(_format_crtsh({"subdomains": subs}))
        assert "5 more" in result


class TestFormatWayback:
    def test_exception_result(self):
        from services.tools._infra_handler import _format_wayback

        result = "\n".join(_format_wayback(RuntimeError("timeout")))
        assert "❌" in result

    def test_non_dict_result(self):
        from services.tools._infra_handler import _format_wayback

        assert _format_wayback(42) == []

    def test_error_key(self):
        from services.tools._infra_handler import _format_wayback

        result = "\n".join(_format_wayback({"error": "no data"}))
        assert "⚠️" in result

    def test_with_snapshots(self):
        from services.tools._infra_handler import _format_wayback

        snaps = [{"timestamp": "20240101", "url": "http://example.com/page"}]
        result = "\n".join(_format_wayback({"snapshots": snaps}))
        assert "1 archived" in result
        assert "20240101" in result

    def test_many_snapshots_truncated(self):
        from services.tools._infra_handler import _format_wayback

        snaps = [{"timestamp": str(i), "url": f"http://e.com/{i}"} for i in range(8)]
        result = "\n".join(_format_wayback({"snapshots": snaps}))
        assert "3 more" in result


class TestFormatUrlscan:
    def test_exception_result(self):
        from services.tools._infra_handler import _format_urlscan

        result = "\n".join(_format_urlscan(RuntimeError("err")))
        assert "❌" in result

    def test_non_dict_result(self):
        from services.tools._infra_handler import _format_urlscan

        assert _format_urlscan(None) == []

    def test_error_key(self):
        from services.tools._infra_handler import _format_urlscan

        result = "\n".join(_format_urlscan({"error": "blocked"}))
        assert "⚠️" in result

    def test_with_scans(self):
        from services.tools._infra_handler import _format_urlscan

        scans = [{"ip": "1.2.3.4", "domain": "ex.com", "url": "http://ex.com", "malicious": True}]
        result = "\n".join(_format_urlscan({"scans": scans}))
        assert "1 passive" in result
        assert "🚨" in result

    def test_not_malicious_scan(self):
        from services.tools._infra_handler import _format_urlscan

        scans = [{"ip": "1.2.3.4", "domain": "ex.com", "url": "http://ex.com", "malicious": False}]
        result = "\n".join(_format_urlscan({"scans": scans}))
        assert "✅" in result


class TestScanInfrastructureHandler:
    async def test_invalid_domain_no_dot(self):
        from services.tools._infra_handler import scan_infrastructure_handler

        result = await scan_infrastructure_handler("nodot")
        assert "❌" in result

    async def test_invalid_domain_empty(self):
        from services.tools._infra_handler import scan_infrastructure_handler

        result = await scan_infrastructure_handler("")
        assert "❌" in result

    async def test_strips_protocol(self):
        with (
            patch("services.tools._infra_handler.scan_crtsh", new=AsyncMock(return_value={"subdomains": []})),
            patch("services.tools._infra_handler.scan_wayback", new=AsyncMock(return_value={"snapshots": []})),
            patch("services.tools._infra_handler.scan_urlscan", new=AsyncMock(return_value={"scans": []})),
        ):
            from services.tools._infra_handler import scan_infrastructure_handler

            result = await scan_infrastructure_handler("https://example.com/")
            assert "example.com" in result

    async def test_timeout(self):
        import asyncio

        async def slow(*a, **kw):
            await asyncio.sleep(100)

        with (
            patch("services.tools._infra_handler.scan_crtsh", new=slow),
            patch("services.tools._infra_handler.scan_wayback", new=slow),
            patch("services.tools._infra_handler.scan_urlscan", new=slow),
        ):
            from services.tools._infra_handler import scan_infrastructure_handler

            result = await scan_infrastructure_handler("example.com")
            assert "timed out" in result

    async def test_all_sources_return_data(self):
        with (
            patch(
                "services.tools._infra_handler.scan_crtsh",
                new=AsyncMock(return_value={"subdomains": ["a.example.com"]}),
            ),
            patch(
                "services.tools._infra_handler.scan_wayback",
                new=AsyncMock(return_value={"snapshots": [{"timestamp": "20240101", "url": "http://x.com"}]}),
            ),
            patch(
                "services.tools._infra_handler.scan_urlscan",
                new=AsyncMock(return_value={"scans": [{"ip": "1.2.3.4", "domain": "x.com", "url": "http://x.com"}]}),
            ),
        ):
            from services.tools._infra_handler import scan_infrastructure_handler

            result = await scan_infrastructure_handler("example.com")
            assert "crt.sh" in result
            assert "Wayback" in result
            assert "urlscan.io" in result

    async def test_source_exception_isolated(self):
        with (
            patch("services.tools._infra_handler.scan_crtsh", new=AsyncMock(side_effect=RuntimeError("crt down"))),
            patch("services.tools._infra_handler.scan_wayback", new=AsyncMock(return_value={"snapshots": []})),
            patch("services.tools._infra_handler.scan_urlscan", new=AsyncMock(return_value={"scans": []})),
        ):
            from services.tools._infra_handler import scan_infrastructure_handler

            result = await scan_infrastructure_handler("example.com")
            assert "❌" in result
            assert "crt down" in result


# ── news_ai/single.py ───────────────────────────────────────────────────────


class TestSummarizeArticle:
    async def test_empty_text_returns_none(self):
        from services.news_ai.single import summarize_article
        bridge = MagicMock()
        result = await summarize_article("Title", "", bridge)
        assert result is None

    async def test_success(self):
        from services.news_ai.single import summarize_article
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="  Summary text  ")
        result = await summarize_article("Title", "x" * 600, bridge)
        assert result == "Summary text"

    async def test_bridge_returns_empty(self):
        from services.news_ai.single import summarize_article
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="")
        result = await summarize_article("Title", "x" * 600, bridge)
        assert result is None

    async def test_bridge_raises(self):
        from services.news_ai.single import summarize_article
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("LLM down"))
        result = await summarize_article("Title", "x" * 600, bridge)
        assert result is None


class TestBatchSummarize:
    async def test_empty_items(self):
        from services.news_ai.single import batch_summarize

        result = await batch_summarize([], MagicMock())
        assert result == []

    async def test_multiple_items(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=["s1", "s2"])
        from services.news_ai.single import batch_summarize

        items = [{"title": "t1", "full_text": "x" * 600}, {"title": "t2", "summary": "x" * 600}]
        result = await batch_summarize(items, bridge)
        assert result == ["s1", "s2"]


class TestClassifySentiment:
    async def test_positive(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="positive")
        from services.news_ai.single import classify_sentiment

        result = await classify_sentiment("Good news", "text", bridge)
        assert result == "positive"

    async def test_negative_with_period(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Negative.")
        from services.news_ai.single import classify_sentiment

        result = await classify_sentiment("Bad news", "text", bridge)
        assert result == "negative"

    async def test_unknown_sentiment_word(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="mixed")
        from services.news_ai.single import classify_sentiment

        result = await classify_sentiment("Title", "text", bridge)
        assert result == "unknown"

    async def test_bridge_raises(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("err"))
        from services.news_ai.single import classify_sentiment

        result = await classify_sentiment("Title", "text", bridge)
        assert result == "unknown"


class TestBatchSentiment:
    async def test_empty(self):
        from services.news_ai.single import batch_sentiment

        assert await batch_sentiment([], MagicMock()) == []

    async def test_multiple(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=["positive", "neutral"])
        from services.news_ai.single import batch_sentiment

        items = [{"title": "t1", "summary": "s1"}, {"title": "t2", "full_text": "s2"}]
        result = await batch_sentiment(items, bridge)
        assert result == ["positive", "neutral"]


class TestLlmCategorize:
    async def test_empty_categories(self):
        from services.news_ai.single import llm_categorize

        result = await llm_categorize("title", "text", MagicMock(), [])
        assert result is None

    async def test_valid_category(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="cyber")
        from services.news_ai.single import llm_categorize

        result = await llm_categorize("title", "text", bridge, ["cyber", "economy"])
        assert result == "cyber"

    async def test_invalid_category(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="unknown_cat")
        from services.news_ai.single import llm_categorize

        result = await llm_categorize("title", "text", bridge, ["cyber", "economy"])
        assert result is None

    async def test_case_insensitive_match(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Cyber")
        from services.news_ai.single import llm_categorize

        result = await llm_categorize("title", "text", bridge, ["cyber", "economy"])
        assert result == "cyber"


class TestSummarizeCluster:
    async def test_empty_cluster(self):
        from services.news_ai.single import summarize_cluster

        result = await summarize_cluster([], MagicMock())
        assert result is None

    async def test_success(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Headline\n• insight1\n• insight2")
        from services.news_ai.single import summarize_cluster

        articles = [{"title": "T1", "summary": "S1"}]
        result = await summarize_cluster(articles, bridge)
        assert "Headline" in result

    async def test_thinking_content_stripped(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="<thinking>internal</thinking>\nReal headline")
        from services.news_ai.single import summarize_cluster

        result = await summarize_cluster([{"title": "T", "summary": "S"}], bridge)
        assert "Real headline" in result

    async def test_bridge_raises(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("err"))
        from services.news_ai.single import summarize_cluster

        result = await summarize_cluster([{"title": "T", "summary": "S"}], bridge)
        assert result is None

    async def test_empty_result(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="")
        from services.news_ai.single import summarize_cluster

        result = await summarize_cluster([{"title": "T", "summary": "S"}], bridge)
        assert result is None


# ── news_ai/prompts.py ──────────────────────────────────────────────────────


class TestNormalize:
    def test_basic(self):
        from services.news_ai.prompts import _normalize

        assert _normalize("Hello, World!") == "hello world"

    def test_hebrew(self):
        from services.news_ai.prompts import _normalize

        assert _normalize("שלום, עולם!") == "שלום עולם"


class TestIsTitleEcho:
    def test_identical(self):
        from services.news_ai.prompts import _is_title_echo

        assert _is_title_echo("Attack on Israel", "Attack on Israel") is True

    def test_empty(self):
        from services.news_ai.prompts import _is_title_echo

        assert _is_title_echo("", "summary") is False

    def test_high_overlap(self):
        from services.news_ai.prompts import _is_title_echo

        assert _is_title_echo("Attack on Israel today", "Attack on Israel today") is True

    def test_low_overlap(self):
        from services.news_ai.prompts import _is_title_echo

        assert _is_title_echo("Attack on Israel", "Economic growth in Q3") is False

    def test_short_title_subset(self):
        from services.news_ai.prompts import _is_title_echo

        assert _is_title_echo("CVE-2024", "CVE-2024 found in the wild today") is True


class TestBuildBulkPrompt:
    def test_basic(self):
        from services.news_ai.prompts import build_bulk_prompt

        items = [{"title": "T1", "full_text": "text1"}]
        result = build_bulk_prompt(items)
        assert "T1" in result
        assert "text1" in result
        assert "Sentiment" in result

    def test_uses_summary_fallback(self):
        from services.news_ai.prompts import build_bulk_prompt

        items = [{"title": "T1", "summary": "fallback text"}]
        result = build_bulk_prompt(items)
        assert "fallback text" in result


class TestParseBulkResponse:
    def test_empty_text(self):
        from services.news_ai.prompts import parse_bulk_response

        result = parse_bulk_response("", 2)
        assert result == [{"summary": "", "sentiment": "unknown"}, {"summary": "", "sentiment": "unknown"}]

    def test_parsed_items(self):
        from services.news_ai.prompts import parse_bulk_response

        text = "1. Summary: Good news\n   Sentiment: positive\n2. Summary: Bad news\n   Sentiment: negative"
        result = parse_bulk_response(text, 2)
        assert result[0]["summary"] == "Good news"
        assert result[0]["sentiment"] == "positive"
        assert result[1]["sentiment"] == "negative"


class TestBuildBulkSummarizePrompt:
    def test_basic(self):
        from services.news_ai.prompts import build_bulk_summarize_prompt

        items = [{"title": "T1", "full_text": "body text"}]
        result = build_bulk_summarize_prompt(items)
        assert "T1" in result
        assert "body text" in result


class TestParseBulkSummarize:
    def test_empty(self):
        from services.news_ai.prompts import parse_bulk_summarize

        assert parse_bulk_summarize("", 2, []) == ["", ""]

    def test_parsed(self):
        from services.news_ai.prompts import parse_bulk_summarize

        text = "1. First summary\n2. Second summary"
        items = [{"title": "T1"}, {"title": "T2"}]
        result = parse_bulk_summarize(text, 2, items)
        assert result[0] == "First summary"
        assert result[1] == "Second summary"

    def test_title_echo_blank(self):
        from services.news_ai.prompts import parse_bulk_summarize

        text = "1. Same Title"
        items = [{"title": "Same Title"}]
        result = parse_bulk_summarize(text, 1, items)
        assert result[0] == ""

    def test_dash_blank(self):
        from services.news_ai.prompts import parse_bulk_summarize

        text = "1. -"
        items = [{"title": "T1"}]
        result = parse_bulk_summarize(text, 1, items)
        assert result[0] == ""


class TestBuildBulkSentimentPrompt:
    def test_basic(self):
        from services.news_ai.prompts import build_bulk_sentiment_prompt

        items = [{"title": "T1", "summary": "text"}]
        result = build_bulk_sentiment_prompt(items)
        assert "T1" in result
        assert "positive" in result


class TestParseBulkSentiment:
    def test_empty(self):
        from services.news_ai.prompts import parse_bulk_sentiment

        assert parse_bulk_sentiment("", 2) == ["unknown", "unknown"]

    def test_parsed(self):
        from services.news_ai.prompts import parse_bulk_sentiment

        text = "1. positive\n2. negative"
        result = parse_bulk_sentiment(text, 2)
        assert result == ["positive", "negative"]

    def test_fallback_exact_match(self):
        from services.news_ai.prompts import parse_bulk_sentiment

        text = "positive\nnegative\nneutral"
        result = parse_bulk_sentiment(text, 3)
        assert result == ["positive", "negative", "neutral"]

    def test_fallback_mismatch_stays_unknown(self):
        from services.news_ai.prompts import parse_bulk_sentiment

        text = "positive\nnegative"
        result = parse_bulk_sentiment(text, 3)
        assert result == ["unknown", "unknown", "unknown"]


class TestBuildClusterPrompt:
    def test_basic(self):
        from services.news_ai.prompts import build_cluster_prompt

        clusters = [[{"title": "T1", "summary": "S1"}]]
        result = build_cluster_prompt(clusters)
        assert "Cluster 1" in result
        assert "T1" in result

    def test_limits_to_5_articles(self):
        from services.news_ai.prompts import build_cluster_prompt

        articles = [{"title": f"T{i}", "summary": "S"} for i in range(10)]
        result = build_cluster_prompt([articles])
        assert "T0" in result
        assert "T4" in result
        assert "T5" not in result


class TestParseClusterResponse:
    def test_empty_text(self):
        from services.news_ai.prompts import parse_cluster_response

        result = parse_cluster_response("", 2)
        assert result == ["", ""]

    def test_parsed_clusters(self):
        from services.news_ai.prompts import parse_cluster_response

        text = "1. Headline one\n- insight1\n- insight2\n2. Headline two\n- insight3"
        result = parse_cluster_response(text, 2)
        assert "Headline one" in result[0]
        assert "Headline two" in result[1]

    def test_fallback_parse(self):
        from services.news_ai.prompts import parse_cluster_response

        text = "Just some text\n\nAnother block"
        result = parse_cluster_response(text, 2)
        assert len(result) == 2

    def test_pads_to_expected(self):
        from services.news_ai.prompts import parse_cluster_response

        text = "1. Only one\n- insight"
        result = parse_cluster_response(text, 3)
        assert len(result) == 3
        assert result[2] == ""


# ── translation bypass ──────────────────────────────────────────────────────


class TestExtractTargetLang:
    def test_hebrew_name(self):
        from services.agent.bypass.translation import _extract_target_lang

        assert _extract_target_lang("תרגם לעברית") == "he"

    def test_english_name(self):
        from services.agent.bypass.translation import _extract_target_lang

        assert _extract_target_lang("translate to english") == "en"

    def test_code(self):
        from services.agent.bypass.translation import _extract_target_lang

        assert _extract_target_lang("translate to fr") == "fr"

    def test_default_he(self):
        from services.agent.bypass.translation import _extract_target_lang

        assert _extract_target_lang("translate this") == "he"


class TestExtractExplicitText:
    def test_with_colon(self):
        from services.agent.bypass.translation import _extract_explicit_text

        assert _extract_explicit_text("translate: hello world") == "hello world"

    def test_no_colon(self):
        from services.agent.bypass.translation import _extract_explicit_text

        assert _extract_explicit_text("translate hello") is None


class TestDirectTranslationBypass:
    async def test_explicit_text_translates(self):
        translator = MagicMock()
        translator.translate = MagicMock(return_value=("translated text", "google"))
        with (
            patch("services.agent.bypass.translation._get_real_translator", return_value=translator),
            patch("services.agent.bypass.translation.async_store_conversation", new=AsyncMock()),
        ):
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("translate to he: hello world")
            assert result == "translated text"

    async def test_explicit_text_translator_fails(self):
        translator = MagicMock()
        translator.translate = MagicMock(side_effect=RuntimeError("api down"))
        with (
            patch("services.agent.bypass.translation._get_real_translator", return_value=translator),
            patch("services.agent.bypass.translation.async_store_conversation", new=AsyncMock()),
        ):
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("translate: hello")
            assert "❌" in result or "שגיאה" in result

    async def test_summarize_with_document(self):
        with (
            patch("services.agent.bypass.translation.get_last_document", return_value="doc content"),
            patch(
                "services.agent.bypass.translation.llm_summarize_doc",
                new=AsyncMock(return_value="summary result"),
            ),
        ):
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("סכם את המסמך")
            assert result == "summary result"

    async def test_summarize_no_doc_no_memory(self):
        with (
            patch("services.agent.bypass.translation.get_last_document", return_value=""),
            patch("services.agent.bypass.translation.get_memory_service") as mock_svc,
        ):
            svc = MagicMock()
            svc.get_recent = AsyncMock(return_value=[])
            mock_svc.return_value = svc
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("סכם")
            assert result is None

    async def test_summarize_no_doc_with_memory(self):
        entry = MagicMock()
        entry.query = "What is MITRE?"
        entry.response = "A framework for TTPs."
        svc = MagicMock()
        svc.get_recent = AsyncMock(return_value=[entry])
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Summary of conversation")
        with (
            patch("services.agent.bypass.translation.get_last_document", return_value=""),
            patch("services.agent.bypass.translation.get_memory_service", return_value=svc),
            patch("services.llm_bridge.LLMBridge") as mock_bridge_cls,
            patch("services.agent.bypass.translation.async_store_conversation", new=AsyncMock()),
        ):
            mock_bridge_cls.get_instance.return_value = bridge
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("סכם")
            assert result == "Summary of conversation"

    async def test_translate_no_doc_no_explicit(self):
        with patch("services.agent.bypass.translation.get_last_document", return_value=""):
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("תרגם")
            assert result is None

    async def test_translate_last_document(self):
        with (
            patch("services.agent.bypass.translation.get_last_document", return_value="doc text"),
            patch(
                "services.agent.bypass.translation.llm_translate_doc",
                new=AsyncMock(return_value="translated doc"),
            ),
        ):
            from services.agent.bypass.translation import _direct_translation_bypass

            result = await _direct_translation_bypass("תרגם לעברית")
            assert result == "translated doc"


# ── _translation_handlers ───────────────────────────────────────────────────


class TestProcessChunksTranslate:
    async def test_success(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=["trans1", "trans2"])
        from services.agent.bypass._translation_handlers import _process_chunks_translate

        result = await _process_chunks_translate(bridge, ["chunk1", "chunk2"], "עברית")
        assert result == ["trans1", "trans2"]

    async def test_chunk_failure(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("LLM down"))
        from services.agent.bypass._translation_handlers import _process_chunks_translate

        result = await _process_chunks_translate(bridge, ["chunk1"], "עברית")
        assert "שגיאה" in result[0]


class TestProcessChunksSummarize:
    async def test_success(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="summary part")
        from services.agent.bypass._translation_handlers import _process_chunks_summarize

        result = await _process_chunks_summarize(bridge, ["chunk1"])
        assert result == ["summary part"]

    async def test_chunk_failure(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("err"))
        from services.agent.bypass._translation_handlers import _process_chunks_summarize

        result = await _process_chunks_summarize(bridge, ["chunk1"])
        assert "שגיאה" in result[0]


class TestConsolidateSummaries:
    async def test_success(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="consolidated")
        from services.agent.bypass._translation_handlers import _consolidate_summaries

        result = await _consolidate_summaries(bridge, ["part1", "part2"])
        assert result == "consolidated"

    async def test_failure_returns_merged(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=RuntimeError("err"))
        from services.agent.bypass._translation_handlers import _consolidate_summaries

        result = await _consolidate_summaries(bridge, ["part1", "part2"])
        assert "part1" in result
        assert "part2" in result

    async def test_empty_result_returns_merged(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="")
        from services.agent.bypass._translation_handlers import _consolidate_summaries

        result = await _consolidate_summaries(bridge, ["part1"])
        assert result == "part1"


class TestLlmTranslateDoc:
    async def test_empty_doc(self):
        from services.agent.bypass._translation_handlers import llm_translate_doc

        result = await llm_translate_doc("translate", "", "he")
        assert "ריק" in result

    async def test_success(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="translated chunk")
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            from services.agent.bypass._translation_handlers import llm_translate_doc

            result = await llm_translate_doc("translate", "Some text to translate", "he")
            assert "translated chunk" in result

    async def test_truncated_doc(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="translated")
        long_text = "x" * 25000
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            from services.agent.bypass._translation_handlers import llm_translate_doc

            result = await llm_translate_doc("translate", long_text, "he")
            assert "נחתך" in result


class TestLlmSummarizeDoc:
    async def test_empty_doc(self):
        from services.agent.bypass._translation_handlers import llm_summarize_doc

        result = await llm_summarize_doc("summarize", "")
        assert "ריק" in result

    async def test_success_single_chunk(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="summary part")
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            from services.agent.bypass._translation_handlers import llm_summarize_doc

            result = await llm_summarize_doc("summarize", "paragraph\n\n" + "x" * 3000)
            assert "summary part" in result

    async def test_success_multi_chunk_consolidates(self):
        bridge = MagicMock()
        bridge.complete = AsyncMock(side_effect=["part1", "part2", "consolidated"])
        long_text = "paragraph1\n\nparagraph2\n\n" + "x" * 3000
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            from services.agent.bypass._translation_handlers import llm_summarize_doc

            result = await llm_summarize_doc("summarize", long_text)
            assert "consolidated" in result


# ── fs_tools ────────────────────────────────────────────────────────────────


class TestFilesystemToolsReadFile:
    def test_file_not_found(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        req = ReadFileRequest(path=str(tmp_path / "nonexistent.txt"))
        resp = FilesystemTools.read_file(req)
        assert "not found" in resp.content.lower()
        assert resp.lines_read == 0

    def test_read_text_file(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        f = tmp_path / "test.txt"
        f.write_text("line1\nline2\nline3\n", encoding="utf-8")
        req = ReadFileRequest(path=str(f))
        resp = FilesystemTools.read_file(req)
        assert "line1" in resp.content
        assert resp.lines_read == 3
        assert resp.truncated is False

    def test_truncated_file(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        f = tmp_path / "big.txt"
        f.write_text("\n".join(f"line{i}" for i in range(200)), encoding="utf-8")
        req = ReadFileRequest(path=str(f), max_lines=10)
        resp = FilesystemTools.read_file(req)
        assert resp.lines_read == 10
        assert resp.truncated is True
        assert resp.total_lines == 200

    def test_binary_ext_blocked(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        f = tmp_path / "file.pdf"
        f.write_bytes(b"%PDF-1.4 fake")
        req = ReadFileRequest(path=str(f))
        resp = FilesystemTools.read_file(req)
        assert "בינארי" in resp.content
        assert resp.lines_read == 0

    def test_sensitive_ext_blocked(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        f = tmp_path / "secret.env"
        f.write_text("KEY=value", encoding="utf-8")
        req = ReadFileRequest(path=str(f))
        resp = FilesystemTools.read_file(req)
        assert "מוגן" in resp.content

    def test_null_byte_binary_detection(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        f = tmp_path / "data.txt"
        f.write_bytes(b"text\x00\x00binary\x00")
        req = ReadFileRequest(path=str(f))
        resp = FilesystemTools.read_file(req)
        assert "בינארי" in resp.content or "null" in resp.content

    def test_not_a_file(self, tmp_path):
        from services.fs_models import ReadFileRequest
        from services.fs_tools import FilesystemTools

        req = ReadFileRequest(path=str(tmp_path))
        resp = FilesystemTools.read_file(req)
        assert "Not a file" in resp.content


class TestFilesystemToolsListDir:
    def test_list_directory(self, tmp_path):
        from services.fs_models import ListDirRequest
        from services.fs_tools import FilesystemTools

        (tmp_path / "file1.txt").write_text("a")
        (tmp_path / "subdir").mkdir()
        req = ListDirRequest(path=str(tmp_path))
        resp = FilesystemTools.list_directory(req)
        assert resp.total == 2
        names = [e.name for e in resp.entries]
        assert "file1.txt" in names
        assert "subdir" in names

    def test_list_hidden(self, tmp_path):
        from services.fs_models import ListDirRequest
        from services.fs_tools import FilesystemTools

        (tmp_path / ".hidden").write_text("a")
        (tmp_path / "visible.txt").write_text("b")
        req = ListDirRequest(path=str(tmp_path), show_hidden=True)
        resp = FilesystemTools.list_directory(req)
        names = [e.name for e in resp.entries]
        assert ".hidden" in names

    def test_hide_hidden(self, tmp_path):
        from services.fs_models import ListDirRequest
        from services.fs_tools import FilesystemTools

        (tmp_path / ".hidden").write_text("a")
        (tmp_path / "visible.txt").write_text("b")
        req = ListDirRequest(path=str(tmp_path), show_hidden=False)
        resp = FilesystemTools.list_directory(req)
        names = [e.name for e in resp.entries]
        assert ".hidden" not in names

    def test_nonexistent_dir(self, tmp_path):
        from services.fs_models import ListDirRequest
        from services.fs_tools import FilesystemTools

        req = ListDirRequest(path=str(tmp_path / "noexist"))
        resp = FilesystemTools.list_directory(req)
        assert resp.entries == []
        assert resp.total == 0


class TestFilesystemToolsSearchFiles:
    def test_search_recursive(self, tmp_path):
        from services.fs_models import SearchFilesRequest
        from services.fs_tools import FilesystemTools

        (tmp_path / "a.py").write_text("x")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.py").write_text("y")
        (tmp_path / "c.txt").write_text("z")
        req = SearchFilesRequest(pattern="*.py", path=str(tmp_path), recursive=True)
        resp = FilesystemTools.search_files(req)
        assert resp.total == 2
        assert "a.py" in resp.matches
        assert any("b.py" in m for m in resp.matches)

    def test_search_non_recursive(self, tmp_path):
        from services.fs_models import SearchFilesRequest
        from services.fs_tools import FilesystemTools

        (tmp_path / "a.py").write_text("x")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.py").write_text("y")
        req = SearchFilesRequest(pattern="*.py", path=str(tmp_path), recursive=False)
        resp = FilesystemTools.search_files(req)
        assert resp.total == 1
        assert "a.py" in resp.matches

    def test_search_nonexistent_dir(self, tmp_path):
        from services.fs_models import SearchFilesRequest
        from services.fs_tools import FilesystemTools

        req = SearchFilesRequest(pattern="*.py", path=str(tmp_path / "noexist"))
        resp = FilesystemTools.search_files(req)
        assert resp.matches == []
        assert resp.total == 0


class TestHashFileTool:
    def test_hash_existing_file(self, tmp_path):
        from services.fs_tools import hash_file_tool

        f = tmp_path / "test.bin"
        f.write_bytes(b"hello world")
        result = hash_file_tool(str(f))
        assert result.startswith("SHA256:")
        assert len(result) == len("SHA256: ") + 64

    def test_hash_nonexistent(self, tmp_path):
        from services.fs_tools import hash_file_tool

        result = hash_file_tool(str(tmp_path / "noexist.bin"))
        assert "❌" in result or "Error" in result
