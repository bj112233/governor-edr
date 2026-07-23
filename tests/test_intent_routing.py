# tests/test_intent_routing.py
"""Tests for intent-based search routing in osint_search.py.

Covers: IOC detection, SearXNG API, Startpage scraper, Wikipedia API,
waterfall logic, intent routing.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Test helpers ──


def _mock_httpx_response(json_data=None, text_data=None):
    """Build a mock httpx response + client for async patching."""
    mock_resp = MagicMock()
    if json_data is not None:
        mock_resp.json.return_value = json_data
    if text_data is not None:
        mock_resp.text = text_data
    mock_resp.raise_for_status = lambda: None
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


# ── IOC detection tests ──


class TestIOCDetection:
    def test_pure_ipv4_detected(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("1.2.3.4") is True

    def test_pure_ipv6_detected(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("2001:db8::1") is True

    def test_hash_md5_detected(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_hash_sha256_detected(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True

    def test_bare_domain_detected(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("evil.com") is True

    def test_cve_not_ioc(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("CVE-2024-3094") is False

    def test_apt_group_not_ioc(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("Lazarus group attacks") is False

    def test_sentence_not_ioc(self):
        from services.osint_search import _is_ioc_query

        assert _is_ioc_query("what is xz utils backdoor") is False


# ── SearXNG API tests ──


class TestSearXNG:
    @pytest.mark.asyncio
    async def test_searxng_parses_json(self):
        from services.osint_search import _search_searxng

        mock_json = {"results": [{"title": "Test", "url": "http://example.com", "content": "snippet"}]}
        with (
            patch("services.osint_search._SEARXNG_URL", "http://localhost:8080/search"),
            patch("services.osint_search.httpx.AsyncClient") as mock_cls,
        ):
            mock_cls.return_value = _mock_httpx_response(json_data=mock_json)
            results = await _search_searxng("test", page=0)
        assert len(results) == 1
        assert results[0]["engine"] == "searxng"

    @pytest.mark.asyncio
    async def test_searxng_empty_url_returns_empty(self):
        from services.osint_search import _search_searxng

        with patch("services.osint_search._SEARXNG_URL", ""):
            assert await _search_searxng("test", page=0) == []


# ── Startpage scraper tests (now via StartpageEngine) ──


class TestStartpageScraper:
    @pytest.mark.asyncio
    async def test_startpage_parses_result_blocks(self):
        from services.search_engines.startpage import StartpageEngine

        mock_html = (
            "<html><body>" + "x" * 200 + '<div class="result">'
            '<a href="https://example.com">Example Title That Is Long Enough</a>'
            "<p>Example snippet text about the topic</p>"
            "</div></body></html>"
        )
        with patch("services.search_engines.startpage.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _mock_httpx_response(text_data=mock_html)
            engine = StartpageEngine()
            results = await engine.search("test")
        assert len(results) == 1
        assert results[0].engine == "startpage"

    @pytest.mark.asyncio
    async def test_startpage_captcha_detected(self):
        """Captcha page -> empty results (circuit breaker)."""
        from services.search_engines.startpage import StartpageEngine

        mock_html = "<html><body>Are you human? captcha required</body></html>"
        with patch("services.search_engines.startpage.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _mock_httpx_response(text_data=mock_html)
            engine = StartpageEngine()
            results = await engine.search("test")
        assert results == []


# ── Wikipedia API tests ──


class TestWikipedia:
    @pytest.mark.asyncio
    async def test_wikipedia_parses_search(self):
        from services.osint_search import _search_wikipedia

        mock_json = {
            "query": {
                "search": [
                    {"title": "Lazarus Group", "snippet": "North Korean <span>hacker</span> group"},
                ]
            }
        }
        with patch("services.osint_search.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _mock_httpx_response(json_data=mock_json)
            results = await _search_wikipedia("Lazarus group")
        assert len(results) == 1
        assert results[0]["engine"] == "wikipedia"
        assert "Lazarus Group" in results[0]["title"]
        assert "hacker" in results[0]["snippet"]  # HTML stripped

    @pytest.mark.asyncio
    async def test_wikipedia_empty_response(self):
        from services.osint_search import _search_wikipedia

        mock_json = {"query": {"search": []}}
        with patch("services.osint_search.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value = _mock_httpx_response(json_data=mock_json)
            assert await _search_wikipedia("nonexistent topic xyz") == []


# ── Waterfall + intent routing tests ──


class TestWaterfall:
    @pytest.mark.asyncio
    async def test_ioc_query_returns_empty(self):
        """IOC queries (IP, hash, domain) skip all web search."""
        from services.osint_search import search_threat_intel

        with patch("services.osint_search._ENGINES", []):
            results = await search_threat_intel("1.2.3.4")
        assert results == []

    @pytest.mark.asyncio
    async def test_general_query_uses_engines(self):
        """General queries -> engine queue (DDG first)."""
        from services.osint_search import search_threat_intel
        from services.search_engines.base import SearchResult

        mock_engine = MagicMock()
        mock_engine.search = AsyncMock(
            return_value=[SearchResult(title="CVE Info", url="http://cve.com", snippet="found", engine="ddg")]
        )
        mock_engine.name = "ddg"
        with (
            patch("services.osint_search._SEARXNG_URL", ""),
            patch("services.osint_search._ENGINES", [mock_engine]),
            patch("services.osint_search._search_wikipedia", new_callable=AsyncMock) as mock_wiki,
            patch("services.osint_search._search_ai", new_callable=AsyncMock) as mock_ai,
        ):
            mock_wiki.return_value = []
            mock_ai.return_value = []
            results = await search_threat_intel("CVE-2024-3094")
        assert len(results) == 1
        assert results[0]["engine"] == "ddg"
        mock_wiki.assert_not_called()

    @pytest.mark.asyncio
    async def test_engines_empty_falls_to_wikipedia(self):
        """All engines empty -> Wikipedia."""
        from services.osint_search import search_threat_intel

        mock_engine = MagicMock()
        mock_engine.search = AsyncMock(return_value=[])
        mock_engine.name = "ddg"
        wiki_result = [{"title": "Wiki: APT", "url": "http://wiki.com", "snippet": "info", "engine": "wikipedia"}]
        with (
            patch("services.osint_search._SEARXNG_URL", ""),
            patch("services.osint_search._ENGINES", [mock_engine]),
            patch("services.osint_search._search_wikipedia", new_callable=AsyncMock) as mock_wiki,
            patch("services.osint_search._search_ai", new_callable=AsyncMock) as mock_ai,
        ):
            mock_wiki.return_value = wiki_result
            mock_ai.return_value = []
            results = await search_threat_intel("Lazarus group")
        assert len(results) == 1
        assert results[0]["engine"] == "wikipedia"
        mock_ai.assert_not_called()

    @pytest.mark.asyncio
    async def test_wikipedia_empty_falls_to_ai(self):
        """Engines + Wikipedia empty -> AI_SEARCH."""
        from services.osint_search import search_threat_intel

        mock_engine = MagicMock()
        mock_engine.search = AsyncMock(return_value=[])
        mock_engine.name = "ddg"
        ai_result = [{"title": "AI", "url": "", "snippet": "summary", "engine": "ai_search"}]
        with (
            patch("services.osint_search._SEARXNG_URL", ""),
            patch("services.osint_search._ENGINES", [mock_engine]),
            patch("services.osint_search._search_wikipedia", new_callable=AsyncMock) as mock_wiki,
            patch("services.osint_search._search_ai", new_callable=AsyncMock) as mock_ai,
        ):
            mock_wiki.return_value = []
            mock_ai.return_value = ai_result
            results = await search_threat_intel("obscure topic")
        assert len(results) == 1
        assert results[0]["engine"] == "ai_search"

    @pytest.mark.asyncio
    async def test_all_fail_returns_empty(self):
        from services.osint_search import search_threat_intel

        mock_engine = MagicMock()
        mock_engine.search = AsyncMock(return_value=[])
        mock_engine.name = "ddg"
        with (
            patch("services.osint_search._SEARXNG_URL", ""),
            patch("services.osint_search._ENGINES", [mock_engine]),
            patch("services.osint_search._search_wikipedia", new_callable=AsyncMock) as mock_wiki,
            patch("services.osint_search._search_ai", new_callable=AsyncMock) as mock_ai,
        ):
            mock_wiki.return_value = []
            mock_ai.return_value = []
            assert await search_threat_intel("test") == []

    @pytest.mark.asyncio
    async def test_searxng_takes_priority(self):
        from services.osint_search import search_threat_intel

        mock_engine = MagicMock()
        mock_engine.search = AsyncMock(return_value=[])
        mock_engine.name = "ddg"
        sx_result = [{"title": "SX", "url": "http://sx.com", "snippet": "found", "engine": "searxng"}]
        with (
            patch("services.osint_search._SEARXNG_URL", "http://localhost:8080/search"),
            patch("services.osint_search._search_searxng", new_callable=AsyncMock) as mock_sx,
            patch("services.osint_search._ENGINES", [mock_engine]),
        ):
            mock_sx.return_value = sx_result
            results = await search_threat_intel("CVE-2024")
        assert results[0]["engine"] == "searxng"

    @pytest.mark.asyncio
    async def test_empty_query_returns_empty(self):
        from services.osint_search import search_threat_intel

        assert await search_threat_intel("") == []
        assert await search_threat_intel("   ") == []


# ── Bypass handler integration tests (new intent routers) ──


class TestBypassHandlers:
    """Verify the new bypass handlers are wired into _BYPASS_HANDLERS."""

    def test_cve_bypass_registered(self):
        from services.agent._bypasses import _BYPASS_HANDLERS
        from services.agent.bypass.cve import _try_cve_bypass

        assert _try_cve_bypass in _BYPASS_HANDLERS

    def test_file_path_bypass_registered(self):
        from services.agent._bypasses import _BYPASS_HANDLERS
        from services.agent.bypass.file_path import _try_file_path_bypass

        assert _try_file_path_bypass in _BYPASS_HANDLERS

    def test_process_bypass_registered(self):
        from services.agent._bypasses import _BYPASS_HANDLERS
        from services.agent.bypass.process import _try_process_bypass

        assert _try_process_bypass in _BYPASS_HANDLERS

    def test_yara_bypass_registered(self):
        from services.agent._bypasses import _BYPASS_HANDLERS
        from services.agent.bypass.yara import _try_yara_bypass

        assert _try_yara_bypass in _BYPASS_HANDLERS

    def test_cve_bypass_before_intel(self):
        """CVE bypass must run before intel to prevent CVE misrouting."""
        from services.agent._bypasses import _BYPASS_HANDLERS, _try_intel_bypass
        from services.agent.bypass.cve import _try_cve_bypass

        cve_idx = _BYPASS_HANDLERS.index(_try_cve_bypass)
        intel_idx = _BYPASS_HANDLERS.index(_try_intel_bypass)
        assert cve_idx < intel_idx

    @pytest.mark.asyncio
    async def test_cve_bypass_calls_osint_hunt(self):
        """CVE bypass should call osint_hunt_tool with the CVE ID."""
        from services.agent.bypass.cve import _try_cve_bypass

        with patch("services.tools.mcp_skill_handlers.osint_hunt_tool", new_callable=AsyncMock) as mock_hunt:
            mock_hunt.return_value = "🛡️ CVE report"
            result = await _try_cve_bypass("CVE-2024-3094")
        assert result == "🛡️ CVE report"
        mock_hunt.assert_awaited_once_with(topic="CVE-2024-3094")

    @pytest.mark.asyncio
    async def test_cve_bypass_no_match(self):
        from services.agent.bypass.cve import _try_cve_bypass

        assert await _try_cve_bypass("show processes") is None

    @pytest.mark.asyncio
    async def test_file_path_bypass_calls_skill(self):
        """File-path bypass should call skills_engine.execute."""
        from services.agent.bypass.file_path import _try_file_path_bypass

        mock_engine = MagicMock()
        mock_engine.execute = AsyncMock(return_value="📄 Summary")
        with patch("services.agent.bypass.file_path.get_skills_engine", return_value=mock_engine):
            result = await _try_file_path_bypass("summarize C:\\test\\report.pdf")
        assert result == "📄 Summary"
        mock_engine.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_process_list_bypass_calls_tool(self):
        """Process-list bypass should call get_process_list from LLM_TOOL_MAP."""
        from services.agent.bypass.process import _try_process_bypass

        mock_handler = AsyncMock(return_value="PID 123 chrome")
        with patch.dict("services.tools_registry.LLM_TOOL_MAP", {"get_process_list": mock_handler}):
            result = await _try_process_bypass("show running processes")
        assert "123" in result
        mock_handler.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_yara_bypass_calls_tool(self):
        """YARA bypass should call scan_file_yara from LLM_TOOL_MAP."""
        from services.agent.bypass.yara import _try_yara_bypass

        mock_handler = AsyncMock(return_value="✅ No YARA matches")
        with patch.dict("services.tools_registry.LLM_TOOL_MAP", {"scan_file_yara": mock_handler}):
            result = await _try_yara_bypass("yara scan C:\\test\\file.bin")
        assert "No YARA matches" in result
        mock_handler.assert_awaited_once_with(filepath="C:\\test\\file.bin")
