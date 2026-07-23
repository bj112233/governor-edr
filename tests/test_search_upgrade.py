# tests/test_search_upgrade.py
"""Tests for leak scanning + ReAct dispatch.

Covers: dedup, crt.sh parser, Wayback parser, urlscan.io parser,
ReAct intel/search/leaks/certs dispatch, scan_leaks orchestrator,
format_leak_results.
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


class TestDedup:
    def test_dedup_by_url(self):
        """Duplicate URLs should be removed."""
        from services.osint_search import _dedup

        results = [
            {"title": "A", "url": "http://evil.com", "snippet": "a", "engine": "ddg"},
            {"title": "B", "url": "http://evil.com/", "snippet": "b", "engine": "bing"},
            {"title": "C", "url": "http://other.com", "snippet": "c", "engine": "ddg"},
        ]
        deduped = _dedup(results)
        assert len(deduped) == 2
        assert deduped[0]["title"] == "A"
        assert deduped[1]["title"] == "C"

    def test_dedup_case_insensitive(self):
        """URLs differing only in case should be deduped."""
        from services.osint_search import _dedup

        results = [
            {"title": "A", "url": "http://Evil.com", "snippet": "", "engine": "ddg"},
            {"title": "B", "url": "http://evil.com", "snippet": "", "engine": "bing"},
        ]
        deduped = _dedup(results)
        assert len(deduped) == 1

    def test_dedup_empty_url_kept(self):
        """Results with empty URL (AI_SEARCH) should NOT be deduped."""
        from services.osint_search import _dedup

        results = [
            {"title": "AI1", "url": "", "snippet": "summary1", "engine": "ai_search"},
            {"title": "AI2", "url": "", "snippet": "summary2", "engine": "ai_search"},
        ]
        deduped = _dedup(results)
        assert len(deduped) == 2


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ crt.sh parser tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestCrtSh:
    @pytest.mark.asyncio
    async def test_crtsh_parses_subdomains(self):
        """crt.sh JSON should be parsed into subdomains + certs."""
        from services.leak_scanner import scan_crtsh

        mock_json = [
            {
                "id": 123,
                "name_value": "evil.com\nwww.evil.com\nmail.evil.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2026-01-01",
                "not_after": "2026-04-01",
            },
            {
                "id": 124,
                "name_value": "api.evil.com",
                "issuer_name": "DigiCert",
                "not_before": "2026-02-01",
                "not_after": "2027-02-01",
            },
        ]
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await scan_crtsh("evil.com")

        assert result["error"] is None
        assert "evil.com" in result["subdomains"]
        assert "www.evil.com" in result["subdomains"]
        assert "mail.evil.com" in result["subdomains"]
        assert "api.evil.com" in result["subdomains"]
        assert len(result["certs"]) == 2
        assert result["certs"][0]["issuer"] == "Let's Encrypt"

    @pytest.mark.asyncio
    async def test_crtsh_invalid_domain(self):
        """Invalid domain should return error without API call."""
        from services.leak_scanner import scan_crtsh

        result = await scan_crtsh("notadomain")
        assert result["error"] == "invalid domain"
        assert result["subdomains"] == []

    @pytest.mark.asyncio
    async def test_crtsh_wildcard_filtered(self):
        """Wildcard certificates (*.evil.com) should be filtered from subdomains."""
        from services.leak_scanner import scan_crtsh

        mock_json = [
            {"id": 1, "name_value": "*.evil.com", "issuer_name": "CA", "not_before": "", "not_after": ""},
            {"id": 2, "name_value": "www.evil.com", "issuer_name": "CA", "not_before": "", "not_after": ""},
        ]
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await scan_crtsh("evil.com")

        assert "*.evil.com" not in result["subdomains"]
        assert "www.evil.com" in result["subdomains"]


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ Wayback parser tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestWayback:
    @pytest.mark.asyncio
    async def test_wayback_parses_snapshots(self):
        """Wayback CDX JSON should be parsed into snapshot dicts."""
        from services.leak_scanner import scan_wayback

        mock_json = [
            ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
            ["com,evil)/", "20260101000000", "https://evil.com/", "text/html", "200", "abc", "1234"],
            ["com,evil)/admin", "20260102000000", "https://evil.com/admin", "text/html", "403", "def", "567"],
        ]
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await scan_wayback("evil.com")

        assert result["error"] is None
        assert len(result["snapshots"]) == 2
        assert result["snapshots"][0]["url"] == "https://evil.com/"
        assert result["snapshots"][0]["status"] == "200"
        assert result["snapshots"][1]["status"] == "403"

    @pytest.mark.asyncio
    async def test_wayback_empty_response(self):
        """Empty CDX response (only header) should return 0 snapshots."""
        from services.leak_scanner import scan_wayback

        mock_json = [["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"]]
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await scan_wayback("nonexistent.com")

        assert result["error"] is None
        assert result["snapshots"] == []


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ urlscan.io parser tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestUrlScan:
    @pytest.mark.asyncio
    async def test_urlscan_parses_scans(self):
        """urlscan.io API response should be parsed into scan dicts."""
        from services.leak_scanner import scan_urlscan

        mock_json = {
            "total": 2,
            "results": [
                {
                    "task": {
                        "url": "https://evil.com/",
                        "domain": "evil.com",
                        "ip": "1.2.3.4",
                        "time": "2026-06-01T00:00:00",
                    },
                    "page": {"screenshot": "https://urlscan.io/screeshots/123.png", "title": "Phishing Page"},
                    "scores": {"phishing": 0.95},
                    "verdicts": {"overall": {"malicious": True}},
                },
                {
                    "task": {
                        "url": "https://evil.com/login",
                        "domain": "evil.com",
                        "ip": "1.2.3.4",
                        "time": "2026-06-02T00:00:00",
                    },
                    "page": {"screenshot": "", "title": "Login"},
                    "scores": {"phishing": 0.1},
                    "verdicts": {"overall": {"malicious": False}},
                },
            ],
        }
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            result = await scan_urlscan("evil.com")

        assert result["error"] is None
        assert result["total"] == 2
        assert len(result["scans"]) == 2
        assert result["scans"][0]["malicious"] is True
        assert result["scans"][0]["score"] == 0.95
        assert result["scans"][1]["malicious"] is False

    @pytest.mark.asyncio
    async def test_urlscan_ip_query(self):
        """IP target should use ip: field in query."""
        from services.leak_scanner import scan_urlscan

        mock_json = {"total": 0, "results": []}
        with patch("services.leak_scanner.httpx.AsyncClient") as mock_client_cls:
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_json
            mock_resp.raise_for_status = lambda: None
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client

            await scan_urlscan("1.2.3.4")

        call_args = mock_client.get.call_args
        url = call_args.args[0] if call_args.args else call_args.kwargs.get("url", "")
        assert "ip:1.2.3.4" in url, f"IP query should use ip: field, got {url}"


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ ReAct leaks/certs dispatch tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestReactDispatch:
    @pytest.mark.asyncio
    async def test_leaks_action_dispatches_scan_leaks(self):
        """ReAct 'leaks' action should call scan_leaks + format_leak_results."""
        from services.osint_react_loop import _run_tool

        mock_result = {
            "query": "evil.com",
            "target": "evil.com",
            "sources": {"crt_sh": {"subdomains": ["www.evil.com"], "certs": [], "error": None}},
        }
        with (
            patch("services.leak_scanner.scan_leaks", new_callable=AsyncMock) as mock_scan,
            patch(
                "services.leak_scanner.format_leak_results",
                return_value="Leak scan for: evil.com\n[crt.sh] 1 subdomains",
            ),
        ):
            mock_scan.return_value = mock_result

            obs = await _run_tool("leaks", "evil.com")

        assert "Leak scan" in obs
        assert "evil.com" in obs
        mock_scan.assert_called_once_with("evil.com")

    @pytest.mark.asyncio
    async def test_certs_action_dispatches_scan_crtsh(self):
        """ReAct 'certs' action should call scan_crtsh."""
        from services.osint_react_loop import _run_tool

        mock_result = {
            "source": "crt.sh",
            "domain": "evil.com",
            "subdomains": ["www.evil.com", "api.evil.com", "mail.evil.com"],
            "certs": [],
            "error": None,
        }
        with patch("services.leak_scanner.scan_crtsh", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = mock_result

            obs = await _run_tool("certs", "evil.com")

        assert "3 subdomains" in obs
        assert "www.evil.com" in obs
        mock_scan.assert_called_once_with("evil.com")

    @pytest.mark.asyncio
    async def test_certs_empty_returns_no_results(self):
        """certs action with 0 subdomains should return 'No certificates' message."""
        from services.osint_react_loop import _run_tool

        mock_result = {"subdomains": [], "certs": [], "error": None}
        with patch("services.leak_scanner.scan_crtsh", new_callable=AsyncMock) as mock_scan:
            mock_scan.return_value = mock_result

            obs = await _run_tool("certs", "nonexistent.com")

        assert "No certificates" in obs

    @pytest.mark.asyncio
    async def test_unknown_action_returns_help(self):
        """Unknown action should list available tools."""
        from services.osint_react_loop import _run_tool

        obs = await _run_tool("hack", "target")
        assert "intel" in obs
        assert "search" in obs
        assert "leaks" in obs
        assert "certs" in obs

    @pytest.mark.asyncio
    async def test_intel_action_ip_routes_to_enrich_ip(self):
        """ReAct 'intel' action with IP should call enrich_ip."""
        from services.osint_react_loop import _run_tool

        mock_data = {"ip": "1.2.3.4", "abuse_score": 85, "country": "RU"}
        with patch("services.intel_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            obs = await _run_tool("intel", "1.2.3.4")
        assert "1.2.3.4" in obs
        assert "85" in obs
        mock_enrich.assert_called_once_with("1.2.3.4")

    @pytest.mark.asyncio
    async def test_intel_action_domain_routes_to_leaks(self):
        """ReAct 'intel' action with domain should fall back to scan_leaks."""
        from services.osint_react_loop import _run_tool

        mock_result = {
            "query": "evil.com",
            "target": "evil.com",
            "sources": {"crt_sh": {"subdomains": ["www.evil.com"], "certs": [], "error": None}},
        }
        with (
            patch("services.intel_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich,
            patch("services.leak_scanner.scan_leaks", new_callable=AsyncMock) as mock_scan,
            patch("services.leak_scanner.format_leak_results", return_value="Leak scan: evil.com"),
        ):
            mock_enrich.return_value = None
            mock_scan.return_value = mock_result
            obs = await _run_tool("intel", "evil.com")
        assert "Leak scan" in obs
        mock_scan.assert_called_once_with("evil.com")

    @pytest.mark.asyncio
    async def test_search_returns_engine_tag(self):
        """Search results should include engine tag in observation."""
        from services.osint_react_loop import _run_tool

        mock_results = [
            {"title": "Test", "url": "http://test.com", "snippet": "found", "engine": "ddg"},
        ]
        with patch("services.osint_react_loop.search_threat_intel", new_callable=AsyncMock) as mock_search:
            mock_search.return_value = mock_results

            obs = await _run_tool("search", "test query")

        assert "[ddg]" in obs
        assert "Test" in obs


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ scan_leaks orchestrator tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestScanLeaksOrchestrator:
    @pytest.mark.asyncio
    async def test_domain_triggers_all_sources(self):
        """Domain input should trigger crt.sh + wayback + urlscan."""
        from services.leak_scanner import scan_leaks

        with (
            patch("services.leak_scanner.scan_crtsh", new_callable=AsyncMock) as mock_crt,
            patch("services.leak_scanner.scan_wayback", new_callable=AsyncMock) as mock_wb,
            patch("services.leak_scanner.scan_urlscan", new_callable=AsyncMock) as mock_us,
        ):
            mock_crt.return_value = {"subdomains": [], "certs": [], "error": None}
            mock_wb.return_value = {"snapshots": [], "error": None}
            mock_us.return_value = {"scans": [], "error": None}

            result = await scan_leaks("evil.com")

        assert "crt_sh" in result["sources"]
        assert "wayback" in result["sources"]
        assert "urlscan" in result["sources"]
        mock_crt.assert_called_once()
        mock_wb.assert_called_once()
        mock_us.assert_called_once()

    @pytest.mark.asyncio
    async def test_ip_triggers_urlscan_only(self):
        """IP input should trigger only urlscan."""
        from services.leak_scanner import scan_leaks

        with (
            patch("services.leak_scanner.scan_crtsh", new_callable=AsyncMock) as mock_crt,
            patch("services.leak_scanner.scan_wayback", new_callable=AsyncMock) as mock_wb,
            patch("services.leak_scanner.scan_urlscan", new_callable=AsyncMock) as mock_us,
        ):
            mock_us.return_value = {"scans": [], "error": None}

            result = await scan_leaks("1.2.3.4")

        assert "urlscan" in result["sources"]
        assert "crt_sh" not in result["sources"]
        assert "wayback" not in result["sources"]
        mock_crt.assert_not_called()
        mock_wb.assert_not_called()


# ╫עΓא¥Γג¼╫עΓא¥Γג¼ format_leak_results tests ╫עΓא¥Γג¼╫עΓא¥Γג¼


class TestFormatLeakResults:
    def test_format_crtsh(self):
        """crt.sh results should be formatted with subdomain list."""
        from services.leak_scanner import format_leak_results

        results = {
            "query": "evil.com",
            "target": "evil.com",
            "sources": {
                "crt_sh": {
                    "subdomains": ["www.evil.com", "api.evil.com"],
                    "certs": [{"id": "1", "issuer": "CA"}],
                    "error": None,
                },
            },
        }
        text = format_leak_results(results)
        assert "crt.sh" in text
        assert "2 subdomains" in text
        assert "www.evil.com" in text

    def test_format_error(self):
        """Error in source should be formatted."""
        from services.leak_scanner import format_leak_results

        results = {
            "query": "evil.com",
            "target": "evil.com",
            "sources": {
                "crt_sh": {"subdomains": [], "certs": [], "error": "timeout"},
            },
        }
        text = format_leak_results(results)
        assert "Error" in text
        assert "timeout" in text

    def test_format_empty(self):
        """Empty results should return 'No leak data found.'"""
        from services.leak_scanner import format_leak_results

        text = format_leak_results({"query": "test", "target": "test", "sources": {}})
        assert "No leak data" in text
