"""Tests for search engines — Strategy pattern + DDG/Startpage implementations."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from services.search_engines.base import BaseSearchEngine, SearchResult
from services.search_engines.ddg import DuckDuckGoEngine
from services.search_engines.startpage import StartpageEngine


def _mock_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.text = text
    resp.raise_for_status = MagicMock()
    return resp


def _mock_client(resp: MagicMock) -> MagicMock:
    """Create a mock AsyncClient context manager."""
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


class TestSearchResult:
    def test_to_dict(self):
        r = SearchResult(title="Test", url="https://example.com", snippet="Snip", engine="ddg")
        d = r.to_dict()
        assert d["title"] == "Test"
        assert d["url"] == "https://example.com"
        assert d["snippet"] == "Snip"
        assert d["engine"] == "ddg"

    def test_defaults(self):
        r = SearchResult(title="T", url="https://x.com")
        assert r.snippet == ""
        assert r.engine == ""


class TestDuckDuckGoEngine:
    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        html = (
            "<html><body>" + "x" * 500 + '<div class="result">'
            '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath&rut=xxx">Example Title</a>'
            '<a class="result__snippet">This is a snippet</a>'
            "</div></body></html>"
        )
        resp = _mock_response(html)
        cm = _mock_client(resp)
        with patch("httpx.AsyncClient", return_value=cm):
            engine = DuckDuckGoEngine()
            results = await engine.search("test query")

        assert len(results) == 1
        assert results[0].title == "Example Title"
        assert results[0].url == "https://example.com/path"
        assert results[0].snippet == "This is a snippet"
        assert results[0].engine == "ddg"

    @pytest.mark.asyncio
    async def test_captcha_detection_returns_empty(self):
        resp = _mock_response("<html>captcha challenge please solve</html>")
        cm = _mock_client(resp)
        with patch("httpx.AsyncClient", return_value=cm):
            engine = DuckDuckGoEngine()
            results = await engine.search("test query")
        assert len(results) == 0

    def test_extract_url_direct(self):
        assert DuckDuckGoEngine._extract_url("https://example.com") == "https://example.com"

    def test_extract_url_redirect(self):
        href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fmalware.com%2Fpayload&rut=abc"
        assert DuckDuckGoEngine._extract_url(href) == "https://malware.com/payload"

    @pytest.mark.asyncio
    async def test_error_returns_empty(self):
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(side_effect=RuntimeError("network error"))
        cm.__aexit__ = AsyncMock(return_value=None)
        with patch("httpx.AsyncClient", return_value=cm):
            engine = DuckDuckGoEngine()
            results = await engine.search("test")
        assert len(results) == 0


class TestStartpageEngine:
    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        html = (
            "<html><body>" + "x" * 200 + '<div class="result">'
            '<a href="https://example.com/page">Example Page Title Here</a>'
            "<p>Some snippet text</p>"
            "</div></body></html>"
        )
        resp = _mock_response(html)
        cm = _mock_client(resp)
        with patch("httpx.AsyncClient", return_value=cm):
            engine = StartpageEngine()
            results = await engine.search("test query")

        assert len(results) == 1
        assert results[0].url == "https://example.com/page"
        assert results[0].snippet == "Some snippet text"
        assert results[0].engine == "startpage"

    @pytest.mark.asyncio
    async def test_captcha_returns_empty(self):
        resp = _mock_response("<html>Are you human? captcha</html>")
        cm = _mock_client(resp)
        with patch("httpx.AsyncClient", return_value=cm):
            engine = StartpageEngine()
            results = await engine.search("test")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_page2_skipped(self):
        engine = StartpageEngine()
        results = await engine._do_search("test", page=1)
        assert len(results) == 0


class TestBaseSearchEngine:
    @pytest.mark.asyncio
    async def test_search_aggregates_pages(self):
        class TestEngine(BaseSearchEngine):
            name = "test"
            timeout = 5

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                return [SearchResult(title=f"R{page}", url=f"https://p{page}.com", engine="test")]

        engine = TestEngine()
        results = await engine.search("query", max_pages=3)
        assert len(results) == 3
        assert results[0].title == "R0"
        assert results[2].title == "R2"

    @pytest.mark.asyncio
    async def test_safe_page_swallows_errors(self):
        class FailEngine(BaseSearchEngine):
            name = "fail"
            timeout = 5

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                raise RuntimeError("boom")

        engine = FailEngine()
        results = await engine.search("query")
        assert len(results) == 0


class TestCircuitBreaker:
    @pytest.mark.asyncio
    async def test_circuit_trips_after_threshold(self):
        """3 consecutive failures → circuit trips (open)."""

        class FailEngine(BaseSearchEngine):
            name = "fail"
            timeout = 2

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                raise RuntimeError("blocked")

        engine = FailEngine()
        # 3 failures to trip
        await engine.search("q1")
        await engine.search("q2")
        await engine.search("q3")
        assert engine._consecutive_failures == 3
        assert engine._circuit_open_until > 0
        assert engine._is_circuit_open() is True

    @pytest.mark.asyncio
    async def test_circuit_open_skips_network(self):
        """When circuit is open, search returns [] without calling _do_search."""
        call_count = 0

        class CountEngine(BaseSearchEngine):
            name = "count"
            timeout = 2

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                nonlocal call_count
                call_count += 1
                return []

        engine = CountEngine()
        engine._circuit_open_until = float("inf")  # force open
        results = await engine.search("test")
        assert results == []
        assert call_count == 0  # _do_search never called

    @pytest.mark.asyncio
    async def test_success_resets_failures(self):
        """A successful search resets the failure counter."""

        class FlakyEngine(BaseSearchEngine):
            name = "flaky"
            timeout = 2
            fail_next = True

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                if self.fail_next:
                    raise RuntimeError("flaky")
                return [SearchResult(title="OK", url="https://ok.com", engine="flaky")]

        engine = FlakyEngine()
        await engine.search("q1")  # fail
        assert engine._consecutive_failures == 1
        engine.fail_next = False
        await engine.search("q2")  # success
        assert engine._consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_circuit_cooldown_expires(self):
        """After cooldown expires, circuit resets and allows retry."""
        import time as time_mod

        class OkEngine(BaseSearchEngine):
            name = "ok"
            timeout = 2

            async def _do_search(self, query: str, page: int) -> list[SearchResult]:
                return [SearchResult(title="R", url="https://r.com", engine="ok")]

        engine = OkEngine()
        # Set circuit to expire in the past
        engine._circuit_open_until = time_mod.time() - 1
        assert engine._is_circuit_open() is False  # expired → reset
        assert engine._circuit_open_until == 0.0
