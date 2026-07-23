"""DuckDuckGo HTML scrape engine — free, no API key, relatively captcha-resistant.

Uses the html.duckduckgo.com/html/ endpoint. Parses result blocks for
title, URL (via result__url class or udir redirect), and snippet.
"""

from __future__ import annotations

import logging

import httpx
from bs4 import BeautifulSoup

from services.search_engines.base import BaseSearchEngine, SearchResult

logger = logging.getLogger(__name__)

_DDG_URL = "https://html.duckduckgo.com/html/"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
_MAX_RESULTS = 10


class DuckDuckGoEngine(BaseSearchEngine):
    name = "ddg"
    timeout = 10

    async def _do_search(self, query: str, page: int) -> list[SearchResult]:
        params = {"q": query}
        if page > 0:
            params["s"] = str(page * _MAX_RESULTS)  # DDG offset

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            resp = await client.get(_DDG_URL, params=params, headers=_HEADERS)
            resp.raise_for_status()
            text = resp.text

        # Circuit breaker: DDG sometimes returns a redirect/captcha page
        if "captcha" in text.lower() or "anomaly" in text.lower() or len(text) < 500:
            logger.warning("[SearchEngine:ddg] captcha/block detected — skipping")
            return []

        soup = BeautifulSoup(text, "html.parser")
        results: list[SearchResult] = []

        for block in soup.find_all("div", class_="result", limit=_MAX_RESULTS):
            # Title + URL
            title_tag = block.find("a", class_="result__a")
            if not title_tag:
                continue
            title = title_tag.get_text(strip=True)
            # DDG wraps URLs in a redirect — extract the actual URL
            href = str(title_tag.get("href", ""))
            url = self._extract_url(href)
            if not title or not url:
                continue
            # Snippet
            snippet_tag = block.find("a", class_="result__snippet")
            snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
            results.append(SearchResult(title=title, url=url, snippet=snippet, engine="ddg"))

        return results

    @staticmethod
    def _extract_url(href: str) -> str:
        """Extract actual URL from DDG redirect wrapper (uddg= parameter)."""
        if href.startswith("http") and "duckduckgo.com" not in href:
            return href
        # Parse uddg= redirect: //duckduckgo.com/l/?uddg=ENCODED_URL&...
        if "uddg=" in href:
            from urllib.parse import parse_qs, urlparse

            # Fix protocol-relative URLs
            if href.startswith("//"):
                href = "https:" + href
            parsed = urlparse(href)
            params = parse_qs(parsed.query)
            uddg = params.get("uddg", [None])[0]
            if uddg:
                return uddg
        return ""
