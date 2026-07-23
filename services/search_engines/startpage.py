"""Startpage HTML scrape engine — privacy proxy to Google results.

Page 1 only (page 2+ hits captcha). Includes circuit breaker for
captcha/block detection.
"""

from __future__ import annotations

import logging

import httpx
from bs4 import BeautifulSoup

from services.search_engines.base import BaseSearchEngine, SearchResult

logger = logging.getLogger(__name__)

_STARTPAGE_URL = "https://www.startpage.com/sp/search"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
_MAX_RESULTS = 10


def _is_captcha_page(text: str) -> bool:
    """Circuit breaker: detect captcha/redirect/blocked pages."""
    lower = text.lower()
    return "captcha" in lower or "are you human" in lower or len(text) < 100


def _extract_result_from_block(block) -> SearchResult | None:
    """Parse a single result block into a SearchResult, or None if invalid."""
    links = block.find_all("a", href=True)
    url = ""
    title = ""
    for a in links:
        href = str(a["href"])
        if href.startswith("http") and "startpage.com" not in href and "browse.startpage" not in href:
            url = href
            text_val = a.get_text(strip=True)
            if text_val and len(text_val) > 10:
                title = text_val
                break
    snippet_tag = block.find("p")
    snippet = snippet_tag.get_text(strip=True) if snippet_tag else ""
    if not title or not url:
        return None
    return SearchResult(title=title, url=url, snippet=snippet, engine="startpage")


def _parse_results(soup) -> list[SearchResult]:
    """Pure: parse BeautifulSoup into SearchResult list."""
    results: list[SearchResult] = []
    for block in soup.find_all(class_="result", limit=_MAX_RESULTS):
        result = _extract_result_from_block(block)
        if result is not None:
            results.append(result)
    return results


class StartpageEngine(BaseSearchEngine):
    name = "startpage"
    timeout = 12

    async def _do_search(self, query: str, page: int) -> list[SearchResult]:
        # Startpage captcha on page 2+ — only serve page 0
        if page > 0:
            logger.debug("[SearchEngine:startpage] page %d skipped (captcha risk)", page)
            return []

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            resp = await client.get(_STARTPAGE_URL, params={"query": query}, headers=_HEADERS)
            resp.raise_for_status()
            text = resp.text

        if _is_captcha_page(text):
            logger.warning("[SearchEngine:startpage] captcha/block detected — skipping")
            return []

        soup = BeautifulSoup(text, "html.parser")
        return _parse_results(soup)
