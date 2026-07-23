# services/osint_search.py
"""OSINT Search Engine — Intent-based routing with multi-engine waterfall.

Intent detection:
  - IOC queries (IP, hash, domain) → skip web search, return []
    (caller should route to intel_enricher / leak_scanner instead)
  - General queries (CVE, APT, news) → engine queue → Wikipedia → AI_SEARCH

Tiers:
  0: SearXNG JSON API (if SEARXNG_URL env var set) — self-hosted meta-engine
  1: DuckDuckGo HTML scrape (free, no key, captcha-resistant) — Strategy pattern
  2: Startpage HTML scrape (free, page 1 only, captcha breaker) — Strategy pattern
  3: Wikipedia REST API (free, no key) — structured summaries
  4: AI_SEARCH via OpenRouter (last resort, quota-limited)

Engines 1-2 use the BaseSearchEngine ABC (services/search_engines/).
All files < 300 lines (SRP).
"""

import logging
import os
from typing import Any

import httpx
from bs4 import BeautifulSoup

from services.search_engines import DuckDuckGoEngine, StartpageEngine

logger = logging.getLogger(__name__)

_TIMEOUT = 12
_RESULTS_PER_PAGE = 10

_SEARXNG_URL = os.getenv("SEARXNG_URL", "").rstrip("/")
_WIKI_API = "https://en.wikipedia.org/w/api.php"

# Engine queue — tried in priority order. Each engine handles its own
# error/captcha/timeout recovery via BaseSearchEngine._safe_page().
_ENGINES = [DuckDuckGoEngine(), StartpageEngine()]

# ── IOC detection: moved to services/agent/routing/intent_routers.py ──
# Re-exported here for backward compat (osint_search consumers + tests).
from services.agent.routing.intent_routers import _is_ioc_query  # noqa: E402,F401

# ── Tier 0: SearXNG (JSON API, self-hosted) ──────────────────────


async def _search_searxng(query: str, page: int = 0) -> list[dict[str, str]]:
    """Query a SearXNG instance via JSON API. Requires SEARXNG_URL env var."""
    if not _SEARXNG_URL:
        return []
    params: dict[str, Any] = {"q": query, "format": "json", "pageno": page + 1}
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_SEARXNG_URL, params=params, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[OSINTSearch] SearXNG failed: %s", exc)
        return []
    return [
        {"title": i.get("title", ""), "url": i.get("url", ""), "snippet": i.get("content", ""), "engine": "searxng"}
        for i in data.get("results", [])[:_RESULTS_PER_PAGE]
    ]


# ── Tier 2: Wikipedia REST API (free, no key, structured summaries) ──


async def _search_wikipedia(query: str) -> list[dict[str, str]]:
    """Query Wikipedia REST API for article summary. Free, no key."""
    # Extract likely article title from query
    title = query.strip()
    # For CVE/technical queries, try direct lookup
    params: dict[str, Any] = {
        "action": "query",
        "list": "search",
        "srsearch": title,
        "srlimit": 3,
        "format": "json",
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_WIKI_API, params=params, headers={"Accept": "application/json"})
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[OSINTSearch] Wikipedia search failed: %s", exc)
        return []

    search_results = data.get("query", {}).get("search", [])
    if not search_results:
        return []

    results: list[dict[str, str]] = []
    for item in search_results[:3]:
        page_title = item.get("title", "")
        snippet_html = item.get("snippet", "")
        # Strip HTML tags from snippet
        snippet = BeautifulSoup(snippet_html, "html.parser").get_text(strip=True)
        results.append(
            {
                "title": f"Wikipedia: {page_title}",
                "url": f"https://en.wikipedia.org/wiki/{page_title.replace(' ', '_')}",
                "snippet": snippet[:300],
                "engine": "wikipedia",
            }
        )
    return results


# ── Tier 3: AI_SEARCH (last resort) ──────────────────────────────


async def _search_ai(query: str) -> list[dict[str, str]]:
    """Use AI_SEARCH as last-resort. Returns synthetic result dict."""
    try:
        from services.ai_search import web_search
    except ImportError:
        return []
    try:
        summary = await web_search(query)
    except Exception as exc:
        logger.warning("[OSINTSearch] AI_SEARCH failed: %s", exc)
        return []
    if not summary or "❌" in summary:
        return []
    return [{"title": f"AI Search: {query[:60]}", "url": "", "snippet": summary[:500], "engine": "ai_search"}]


# ── Waterfall Orchestrator ────────────────────────────────────────


def _dedup(results: list[dict[str, str]]) -> list[dict[str, str]]:
    """Deduplicate by URL (case-insensitive)."""
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for r in results:
        url = (r.get("url") or "").lower().rstrip("/")
        if url and url in seen:
            continue
        if url:
            seen.add(url)
        out.append(r)
    return out


async def search_threat_intel(
    query: str,
    max_results: int = 15,
    pages: int = 1,
) -> list[dict[str, str]]:
    """Intent-based search waterfall.

    IOC queries (IP, hash, bare domain) → return [] immediately.
    General queries → SearXNG (if configured) → Startpage page 1 →
    Wikipedia → AI_SEARCH.

    Args:
        query: Search string.
        max_results: Max deduped results (default 15).
        pages: Ignored — always page 1 (anti-bot protection).

    Returns:
        List of dicts: [{title, url, snippet, engine}, ...]
        Empty list on IOC queries or total failure.
    """
    if not query or not query.strip():
        return []

    safe_query = query[:1800]

    # ── Intent routing: IOC queries skip web search entirely ──
    if _is_ioc_query(safe_query):
        logger.info("[OSINTSearch] IOC query detected ('%s') — skipping web search", safe_query[:40])
        return []

    # ── Tier 0: SearXNG (if configured) ──
    if _SEARXNG_URL:
        results = await _search_searxng(safe_query, 0)
        if results:
            logger.info("[OSINTSearch] SearXNG: %d results for '%s...'", len(results), safe_query[:40])
            return _dedup(results)[:max_results]

    # ── Tier 1-2: Engine queue (DDG → Startpage, Strategy pattern) ──
    for engine in _ENGINES:
        engine_results = await engine.search(safe_query, max_pages=1)
        if engine_results:
            dicts = [r.to_dict() for r in engine_results]
            logger.info("[OSINTSearch] %s: %d results for '%s...'", engine.name, len(dicts), safe_query[:40])
            return _dedup(dicts)[:max_results]
        logger.info("[OSINTSearch] %s empty/blocked — trying next engine", engine.name)

    # ── Tier 3: Wikipedia (free, structured) ──
    logger.info("[OSINTSearch] All scrape engines empty — falling back to Wikipedia")
    wiki_results = await _search_wikipedia(safe_query)
    if wiki_results:
        logger.info("[OSINTSearch] Wikipedia: %d results for '%s...'", len(wiki_results), safe_query[:40])
        return _dedup(wiki_results)[:max_results]

    # ── Tier 4: AI_SEARCH (last resort) ──
    logger.info("[OSINTSearch] Wikipedia empty — falling back to AI_SEARCH")
    ai_results = await _search_ai(safe_query)
    if ai_results:
        logger.info("[OSINTSearch] AI_SEARCH: 1 result for '%s...'", safe_query[:40])
    else:
        logger.warning("[OSINTSearch] All engines failed for '%s...'", safe_query[:40])
    return _dedup(ai_results)[:max_results]
