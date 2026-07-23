# services/credential_monitor.py
"""Credential Leak Monitor — Pastebin/GitHub via Search OS + free APIs.

Zero-cost, no API keys. Uses existing DDG/Startpage engines with `site:`
operator to search paste sites via Google index (bypasses anti-bot).

Flow:
  1. search_paste_sites() — DDG: site:pastebin.com + site:gist.github.com
     a. Semaphore(1) + Jitter(1.5-3.5s) — anti-bot evasion
     b. Extract credentials from snippet FIRST (snippet-first strategy)
     c. Fetch raw paste content as fallback (pastebin.com/raw/XYZ, gist /raw)
     d. Graceful degradation: if raw fetch blocked (403/Cloudflare), use snippet
  2. search_github_code() — GitHub Code Search API (rate-limited, dual-layer)
  3. scan_credential_leaks() — orchestrator (asyncio.gather, ~3s ceiling)

All files < 300 lines (SRP).
"""

import asyncio
import logging
import random
from typing import Any

import httpx

from config import GITHUB_TOKEN
from services.credential_format import format_credential_results  # noqa: F401 (re-export)
from services.credential_patterns import extract_credentials
from services.github_rate_limiter import github_limiter
from services.search_engines import DuckDuckGoEngine, StartpageEngine

logger = logging.getLogger(__name__)

_TIMEOUT = 12
_RAW_FETCH_TIMEOUT = 8
_MAX_PASTE_FETCH = 5
_PASTE_SEMAPHORE = 1  # serial requests to avoid IP ban (anti-bot evasion)
_JITTER_MIN = 1.5  # seconds — simulates human behavior
_JITTER_MAX = 3.5

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/plain,*/*;q=0.8",
}

_PASTE_SITES = ["pastebin.com", "gist.github.com", "ghostbin.com", "paste.ee"]
_GITHUB_CODE_API = "https://api.github.com/search/code"

_ddg_engine = DuckDuckGoEngine()
_sp_engine = StartpageEngine()


# ── Paste Site Search (Semaphore + Jitter anti-bot) ──────────────


def _to_raw_url(url: str) -> str:
    """Convert paste URL to raw content URL for direct fetch."""
    if "pastebin.com" in url and "/raw/" not in url:
        paste_id = url.rstrip("/").split("/")[-1]
        return f"https://pastebin.com/raw/{paste_id}"
    if "gist.github.com" in url:
        return url.replace("gist.github.com", "gist.githubusercontent.com").rstrip("/") + "/raw"
    return url


async def _fetch_raw_content(url: str) -> str:
    """Fetch raw paste content. Returns "" on any failure (graceful degradation)."""
    raw_url = _to_raw_url(url)
    try:
        async with httpx.AsyncClient(timeout=_RAW_FETCH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(raw_url, headers=_HEADERS)
            if resp.status_code == 403:
                logger.debug("[CredMonitor] raw fetch 403 for %s — using snippet", url[:60])
                return ""
            resp.raise_for_status()
            return resp.text[:5000]
    except Exception as exc:
        logger.debug("[CredMonitor] raw fetch failed for %s: %s", url[:60], exc)
        return ""


async def _search_single_site(query: str, site: str) -> list[Any]:
    """Search one paste site via DDG → Startpage waterfall."""
    site_q = f'site:{site} "{query}"'
    ddg_results = await _ddg_engine.search(site_q, max_pages=1)
    if ddg_results:
        return ddg_results
    return await _sp_engine.search(site_q, max_pages=1)


async def search_paste_sites(query: str, max_results: int = 10) -> list[dict[str, Any]]:
    """Search paste sites via DDG `site:` operator with anti-bot protection.

    Semaphore(1) + Jitter(1.5-3.5s) — serial requests with random delay
    to avoid IP bans from concurrent bursts (self-inflicted DoS prevention).
    """
    if not query:
        return []

    sem = asyncio.Semaphore(_PASTE_SEMAPHORE)

    async def _safe_fetch(site: str) -> list[Any]:
        async with sem:
            delay = random.uniform(_JITTER_MIN, _JITTER_MAX)
            logger.debug("[CredMonitor] Throttling %.2fs before %s", delay, site)
            await asyncio.sleep(delay)
            return await _search_single_site(query, site)

    tasks = [_safe_fetch(site) for site in _PASTE_SITES]
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    all_results: list[Any] = []
    for r in responses:
        if isinstance(r, list):
            all_results.extend(r)

    # General search + filter for paste URLs
    general_q = f'"{query}" password OR leak OR credentials'
    general_results: list[Any] = list(await _ddg_engine.search(general_q, max_pages=1))
    if not general_results:
        general_results = list(await _sp_engine.search(general_q, max_pages=1))
    for r in general_results:
        if any(site in r.url for site in _PASTE_SITES):
            all_results.append(r)

    # Dedup by URL
    seen_urls: set[str] = set()
    results = []
    for r in all_results:
        if r.url and r.url not in seen_urls:
            seen_urls.add(r.url)
            results.append(r)

    if not results:
        logger.info("[CredMonitor] No paste results for '%s'", query[:40])
        return []

    findings: list[dict[str, Any]] = []
    for r in results[:max_results]:
        snippet_creds = extract_credentials(r.snippet)
        findings.append(
            {
                "url": r.url,
                "title": r.title,
                "snippet": r.snippet,
                "snippet_credentials": snippet_creds,
                "raw_credentials": {},
            }
        )

    raw_tasks = [_fetch_raw_content(r.url) for r in results[:_MAX_PASTE_FETCH]]
    raw_contents = await asyncio.gather(*raw_tasks, return_exceptions=True)

    for i, raw_text in enumerate(raw_contents):
        if isinstance(raw_text, str) and raw_text and i < len(findings):
            findings[i]["raw_credentials"] = extract_credentials(raw_text)

    total_creds = sum(len(f["snippet_credentials"]) + len(f["raw_credentials"]) for f in findings)
    logger.info(
        "[CredMonitor] Paste search: %d results, %d credential hits for '%s'",
        len(findings),
        total_creds,
        query[:40],
    )
    return findings


# ── GitHub Code Search (rate-limited, dual-layer protection) ─────


async def search_github_code(query: str, max_results: int = 10) -> list[dict[str, Any]]:
    """Search GitHub public code for leaked credentials.

    Uses GitHubRateLimiter for dual-layer protection:
      - Token bucket: 30 req/60s (authenticated) or 10 req/60s (unauthenticated)
      - Min interval: 2s between consecutive requests (anti-abuse)
    """
    if not query:
        return []
    if not GITHUB_TOKEN:
        logger.debug("[CredMonitor] No GITHUB_TOKEN set — skipping GitHub code search")
        return []

    await github_limiter.acquire()

    search_q = f'"{query}" password OR api_key OR secret OR token OR config'
    params: dict[str, str] = {"q": search_q, "per_page": str(min(max_results, 30))}

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _GITHUB_CODE_API,
                params=params,
                headers={
                    **_HEADERS,
                    "Accept": "application/vnd.github.v3+json",
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                },
            )
            if resp.status_code == 403:
                logger.warning("[CredMonitor] GitHub API 403 — secondary rate limit or token burned")
                return []
            if resp.status_code == 401:
                logger.warning("[CredMonitor] GitHub API 401 — invalid token")
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[CredMonitor] GitHub code search failed: %s", exc)
        return []

    items = data.get("items", [])
    findings: list[dict[str, Any]] = []
    for item in items[:max_results]:
        repo = item.get("repository", {})
        file_text = ""
        if item.get("text_matches"):
            file_text = item["text_matches"][0].get("fragment", "")
        creds = extract_credentials(file_text) if file_text else {}
        findings.append(
            {
                "url": item.get("html_url", ""),
                "repo": repo.get("full_name", ""),
                "file": item.get("name", ""),
                "snippet": file_text[:300],
                "credentials": creds,
            }
        )

    logger.info("[CredMonitor] GitHub: %d code results for '%s'", len(findings), query[:40])
    return findings


# ── Orchestrator ─────────────────────────────────────────────────


async def scan_credential_leaks(query: str) -> dict[str, Any]:
    """Orchestrate credential leak scanning across all sources (parallel).

    2 sources fire concurrently via asyncio.gather:
      - search_paste_sites() (internally rate-limited via Semaphore+Jitter)
      - search_github_code() (internally rate-limited via GitHubRateLimiter)
    """
    if not query or not query.strip():
        return {"query": query, "sources": {}, "total_hits": 0}

    clean = query.strip()[:200]
    results: dict[str, Any] = {"query": clean, "sources": {}, "total_hits": 0}

    gathered: tuple[Any, ...] = await asyncio.gather(
        search_paste_sites(clean),
        search_github_code(clean),
        return_exceptions=True,
    )

    source_names = ["paste_sites", "github_code"]
    for name, data in zip(source_names, gathered):
        if isinstance(data, Exception):
            results["sources"][name] = {"error": str(data)}
        else:
            results["sources"][name] = data

    # Count total credential hits
    total = 0
    for source_data in results["sources"].values():
        if isinstance(source_data, list):
            for item in source_data:
                for key in ("credentials", "snippet_credentials", "raw_credentials"):
                    creds = item.get(key, {})
                    if isinstance(creds, dict):
                        total += sum(len(v) for v in creds.values())
    results["total_hits"] = total

    logger.info("[CredMonitor] Scan complete for '%s': %d hits", clean[:40], total)
    return results


# format_credential_results moved to services/credential_format.py (was a
# single 40-point cognitive-complexity function — see .cognitive_baseline.txt
# history). Re-exported above via the top-of-file import for public API stability.
