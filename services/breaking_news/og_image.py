# services/breaking_news/og_image.py
"""Fallback per-article image extraction via Open Graph meta tag (og:image).

RSS-level image extraction (ingestion._extract_image_url) misses images for
feeds that don't populate media_content/enclosure/HTML <img> (e.g. Ynet's
מבזקים feed). This module fetches the full article page as a best-effort
fallback — ONLY for sources verified to publish real per-article og:image
(see OG_IMAGE_ELIGIBLE_SOURCES). inn.co.il was tested and excluded: it
returns the same site-wide placeholder image for every article regardless
of content (verified 2026-07-05), so fetching it wastes a request.
"""

import asyncio
import logging
import re

import aiohttp

logger = logging.getLogger(__name__)

_OG_IMAGE_RE = re.compile(
    r'<meta[^>]+(?:property|name)=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_OG_IMAGE_RE_REV = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+(?:property|name)=["\']og:image["\']',
    re.IGNORECASE,
)

# Site-wide generic images returned as og:image regardless of article content —
# these teach us nothing over the favicon fallback we already have.
_GENERIC_OG_PATTERNS = re.compile(r"defual_image|default_image|placeholder|no-?image", re.IGNORECASE)

_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_TIMEOUT = aiohttp.ClientTimeout(total=6.0)
_MAX_CONCURRENT = 5

# Sources worth the extra fetch. Add a source here only after verifying it
# publishes a real, per-article og:image (not a site-wide placeholder).
OG_IMAGE_ELIGIBLE_SOURCES = frozenset({"Ynet מבזקים", "חדשות ישראל ללא צנזורה"})


async def _fetch_og_image(link: str, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> str:
    """Fetch article page and extract og:image. Returns "" on any failure."""
    if not link:
        return ""
    async with sem:
        try:
            async with session.get(link, timeout=_TIMEOUT, headers={"User-Agent": _UA}) as resp:
                if resp.status != 200:
                    return ""
                html = await resp.text()
        except Exception as exc:
            logger.debug("[BreakingNews] og:image fetch failed (%s): %s", link, exc)
            return ""

    match = _OG_IMAGE_RE.search(html) or _OG_IMAGE_RE_REV.search(html)
    if not match:
        return ""
    url = match.group(1)
    if _GENERIC_OG_PATTERNS.search(url):
        return ""
    return url


async def enrich_missing_images(items: list[dict]) -> None:
    """Best-effort: fill item["image"] via og:image for eligible sources missing a real image.

    Mutates items in place. Fault-isolated — never raises, never blocks the
    send pipeline on a slow/broken article page.
    """
    targets = [
        it
        for it in items
        if not it.get("_image_from_rss") and it.get("source") in OG_IMAGE_ELIGIBLE_SOURCES and it.get("link")
    ]
    if not targets:
        return

    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    try:
        async with aiohttp.ClientSession() as session:
            results = await asyncio.gather(
                *(_fetch_og_image(it["link"], session, sem) for it in targets),
                return_exceptions=True,
            )
    except Exception as exc:
        logger.debug("[BreakingNews] og:image batch failed: %s", exc)
        return

    found = 0
    for it, result in zip(targets, results):
        if isinstance(result, str) and result:
            it["image"] = result
            found += 1
    if found:
        logger.info("[BreakingNews] og:image fallback resolved %d/%d images", found, len(targets))
