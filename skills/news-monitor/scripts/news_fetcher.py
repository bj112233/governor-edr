"""News Monitor — Data Access Layer (I/O only).

Pure network fetching: RSS feeds, site scraping, article extraction.
No business logic, no parsing rules, no rendering.
"""

from __future__ import annotations

import logging
import re
import socket
from typing import Any

import aiohttp
import feedparser
from bs4 import BeautifulSoup

from _news_utils import (
    _format_published,
    _is_recent,
    _sanitize_text,
)

logger = logging.getLogger(__name__)


# ── Local helper (matches original runtime shadowed behaviour) ──


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    if not text or "<" not in text:
        return text
    no_tags = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", no_tags).strip()


# ── RSS Feed Fetching ──


def fetch_rss(url: str, limit: int = 10) -> list[dict[str, Any]]:
    """Fetch and parse an RSS/Atom feed.

    Returns a list of article dicts with keys: title, link, published, summary.
    On any failure returns an empty list (fail-safe).
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(15)
    try:
        d = feedparser.parse(url)
    except Exception as exc:
        logger.warning("[NewsFetcher] RSS parse failed for %s: %s", url, exc)
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)

    out: list[dict[str, Any]] = []
    for entry in d.entries:
        raw_published = entry.get("published", "")
        if not _is_recent(raw_published, hours=48):
            continue
        published = _format_published(entry)
        title = _strip_html(entry.get("title", ""))
        summary = _strip_html(entry.get("summary", ""))
        out.append(
            {
                "title": _sanitize_text(title),
                "link": _sanitize_text(entry.get("link", "")),
                "published": _sanitize_text(published),
                "summary": _sanitize_text(summary)[:500],
            }
        )
        if len(out) >= limit:
            break
    return out


# ── Site Scraping ──


async def fetch_site(url: str, selector: str, limit: int = 10) -> list[dict[str, str]]:
    """Scrape a news site via CSS selector.

    Returns a list of article dicts with keys: title, link.
    On any failure returns an empty list (fail-safe).
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"User-Agent": "SentinelNewsBot/1.0"},
            ) as response:
                response.raise_for_status()
                text = await response.text()
    except Exception as exc:
        logger.warning("[NewsFetcher] Site fetch failed for %s: %s", url, exc)
        return []

    soup = BeautifulSoup(text, "html.parser")
    items = soup.select(selector)[:limit]
    out: list[dict[str, str]] = []
    for item in items:
        a = item.find("a") if item.name != "a" else item
        out.append(
            {
                "title": (a.get_text(strip=True) if a else item.get_text(strip=True)),
                "link": a["href"] if a and a.has_attr("href") else url,
            }
        )
    return out


# ── Full Article Text Extraction ──


async def fetch_article_text(url: str) -> str:
    """Download article HTML and extract clean text via readability-lxml.

    Returns ~2000 chars or empty string on failure.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"User-Agent": "SentinelNewsBot/1.0"},
            ) as response:
                response.raise_for_status()
                html = await response.text()
    except Exception as exc:
        logger.debug("[NewsFetcher] Article fetch failed for %s: %s", url, exc)
        return ""

    try:
        from readability import Document
    except ModuleNotFoundError:
        return ""

    try:
        doc = Document(html)
        text = doc.summary()
        soup = BeautifulSoup(text, "html.parser")
        clean = soup.get_text(separator="\n", strip=True)
        clean = re.sub(r"\n\s*\n", "\n", clean)
        clean = re.sub(r"[ \t]+", " ", clean)
        clean = _sanitize_text(clean)
        return clean[:2000]
    except Exception as exc:
        logger.debug("[NewsFetcher] Article extraction failed for %s: %s", url, exc)
        return ""
