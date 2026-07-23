# services/breaking_news/ingestion.py
"""RSS/HTTP feed fetching — concurrent I/O via aiohttp + feedparser parsing.

Supports two feed types:
  - "rss": standard RSS/Atom via feedparser
  - "telegram_web": Telegram public channel preview (t.me/s/{channel}) via HTML scrape
"""

import asyncio
import html
import logging
import re

import aiohttp

logger = logging.getLogger(__name__)

_IMG_SRC_RE = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")
_SUMMARY_TEXT_LIMIT = 300


def _clean_summary_text(raw: str, limit: int = _SUMMARY_TEXT_LIMIT) -> str:
    """Strip HTML tags/entities from an RSS summary, THEN truncate.

    Must unescape+strip BEFORE truncating — some feeds (e.g. Walla) prefix
    the summary with a long <img src="..."> tag; truncating the raw HTML
    first cuts off the real text that follows before it's ever reached.
    """
    if not raw:
        return ""
    text = html.unescape(raw)  # handles literal AND entity-encoded tags (&lt;p&gt;)
    text = _HTML_TAG_RE.sub(" ", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:limit]


# Placeholder/garbage image URL patterns — these are default images sites
# put in RSS feeds when no real image exists (e.g. inn.co.il /files/pictures/0/0.jpg).
_PLACEHOLDER_PATTERNS = re.compile(
    r"(?:/0/0\.\w+$"  # inn.co.il: /files/pictures/0/0.jpg
    r"|/0x0\.\w+$"  # 0x0 dimension placeholders
    r"|/1x1\.\w+$"  # 1x1 tracking pixels
    r"|placeholder|default|spacer|blank|no-?image|no_?image)",
    re.IGNORECASE,
)


def _is_placeholder_image(url: str) -> bool:
    """True if URL matches known placeholder/garbage patterns."""
    return bool(url and _PLACEHOLDER_PATTERNS.search(url))


def _first_media_url(entry, key: str) -> str:
    """Return first .url from a media_* list field, or ""."""
    for m in entry.get(key, []) or []:
        url = m.get("url", "") if isinstance(m, dict) else ""
        if url:
            return url
    return ""


def _enclosure_image_url(entry) -> str:
    """Return href of first image enclosure, or ""."""
    for enc in entry.get("enclosures", []) or []:
        if isinstance(enc, dict):
            ctype = enc.get("type", "")
            if ctype.startswith("image/") and enc.get("href"):
                return enc["href"]
    return ""


def _img_from_html(entry) -> str:
    """Extract first <img src="..."> from summary/content/description HTML."""
    for field in ("summary", "content", "description"):
        val = entry.get(field, "") or ""
        if isinstance(val, list):  # content field can be list of dicts
            val = " ".join(str(v.get("value", "")) for v in val if isinstance(v, dict))
        m = _IMG_SRC_RE.search(val)
        if m:
            return m.group(1)
    return ""


def _extract_image_url(entry) -> str:
    """Extract best available image URL from a feedparser entry.

    Priority: media_content → media_thumbnail → image enclosure → <img> in HTML.
    Filters out placeholder/garbage URLs. Returns "" if none found.
    """
    for url in (
        _first_media_url(entry, "media_content"),
        _first_media_url(entry, "media_thumbnail"),
        _enclosure_image_url(entry),
        _img_from_html(entry),
    ):
        if url and not _is_placeholder_image(url):
            return url
    return ""


# Israeli news sites (Ynet/Walla) block default script User-Agents (WAF).
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
_HEADERS = {"User-Agent": _UA}
_TIMEOUT = aiohttp.ClientTimeout(total=10.0)


async def fetch_feed_items(feed: dict, session: aiohttp.ClientSession, limit: int = 10) -> list[dict]:
    """Fetch items from a single feed (fault-isolated)."""
    if not feed.get("enabled", True):
        return []
    feed_type = feed.get("type", "rss")
    if feed_type == "rss":
        return await _fetch_rss(feed, session, limit)
    if feed_type == "telegram_web":
        return await _fetch_telegram_web(feed, session, limit)
    logger.warning("[BreakingNews] Unsupported feed type: %s", feed_type)
    return []


async def _fetch_rss(feed: dict, session: aiohttp.ClientSession, limit: int = 10) -> list[dict]:
    """Fetch RSS via aiohttp (concurrent) + parse via feedparser in thread.

    Fault isolation: any failure (timeout, HTTP error, parse error) is caught
    here and returns [] so sibling feeds in the gather continue unaffected.
    """
    url = feed.get("url")
    name = feed.get("name", "Unknown")
    if not url:
        return []
    logger.info("[BreakingNews] Fetching from %s: %s", name, url)
    try:
        async with session.get(url, timeout=_TIMEOUT) as response:
            response.raise_for_status()  # aiohttp does not raise on 4xx/5xx by itself
            xml_data = await response.text()
    except TimeoutError:
        logger.warning("[BreakingNews] RSS timeout (%s): %s", name, url)
        return []
    except aiohttp.ClientResponseError as e:
        logger.warning("[BreakingNews] HTTP %d from %s: %s", e.status, name, url)
        return []
    except Exception as e:
        logger.error("[BreakingNews] Error fetching RSS %s: %s", name, e)
        return []

    # feedparser is CPU-bound/sync — parse the already-fetched XML in a thread
    try:
        import feedparser

        d = await asyncio.to_thread(feedparser.parse, xml_data)
    except Exception as e:
        logger.error("[BreakingNews] Parse error (%s): %s", name, e)
        return []

    items = []
    default_image = feed.get("default_image", "")
    for entry in d.entries[:limit]:
        rss_image = _extract_image_url(entry)
        items.append(
            {
                "title": entry.get("title", ""),
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
                "published_parsed": entry.get("published_parsed"),
                "summary": _clean_summary_text(entry.get("summary", "")),
                "image": rss_image or default_image,
                # True when a real per-article image came from the RSS entry itself
                # (media_content/enclosure/HTML <img>) — False means "image" is just
                # the generic default_image fallback, a candidate for og:image lookup.
                "_image_from_rss": bool(rss_image),
                "category": feed.get("category", "breaking"),
                "source": name,
            }
        )
    logger.info("[BreakingNews] Got %d items from %s", len(items), name)
    return items


# ── Telegram Web preview (t.me/s/{channel}) ──

# Channel signature footer — appended to every post, must be stripped
# before fingerprinting/keyword matching to avoid polluting the signal.
_TG_SIGNATURE_RE = re.compile(
    r"מבזקי.*?רעם.*?מבזקי.*?חדשות.*?זמן.*?אמת.*?📲.*?https://t\.me/\S+",
    re.DOTALL,
)

_TG_TITLE_LIMIT = 200


async def _fetch_telegram_web(feed: dict, session: aiohttp.ClientSession, limit: int = 10) -> list[dict]:
    """Fetch Telegram public channel via t.me/s/{channel} HTML preview.

    No API token required — uses the public web preview. Parses the last
    ~20 messages, strips channel signature, returns items in the same dict
    format as _fetch_rss. Fault-isolated like _fetch_rss.
    """
    channel = feed.get("channel", "")
    name = feed.get("name", "Unknown")
    if not channel:
        return []
    url = f"https://t.me/s/{channel}"
    logger.info("[BreakingNews] Fetching from %s: %s", name, url)
    try:
        async with session.get(url, timeout=_TIMEOUT) as response:
            response.raise_for_status()
            html_data = await response.text()
    except TimeoutError:
        logger.warning("[BreakingNews] Telegram timeout (%s): %s", name, url)
        return []
    except aiohttp.ClientResponseError as e:
        logger.warning("[BreakingNews] HTTP %d from %s: %s", e.status, name, url)
        return []
    except Exception as e:
        logger.error("[BreakingNews] Error fetching Telegram %s: %s", name, e)
        return []

    try:
        from bs4 import BeautifulSoup

        soup = await asyncio.to_thread(BeautifulSoup, html_data, "lxml")
    except Exception as e:
        logger.error("[BreakingNews] Parse error (%s): %s", name, e)
        return []

    items = _parse_tg_messages(soup, feed, name, limit)
    logger.info("[BreakingNews] Got %d items from %s", len(items), name)
    return items


def _parse_tg_messages(soup, feed: dict, name: str, limit: int) -> list[dict]:
    """Extract text messages from parsed Telegram HTML into item dicts."""
    default_image = feed.get("default_image", "")
    items: list[dict] = []
    for msg in soup.select(".tgme_widget_message_wrap"):
        text_el = msg.select_one(".tgme_widget_message_text")
        if not text_el:
            continue  # media-only — skip (no text to match)
        raw_text = text_el.get_text(" ", strip=True)
        clean_text = _TG_SIGNATURE_RE.sub("", raw_text).strip()
        if not clean_text:
            continue
        link_el = msg.select_one(".tgme_widget_message_date")
        link = link_el.get("href", "") if link_el else ""
        time_el = msg.find("time")
        published = time_el.get("datetime", "") if time_el else ""
        items.append(
            {
                "title": clean_text[:_TG_TITLE_LIMIT],
                "link": link,
                "published": published,
                "summary": clean_text,
                "image": default_image,
                "_image_from_rss": False,  # triggers og:image fallback
                "category": feed.get("category", "breaking"),
                "source": name,
            }
        )
        if len(items) >= limit:
            break
    return items


async def fetch_all_feeds(config: dict) -> list[dict]:
    """Fetch items from all configured feeds concurrently.

    Time complexity: O(Max(feed_latencies)) instead of O(Sum).
    One shared ClientSession with WAF-safe User-Agent.
    """
    feeds = config.get("feeds", [])
    logger.info("[BreakingNews] Fetching from %d feeds (concurrent)...", len(feeds))
    async with aiohttp.ClientSession(headers=_HEADERS) as session:
        results = await asyncio.gather(
            *(fetch_feed_items(feed, session, limit=10) for feed in feeds),
            return_exceptions=False,  # exceptions already isolated per-feed
        )
    all_items: list[dict] = []
    for items in results:
        all_items.extend(items)
    logger.info("[BreakingNews] Total items fetched: %d", len(all_items))
    return all_items
