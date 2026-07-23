"""RSS fetcher — sanitization layer. Releases parser objects immediately to GC."""

import asyncio
import logging
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

logger = logging.getLogger(__name__)

_MAX_AGE_HOURS = 24


class RssFetcher:
    """Fetch RSS feeds and return clean item dicts. No parser state leaks."""

    async def fetch_feed(self, feed: dict, limit: int = 10) -> list[dict]:
        """Fetch items from a single feed."""
        if not feed.get("enabled", True):
            return []

        feed_type = feed.get("type", "rss")
        if feed_type == "rss":
            return await self._fetch_rss(feed, limit)
        logger.warning("[NewsFetcher] Unsupported feed type: %s", feed_type)
        return []

    async def _fetch_rss(self, feed: dict, limit: int) -> list[dict]:
        """Fetch RSS — parse, strip HTML, filter by age, release parser objects."""
        url = feed.get("url")
        if not url:
            return []

        try:
            import feedparser
            from bs4 import BeautifulSoup

            d = await asyncio.wait_for(
                asyncio.to_thread(feedparser.parse, url),
                timeout=10.0,
            )
            items = []
            for entry in d.entries[:limit]:
                published = entry.get("published", "")
                if not self._is_recent(published):
                    continue
                raw_summary = entry.get("summary", "")
                clean_summary = self._strip_html(raw_summary) if raw_summary else ""
                items.append(
                    {
                        "title": entry.get("title", ""),
                        "link": entry.get("link", ""),
                        "published": published,
                        "summary": clean_summary[:300],
                        "category": feed.get("category", "general"),
                        "source": feed.get("name", "Unknown"),
                    }
                )
            # Explicitly release parser objects for GC
            del d
            return items
        except TimeoutError:
            logger.warning("[NewsFetcher] RSS timeout (%s): %s", feed.get("name"), url)
            return []
        except Exception as exc:
            logger.error("[NewsFetcher] RSS error (%s): %s", feed.get("name"), exc)
            return []

    @staticmethod
    def _is_recent(published: str) -> bool:
        """True if published is within _MAX_AGE_HOURS of now. No date = keep."""
        if not published:
            return True
        try:
            dt = parsedate_to_datetime(published)
            if dt is None:
                return True
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return datetime.now(UTC) - dt < timedelta(hours=_MAX_AGE_HOURS)
        except Exception:
            return True

    @staticmethod
    def _strip_html(raw: str) -> str:
        """Strip HTML tags using BeautifulSoup, then release."""
        if "<" not in raw:
            return raw
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(raw, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
        del soup  # Release immediately
        return text

    async def fetch_all(self, profiles: list[dict], items_per_feed: int = 3) -> dict[str, list[dict]]:
        """Fetch from all profile feeds with per-category limit."""
        max_per_category = 10
        all_items: dict[str, list[dict]] = {}
        for profile in profiles:
            category = profile["name"]
            if category not in all_items:
                all_items[category] = []
            for feed in profile["feeds"]:
                if len(all_items[category]) >= max_per_category:
                    break
                feed_with_category = {**feed, "category": category}
                items = await self.fetch_feed(feed_with_category, limit=items_per_feed)
                all_items[category].extend(items)
                await asyncio.sleep(0.2)
        return all_items
