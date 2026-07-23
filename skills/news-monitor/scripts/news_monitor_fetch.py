"""News Monitor — Fetch stage.

Acquires raw items from feed / site / config sources and performs optional
parallel full-text extraction. Pure I/O orchestration — no transformations.
"""

from __future__ import annotations

import asyncio
import json
import logging

from _news_utils import NewsMonitorArgs
from news_fetcher import fetch_article_text, fetch_rss, fetch_site

logger = logging.getLogger(__name__)


async def fetch_raw_items(args: NewsMonitorArgs) -> list[dict]:
    """Stage 1: acquire raw items from the configured source."""
    if args.feed:
        return await asyncio.to_thread(fetch_rss, args.feed, args.limit)
    if args.site:
        return await fetch_site(args.site, args.selector, args.limit)
    if args.config:
        return await _fetch_from_config(args)
    return []


async def _fetch_from_config(args: NewsMonitorArgs) -> list[dict]:
    """Fetch all enabled feeds declared in a JSON config file."""
    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    feeds_active = [fd for fd in cfg.get("feeds", []) if fd.get("enabled") is not False]
    workers = max(1, int(args.workers or 1))
    if workers == 1:
        raw_items = await _fetch_sequential(feeds_active, args)
    else:
        raw_items = await _fetch_concurrent(feeds_active, workers, args)
    if not args.keywords and cfg.get("keywords"):
        args.keywords = ",".join(cfg["keywords"])
    return raw_items


async def _fetch_sequential(feeds: list[dict], args: NewsMonitorArgs) -> list[dict]:
    raw_items: list[dict] = []
    for feed in feeds:
        raw_items.extend(await _fetch_one(feed, args))
        if args.delay > 0:
            await asyncio.sleep(args.delay)
    return raw_items


async def _fetch_concurrent(
    feeds: list[dict], workers: int, args: NewsMonitorArgs
) -> list[dict]:
    semaphore = asyncio.Semaphore(workers)

    async def _bounded(feed: dict) -> list[dict]:
        async with semaphore:
            return await _fetch_one(feed, args)

    raw_items: list[dict] = []
    for fetched in await asyncio.gather(*[_bounded(f) for f in feeds]):
        raw_items.extend(fetched)
    return raw_items


async def _fetch_one(feed: dict, args: NewsMonitorArgs) -> list[dict]:
    """Fetch a single feed, tagging each item with category/source."""
    try:
        fetched = await _dispatch_fetch(feed, args)
    except Exception as exc:
        logger.warning("feed failed: %s — %s", feed.get("url"), exc)
        return []
    cat = feed.get("category", "general")
    src = feed.get("name") or feed.get("url", "")
    for it in fetched:
        it.setdefault("category", cat)
        it.setdefault("source", src)
    return fetched


async def _dispatch_fetch(feed: dict, args: NewsMonitorArgs) -> list[dict]:
    if feed.get("type") == "rss":
        return await asyncio.to_thread(fetch_rss, feed["url"], args.limit)
    return await fetch_site(feed["url"], feed.get("selector", args.selector), args.limit)


async def extract_full_text(raw_items: list[dict]) -> None:
    """Stage 2: parallel full-text extraction (mutates raw_items in place)."""
    if not raw_items:
        return
    links = [it.get("link", "") for it in raw_items]
    texts = await asyncio.gather(*[fetch_article_text(link) for link in links])
    for it, txt in zip(raw_items, texts):
        it["full_text"] = txt
