"""ScheduledNewsService — orchestrator. No scheduler inside; callable only."""

import logging
from typing import Optional

from ._config import load_delivery_config, load_profiles
from ._delivery import DigestDelivery
from ._fetcher import RssFetcher
from ._filter import KeywordFilter
from ._formatter import format_digest

logger = logging.getLogger(__name__)


class ScheduledNewsService:
    """Orchestrator: fetch → filter → enrich → format → deliver.

    The service is scheduler-agnostic. An external scheduler (e.g.
    APScheduler in main.py or bootstrap/scheduler.py) calls
    send_daily_digest() at the configured time.
    """

    def __init__(self):
        self.profiles: list[dict] = []
        self.delivery_config: dict = {}
        self.telegram_channel = None
        self._fetcher = RssFetcher()
        self._delivery: DigestDelivery | None = None

    async def initialize(self) -> None:
        """Load config and connect Telegram channel."""
        self.delivery_config = load_delivery_config()
        self.profiles = load_profiles()
        self._connect_telegram()
        self._delivery = DigestDelivery(self.telegram_channel, self.delivery_config)

    def _connect_telegram(self) -> None:
        """Best-effort Telegram connection via DI gateway (non-blocking)."""
        try:
            from services.interfaces import get_message_gateway

            self.telegram_channel = get_message_gateway()
            if self.telegram_channel:
                logger.info("[NewsService] Telegram channel connected")
            else:
                logger.warning("[NewsService] Telegram not available — console fallback")
        except Exception as exc:
            logger.warning("[NewsService] Telegram connection failed: %s", exc)
            self.telegram_channel = None

    async def send_daily_digest(self, category_filter: str = "") -> None:
        """Main orchestration: fetch → filter → enrich → format → deliver."""
        if self._delivery is None:
            logger.error("[NewsService] Not initialized. Call initialize() first.")
            return

        logger.info("[NewsService] Starting daily digest (filter: %s)", category_filter or "all")
        try:
            # 1. Fetch
            items_per_feed = self.delivery_config.get("items_per_category", 3)
            categorized = await self._fetcher.fetch_all(self.profiles, items_per_feed)

            # 2. Category filter
            if category_filter:
                cat_lower = category_filter.lower()
                categorized = {cat: items for cat, items in categorized.items() if cat.lower() == cat_lower}
                if not categorized:
                    logger.warning("[NewsService] No items for category: %s", category_filter)
                    return

            for cat, items in categorized.items():
                logger.info("[NewsService]   %s: %d items fetched", cat, len(items))

            # 3. Keyword filter
            profile_keywords = {p["name"]: p["keywords"] for p in self.profiles}
            for cat in categorized:
                kws = profile_keywords.get(cat, [])
                if kws:
                    categorized[cat] = KeywordFilter.filter(categorized[cat], kws)

            # 4. AI enrich
            if self.delivery_config.get("ai_digest"):
                all_flat = []
                for cat_items in categorized.values():
                    all_flat.extend(cat_items)
                if all_flat:
                    await self._delivery.ai_enrich(all_flat)

            # 5. Format
            message = format_digest(categorized)

            # 6. Deliver
            await self._delivery.send_digest(message)

            # 7. SITREP — news-intelligence summary (decoupled from 08:00 alerts digest)
            await self._delivery.generate_sitrep(categorized)

        except Exception as exc:
            logger.error("[NewsService] Daily digest error: %s", exc, exc_info=True)

    async def trigger_manual_digest(self, category_filter: str = "") -> None:
        """Manual trigger for testing."""
        await self.send_daily_digest(category_filter=category_filter)
