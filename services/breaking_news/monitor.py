# services/breaking_news/monitor.py
"""Breaking News Monitor — orchestrator. Stateful singleton via get_monitor()."""

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .config import NewsConfig
from .dedup import cluster_dedup, intra_batch_dedup, link_dedup
from .dispatch import send_cluster_alert
from .filtering import _title_signature, filter_by_keywords
from .ingestion import fetch_all_feeds
from .state import MonitorState, load_state, save_state

if TYPE_CHECKING:
    from services.telegram import TelegramChannel

logger = logging.getLogger(__name__)


class BreakingNewsMonitor:
    """Real-time breaking news monitoring service."""

    def __init__(self) -> None:
        self.config = NewsConfig()
        self.state = MonitorState()
        self.telegram_channel: TelegramChannel | None = None
        self.state_file = Path(__file__).parent.parent.parent / "state" / "breaking_news_state.json"
        self._bg_tasks: set[asyncio.Task] = set()
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Load config, connect Telegram, load persisted state."""
        await self.config.load()
        try:
            from services.telegram import get_telegram_channel

            self.telegram_channel = get_telegram_channel()
            if self.telegram_channel:
                logger.info("[BreakingNews] Telegram channel connected")
        except ImportError:
            logger.warning("[BreakingNews] Telegram channel not available")
        except Exception as e:
            logger.warning("[BreakingNews] Failed to connect to telegram channel: %s", e)

        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state = await load_state(self.state_file)

    async def check_breaking_news(self) -> None:
        """Main check function — fetch, filter, dedup, cluster, send."""
        async with self._lock:
            return await self._run_cycle()

    async def _run_cycle(self) -> None:
        """Locked body of check_breaking_news."""
        logger.info("[BreakingNews] Checking for breaking news...")
        try:
            all_items = await fetch_all_feeds(self.config.config)
            urgent = filter_by_keywords(
                all_items,
                self.config.keyword_regex,
                secondary_regex=self.config.secondary_regex,
                context_regex=self.config.context_regex,
            )

            link_deduped = link_dedup(urgent, self.state)
            link_dups = len(urgent) - len(link_deduped)

            new_items = intra_batch_dedup(link_deduped)
            intra_dups = len(link_deduped) - len(new_items)

            from .og_image import enrich_missing_images

            await enrich_missing_images(new_items)

            total_dups = link_dups + intra_dups
            if total_dups:
                logger.info(
                    "[BreakingNews] Dedup: link=%d intra=%d total=%d filtered",
                    link_dups,
                    intra_dups,
                    total_dups,
                )

            from .ai_scoring import enrich_items

            new_items = await enrich_items(new_items)

            now = time.time()
            clusters = cluster_dedup(new_items, self.state, now)
            cluster_dups = len(new_items) - len(clusters)
            if cluster_dups:
                logger.info(
                    "[BreakingNews] Cluster consolidation: %d items → %d clusters (%d merged)",
                    len(new_items),
                    len(clusters),
                    cluster_dups,
                )

            logger.info("[BreakingNews] Sending %d consolidated alerts...", len(clusters))
            sent_any = False
            for cluster in clusters:
                success = await send_cluster_alert(cluster, self.telegram_channel, self._bg_tasks)
                if success:
                    sent_any = True
                    # Record every item in the cluster as sent (link + title sig)
                    for item in cluster.items:
                        link = item.get("link", "")
                        title = item.get("title", "")
                        self.state.add_sent(link, _title_signature(title), now)

            if sent_any:
                self.state.cleanup(now=now)

            await save_state(self.state, self.state_file)
            logger.info("[BreakingNews] Sent %d consolidated alerts", len(clusters))
        except Exception as e:
            logger.error("[BreakingNews] Error in breaking news check: %s", e, exc_info=True)


# ── Singleton instance ──
_monitor: BreakingNewsMonitor | None = None


def get_monitor() -> BreakingNewsMonitor:
    """Get or create the breaking news monitor singleton."""
    global _monitor
    if _monitor is None:
        _monitor = BreakingNewsMonitor()
    return _monitor


async def start_monitor() -> None:
    """Initialize the monitor (called from main.py)."""
    await get_monitor().initialize()


async def stop_monitor() -> None:
    """No-op: scheduler jobs are managed by the main scheduler."""
    pass
