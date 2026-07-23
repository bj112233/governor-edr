"""Scheduled News — public API.

Backward-compatible re-exports for all callers.
"""

from typing import Optional

from ._service import ScheduledNewsService

__all__ = [
    "ScheduledNewsService",
    "get_news_service",
    "start_news_service",
    "stop_news_service",
]

# Singleton instance
_news_service: ScheduledNewsService | None = None


def get_news_service() -> ScheduledNewsService:
    """Get or create the news service singleton."""
    global _news_service
    if _news_service is None:
        _news_service = ScheduledNewsService()
    return _news_service


async def start_news_service() -> None:
    """Initialize the news service (called from main.py)."""
    service = get_news_service()
    await service.initialize()


async def stop_news_service() -> None:
    """No-op: scheduler jobs are managed externally."""
    pass
