# tests/test_ingestion_fetch.py
"""Unit tests for feed ingestion dispatch (no network)."""

from services.breaking_news.ingestion import fetch_feed_items


async def test_disabled_feed_returns_empty():
    """A feed with enabled=False must short-circuit to [] without fetching."""
    result = await fetch_feed_items({"enabled": False, "url": "http://x"}, session=None)
    assert result == []
