# tests/test_news_digest_fire_and_forget.py
"""Tests for trigger_news_digest_tool fire-and-forget refactor.

Verifies the tool returns immediately (without waiting for the full
RSS+AI+SITREP pipeline) and that the pipeline runs in the background.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.tools.mcp_skill_handlers import (
    _bg_digest_tasks,
    trigger_news_digest_tool,
)


def _mock_news_service():
    svc = MagicMock()
    svc.initialize = AsyncMock()
    svc.trigger_manual_digest = AsyncMock()
    return svc


async def test_returns_immediately_without_awaiting_pipeline():
    """The tool must return before trigger_manual_digest completes."""
    started = asyncio.Event()

    async def slow_digest(*, category_filter=""):
        started.set()
        await asyncio.sleep(10)  # simulate long pipeline

    svc = _mock_news_service()
    svc.trigger_manual_digest = slow_digest

    with patch("services.scheduled_news.get_news_service", return_value=svc):
        result = await trigger_news_digest_tool()
        await asyncio.sleep(0)  # yield to let background task start

    assert "התחיל" in result
    assert started.is_set()  # background task was started
    # Clean up: cancel the lingering background task
    for t in list(_bg_digest_tasks):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


async def test_returns_category_in_message_when_specified():
    svc = _mock_news_service()
    with patch("services.scheduled_news.get_news_service", return_value=svc):
        result = await trigger_news_digest_tool(category="cyber")
    assert "cyber" in result
    for t in list(_bg_digest_tasks):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


async def test_initialize_is_awaited_before_backgrounding():
    """initialize() must complete before we start the background task."""
    svc = _mock_news_service()
    init_done = False

    async def track_init():
        nonlocal init_done
        init_done = True

    svc.initialize = track_init

    with patch("services.scheduled_news.get_news_service", return_value=svc):
        await trigger_news_digest_tool()

    assert init_done
    for t in list(_bg_digest_tasks):
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass


async def test_background_task_removed_from_set_after_completion():
    svc = _mock_news_service()
    svc.trigger_manual_digest = AsyncMock()

    with patch("services.scheduled_news.get_news_service", return_value=svc):
        await trigger_news_digest_tool()

    # Wait for background task to complete
    await asyncio.sleep(0.3)
    assert len(_bg_digest_tasks) == 0  # done_callback discarded it


async def test_error_in_initialize_returns_error_message():
    svc = _mock_news_service()
    svc.initialize = AsyncMock(side_effect=RuntimeError("boom"))

    with patch("services.scheduled_news.get_news_service", return_value=svc):
        result = await trigger_news_digest_tool()

    assert "❌" in result
    assert "boom" in result
