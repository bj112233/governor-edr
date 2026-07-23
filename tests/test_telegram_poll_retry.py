import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.telegram import TelegramChannel
from services.telegram.polling import _poll


class TestTelegramPollRetry:
    """Resilient polling retry with exponential backoff."""

    def _make_channel(self) -> TelegramChannel:
        """Build a minimal TelegramChannel without running __init__."""
        tg = TelegramChannel.__new__(TelegramChannel)
        tg._running = True
        tg._stop_event = asyncio.Event()
        tg.bot = MagicMock()
        tg.bot.session.close = AsyncMock()
        tg.dp = MagicMock()
        tg.dp.stop_polling = AsyncMock()
        tg.dp.include_router = MagicMock()
        tg.router = MagicMock()
        tg._token = "test-token"
        return tg

    async def test_transient_error_retries(self):
        """Transient network errors trigger retry loop."""
        tg = self._make_channel()

        call_count = 0

        async def _failing_start_polling(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("ClientOSError: [WinError 121] The semaphore timeout period has expired")
            # On 3rd call, set stop_event to exit cleanly
            tg._stop_event.set()

        tg.dp.start_polling = _failing_start_polling

        def _setup_routes():
            # _poll recreates the Dispatcher after each transient error,
            # so re-attach the failing poller to the fresh mock dispatcher.
            tg.dp.start_polling = _failing_start_polling
            tg.dp.stop_polling = AsyncMock()
            tg.dp.include_router = MagicMock()

        tg.setup_routes = _setup_routes

        def _make_bot(*args, **kwargs):
            m = MagicMock()
            m.session.close = AsyncMock()
            return m

        with (
            patch("services.telegram.polling.logger"),
            patch("aiogram.Dispatcher", side_effect=lambda **kw: MagicMock()),
            patch("services.telegram.polling.Bot", side_effect=_make_bot),
            patch("services.telegram.polling.AiohttpSession", return_value=MagicMock()),
        ):
            # Retry delays: attempt 1 -> 5s, attempt 2 -> 10s
            # Total ~15s + margin = 20s
            await asyncio.wait_for(_poll(tg), timeout=20.0)

        assert call_count >= 3, f"Expected at least 3 polling attempts, got {call_count}"

    async def test_fatal_error_aborts(self):
        """Non-transient (fatal) errors abort immediately without retry."""
        tg = self._make_channel()

        call_count = 0

        async def _fatal_start_polling(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("Invalid bot token: 403 Forbidden")

        tg.dp.start_polling = _fatal_start_polling

        with patch("services.telegram.polling.logger"):
            await _poll(tg)

        assert call_count == 1, f"Expected 1 attempt for fatal error, got {call_count}"
        assert tg._running is False

    async def test_clean_stop_exits_gracefully(self):
        """If stop_event is set during retry delay, polling exits without retry."""
        tg = self._make_channel()

        call_count = 0

        async def _failing_start_polling(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            # Always raise transient error to enter retry delay
            raise Exception("ClientOSError: [WinError 121] The semaphore timeout period has expired")

        tg.dp.start_polling = _failing_start_polling

        # Set stop_event during first retry delay (5s)
        async def _trigger_stop():
            await asyncio.sleep(0.5)
            tg._stop_event.set()

        with patch("services.telegram.polling.logger"):
            asyncio.create_task(_trigger_stop())
            await asyncio.wait_for(_poll(tg), timeout=5.0)

        assert call_count == 1, f"Expected 1 attempt before graceful stop, got {call_count}"
        assert tg._running is True  # _running stays True on graceful stop
