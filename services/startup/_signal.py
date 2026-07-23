"""Signal handlers + graceful shutdown helpers. Leaf module."""

import asyncio
import logging
import signal
from typing import Optional

logger = logging.getLogger(__name__)

# First Principles: Lazy initialization prevents RuntimeError on module import
_shutdown_event: asyncio.Event | None = None


def get_shutdown_event() -> asyncio.Event:
    """Get or create the global shutdown event safely inside the running loop."""
    global _shutdown_event
    if _shutdown_event is None:
        _shutdown_event = asyncio.Event()
    return _shutdown_event


def _setup_signal_handlers() -> None:
    """SIGTERM and SIGINT handler for graceful shutdown."""

    def _handle_signal(signum, _frame):
        sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
        logger.info("🛑 [%s] received - initiating graceful shutdown...", sig_name)
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(get_shutdown_event().set)
        except RuntimeError:
            get_shutdown_event().set()

    try:
        signal.signal(signal.SIGTERM, _handle_signal)
        signal.signal(signal.SIGINT, _handle_signal)
    except ValueError as e:
        logger.error("[Signal] Could not bind handlers (must run in MainThread): %s", e)


async def _cancel_gracefully(task_list: list[asyncio.Task], timeout: float = 10.0) -> None:
    """Cancel tasks with a grace period before forcing."""
    if not task_list:
        return

    for t in task_list:
        if not t.done():
            t.cancel()

    # asyncio.wait respects timeout; gather does not
    done, pending = await asyncio.wait(task_list, timeout=timeout)

    for t in done:
        exc = t.exception()
        if isinstance(exc, asyncio.CancelledError):
            logger.debug("[Shutdown] Task '%s' cancelled gracefully.", t.get_name())
        elif isinstance(exc, Exception):
            logger.warning("[Shutdown] Task '%s' raised during shutdown: %s", t.get_name(), exc)

    if pending:
        logger.warning("[Shutdown] %d tasks did not finish in %fs, forcing...", len(pending), timeout)
        for t in pending:
            t.cancel()
        # One-second hail mary for stragglers
        await asyncio.wait(pending, timeout=1.0)
