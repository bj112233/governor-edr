# services/github_rate_limiter.py
"""GitHub API rate limiter — dual-layer protection against abuse detection.

Layer 1: Token bucket — max N requests per 60s window.
Layer 2: Min interval — enforce gap between consecutive requests
         (prevents Secondary Rate Limit from concurrent bursts).

Asyncio.Lock-protected to prevent race conditions when multiple tools
fire GitHub searches concurrently. Zero-blocking — uses asyncio.sleep,
never time.sleep.
"""

import asyncio
import logging
import time

from config import GITHUB_SEARCH_MIN_INTERVAL, GITHUB_SEARCH_RATE_LIMIT, GITHUB_SEARCH_RATE_WINDOW

logger = logging.getLogger(__name__)


class GitHubRateLimiter:
    """Dual-layer rate limiter for GitHub Code Search API."""

    def __init__(self, max_calls: int, window: float, min_interval: float) -> None:
        self._max_calls = max_calls
        self._window = window
        self._min_interval = min_interval
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a request slot is available. Never raises."""
        async with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < self._window]

            # Layer 1: rate limit
            if len(self._timestamps) >= self._max_calls:
                sleep_time = self._window - (now - self._timestamps[0])
                if sleep_time > 0:
                    logger.warning(
                        "[GitHub] API rate limit (%d/%.0fs) — throttling %.1fs",
                        self._max_calls,
                        self._window,
                        sleep_time,
                    )
                    await asyncio.sleep(sleep_time)
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._window]

            # Layer 2: min interval (anti-abuse)
            if self._timestamps:
                elapsed = now - self._timestamps[-1]
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)
                    now = time.monotonic()

            self._timestamps.append(now)


# Singleton — shared across all GitHub API calls
github_limiter = GitHubRateLimiter(
    max_calls=GITHUB_SEARCH_RATE_LIMIT,
    window=GITHUB_SEARCH_RATE_WINDOW,
    min_interval=GITHUB_SEARCH_MIN_INTERVAL,
)
