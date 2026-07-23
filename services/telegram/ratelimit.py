# services/telegram/ratelimit.py
"""Per-user rate limiter for Telegram messages (sliding window)."""

import asyncio
import time


class GlobalOutboxLimiter:
    """Token bucket: 25 msgs/sec global (safe headroom under Telegram 30/sec)."""

    def __init__(self, rate: float = 25.0, per: float = 1.0):
        self._rate = rate
        self._per = per
        self._allowance = rate
        self._last_check = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> float:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_check
            self._allowance = min(self._rate, self._allowance + elapsed * (self._rate / self._per))
            self._last_check = now
            if self._allowance < tokens:
                wait = (tokens - self._allowance) * (self._per / self._rate)
                await asyncio.sleep(wait)
                self._allowance = 0.0
            else:
                self._allowance -= tokens
            return 0.0


class MessageRateLimiter:
    """
    Sliding-window rate limiter: N messages per window_seconds per user_id.
    Default: 5 messages per 60 seconds.
    """

    def __init__(self, max_messages: int = 5, window_seconds: float = 60.0):
        self._max = max_messages
        self._window = window_seconds
        self._store: dict[int, list[float]] = {}

    def can_send(self, user_id: int) -> bool:
        """Return True if user is within rate limit."""
        now = time.time()
        # cleanup stale users (double window)
        cutoff_clean = now - (self._window * 2)
        for uid in list(self._store):
            self._store[uid] = [t for t in self._store[uid] if t > cutoff_clean]
            if not self._store[uid]:
                del self._store[uid]
        cutoff = now - self._window
        timestamps = self._store.get(user_id, [])
        # Drop old entries
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= self._max:
            self._store[user_id] = timestamps
            return False
        timestamps.append(now)
        self._store[user_id] = timestamps
        return True

    def get_remaining(self, user_id: int) -> int:
        """Return remaining messages in current window."""
        now = time.time()
        cutoff = now - self._window
        timestamps = self._store.get(user_id, [])
        timestamps = [t for t in timestamps if t > cutoff]
        return max(0, self._max - len(timestamps))


# Process-wide singleton: created once at import time (module-level init).
# Shared by all TelegramChannel instances via dependency injection.
shared_outbox_limiter = GlobalOutboxLimiter(rate=25.0, per=1.0)
