# services/telegram/cooldown.py
"""Error reply cooldown tracker per chat."""

from datetime import UTC, datetime, timedelta
from typing import Optional


class ErrorCooldown:
    """Track error reply cooldowns per chat."""

    def __init__(self, default_ms: int = 60000):
        self._last_error: dict[int | str, datetime] = {}
        self._default_ms = default_ms

    def can_send(self, chat_id: int | str, cooldown_ms: int | None = None) -> bool:
        now = datetime.now(UTC)
        last = self._last_error.get(chat_id)
        cooldown = timedelta(milliseconds=cooldown_ms or self._default_ms)
        if last is None or now - last > cooldown:
            self._last_error[chat_id] = now
            return True
        return False
