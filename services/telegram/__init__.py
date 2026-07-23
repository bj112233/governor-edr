# services/telegram/__init__.py
"""Telegram channel sub-package — rate limiting, FSM states, channel facade."""

# Backward compat: channel facade + singleton helpers
from services.telegram.channel import TelegramChannel
from services.telegram.fsm_states import ExecApproval
from services.telegram.ratelimit import MessageRateLimiter
from services.telegram.singleton import get_telegram_channel, init_telegram_channel

__all__ = [
    "MessageRateLimiter",
    "ExecApproval",
    "TelegramChannel",
    "get_telegram_channel",
    "init_telegram_channel",
]
