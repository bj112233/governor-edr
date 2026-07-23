# services/telegram/singleton.py
"""Global TelegramChannel instance management."""

from typing import Optional

from services.channels_config import TelegramConfig

from .channel import TelegramChannel

_telegram_channel: TelegramChannel | None = None


def init_telegram_channel(config: TelegramConfig | None = None) -> TelegramChannel:
    """Initialize global Telegram channel."""
    global _telegram_channel
    _telegram_channel = TelegramChannel(config)
    return _telegram_channel


def get_telegram_channel() -> TelegramChannel | None:
    """Get global Telegram channel instance."""
    return _telegram_channel
