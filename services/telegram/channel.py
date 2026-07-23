# services/telegram/channel.py
"""TelegramChannel facade — orchestrates all Telegram subsystems."""

import asyncio
import logging
from typing import Optional

from aiogram import Bot, Dispatcher, Router
from aiogram.filters import Command

from config import TELEGRAM_BOT_TOKEN
from services.channels_config import TelegramConfig

from .cooldown import ErrorCooldown
from .ratelimit import GlobalOutboxLimiter, MessageRateLimiter, shared_outbox_limiter
from .routing import on_callback_query, on_message

logger = logging.getLogger(__name__)


class TelegramChannel:
    """Telegram Channel Service."""

    def __init__(
        self,
        config: TelegramConfig | None = None,
        outbox_limiter: GlobalOutboxLimiter | None = None,
    ) -> None:
        self.cfg = config or TelegramConfig()
        self.bot: Bot | None = None
        self.dp: Dispatcher | None = None
        self.router = Router()
        self._bot_username: str | None = None
        self._error_cooldown = ErrorCooldown(self.cfg.error_cooldown_ms)
        self._rate_limiter = MessageRateLimiter(max_messages=20, window_seconds=60.0)
        self._outbox_limiter = outbox_limiter or shared_outbox_limiter
        self._running = False
        self._stop_event = asyncio.Event()
        self._token: str | None = None

    @property
    def is_enabled(self) -> bool:
        return bool(self.cfg.enabled and (self.cfg.bot_token or TELEGRAM_BOT_TOKEN))

    def _get_token(self) -> str | None:
        return self.cfg.bot_token or TELEGRAM_BOT_TOKEN or None

    def setup_routes(self) -> None:
        """Setup message handlers."""
        from services.telegram.handlers import (
            cmd_help,
            cmd_intel,
            cmd_skills,
            cmd_start,
            cmd_stats,
            cmd_status,
            cmd_threatscan,
            make_arg_handler,
            make_intel_handler,
        )

        async def _handle_start(message) -> None:
            await cmd_start(self, message)

        self.router.message(Command("start"))(_handle_start)
        self.router.message(Command("help"))(cmd_help)
        self.router.message(Command("skills"))(cmd_skills)

        from services.telegram.commands import INTEL_COMMANDS, INTEL_COMMANDS_WITH_ARGS

        for slash, (tool_name, title) in INTEL_COMMANDS.items():
            self.router.message(Command(slash))(make_intel_handler(self, tool_name, title))
        for slash, (tool_name, title, arg_key, default) in INTEL_COMMANDS_WITH_ARGS.items():
            if slash == "intel":
                continue
            self.router.message(Command(slash))(make_arg_handler(self, tool_name, title, arg_key, default))

        self.router.message(Command("status"))(cmd_status)
        self.router.message(Command("intel"))(cmd_intel)
        self.router.message(Command("stats"))(cmd_stats)
        self.router.message(Command("threatscan"))(cmd_threatscan)
        self.router.message()(self._on_message)
        self.router.callback_query()(self._on_callback_query)

        from services.telegram.hitl_handler import router as hitl_router

        if self.dp is not None:
            self.dp.include_router(hitl_router)

    async def start(self) -> None:
        """Start the Telegram bot."""
        from .polling import start_polling

        await start_polling(self)

    async def stop(self) -> None:
        """Stop the bot."""
        from .polling import stop_polling

        await stop_polling(self)

    async def send_message(self, chat_id, text, reply_to=None, reply_markup=None) -> bool:
        """Send message to specific chat."""
        from .sender import send_message

        return await send_message(
            self.bot,
            chat_id,
            text,
            self.cfg,
            self._outbox_limiter,
            reply_to=reply_to,
            reply_markup=reply_markup,
        )

    async def send_error(self, message, error_text) -> None:
        """Send error with cooldown and policy check."""
        from .sender import send_error

        await send_error(message, error_text, self.cfg, self._error_cooldown, self._outbox_limiter)

    async def _send_response(self, message, text) -> None:
        """Send response with chunking."""
        from .sender import send_response

        await send_response(message, text, self.cfg, self._outbox_limiter)

    async def _on_message(self, message) -> None:
        """Main message handler — delegates to routing module."""
        # Get state from dispatcher data (aiogram injects it)
        from aiogram.fsm.context import FSMContext

        # aiogram passes state via middleware; for bound methods we need to extract it
        # Using a simple approach: the handler is called with message only by aiogram
        # when it's a bound method without state parameter
        await on_message(message, None, self)

    async def _on_callback_query(self, callback) -> None:
        """Callback query handler — delegates to routing module."""
        await on_callback_query(callback, self)

    # --- Helper methods for handlers ---

    def is_dm_allowed(self, user_id: int) -> bool:
        from .permissions import is_dm_allowed

        return is_dm_allowed(user_id, self.cfg)

    async def is_group_allowed(self, chat_id: int, user_id: int) -> bool:
        from .permissions import is_group_allowed

        return await is_group_allowed(chat_id, user_id, self.cfg)

    async def list_pending_pairings(self) -> list:
        """Return pending pairings (delegates to config)."""
        return getattr(self.cfg, "pending_pairings", None) or []

    async def approve_pairing(self, code: str) -> str:
        """Approve a pairing code."""
        approve = getattr(self.cfg, "approve_pairing", None)
        if approve:
            return approve(code)
        return "Pairing not configured"
