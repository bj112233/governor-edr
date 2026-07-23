# services/telegram/routing.py
"""Message routing — DM handlers, group handlers, main on_message."""

import logging

from aiogram.enums import ChatType
from aiogram.types import CallbackQuery, Message

from services.telegram.processing import process_message

from . import permissions, sender, typing

logger = logging.getLogger(__name__)

# HITL prompt marker — matches _executor_phases.py HITL message prefix.
_HITL_MARKER = "⚠️ **דרוש אישור מפעיל**"


def _hitl_keyboard_if_needed(response: str):
    """Attach approve/reject InlineKeyboard when response is a HITL prompt."""
    if not response or _HITL_MARKER not in response:
        return None
    from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ אשר", callback_data="hitl_approve"),
                InlineKeyboardButton(text="❌ דחה", callback_data="hitl_reject"),
            ]
        ]
    )


async def handle_dm(message: Message, state, channel) -> None:
    """Handle direct message."""
    user = message.from_user
    if not user:
        return
    allowed = permissions.is_dm_allowed(user.id, channel.cfg)
    if not allowed:
        await sender.send_error(
            message,
            "אין הרשאה לשלוח הודעות ישירות.",
            channel.cfg,
            channel._error_cooldown,
            channel._outbox_limiter,
        )
        return
    response = await typing.with_typing(message, process_message(channel, message, state))
    if response:
        await sender.send_response(
            message,
            response,
            channel.cfg,
            channel._outbox_limiter,
            reply_markup=_hitl_keyboard_if_needed(response),
        )


async def handle_group(message: Message, state, channel) -> None:
    """Handle group message."""
    user = message.from_user
    chat = message.chat
    if not user or not chat:
        return
    if permissions.should_require_mention(chat.id, channel.cfg.groups) and not permissions.is_mentioned(
        message, channel._bot_username, channel.bot.id if channel.bot else None
    ):
        return
    allowed = await permissions.is_group_allowed(chat.id, user.id, channel.cfg)
    if not allowed:
        logger.debug("[Telegram] User %d not allowed in group %d", user.id, chat.id)
        return
    response = await typing.with_typing(message, process_message(channel, message, state))
    if response:
        await sender.send_response(
            message,
            response,
            channel.cfg,
            channel._outbox_limiter,
            reply_markup=_hitl_keyboard_if_needed(response),
        )


async def on_message(message: Message, state, channel) -> None:
    """Main message handler — supports text, caption, and file attachments."""
    user = message.from_user
    if user:
        if not channel._rate_limiter.can_send(user.id):
            logger.warning("[Telegram] Rate limit hit for user %d", user.id)
            return

    text = message.text or message.caption or ""
    if text.startswith("/") and "/" not in text.split()[0][1:] and not message.document and not message.photo:
        return

    if message.chat.type == ChatType.PRIVATE:
        await handle_dm(message, state, channel)
    else:
        await handle_group(message, state, channel)


async def on_callback_query(callback: CallbackQuery, channel) -> None:
    from services.telegram.callbacks import handle_callback_query

    await handle_callback_query(callback, channel.bot)
