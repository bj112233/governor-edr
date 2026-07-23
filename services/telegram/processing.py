# services/telegram/processing.py
"""Telegram message processing — file attachments, skill routing, agent calls."""

import logging
from typing import TYPE_CHECKING, Optional

from aiogram.fsm.context import FSMContext
from aiogram.types import Message

from services.agent import run_agent
from services.alert_history import async_save_audit_log
from services.telegram.processing_handlers import (
    download_attachment,
    route_attachment,
)

if TYPE_CHECKING:
    from services.telegram import TelegramChannel

logger = logging.getLogger(__name__)


async def _save_audit(user_id: int | None, query: str, result: str) -> None:
    """Save audit log entry for agent call."""
    await async_save_audit_log(
        tool="telegram_agent",
        args=f"user_id={user_id or 'unknown'}, query={query[:200]}",
        result=result[:500],
        client_ip="telegram",
        duration_ms=0,
    )


async def _handle_attachment(
    channel: "TelegramChannel",
    message: Message,
    state: FSMContext,
    text: str,
    prefix: str,
) -> tuple[str | None, str]:
    """Handle file attachment routing. Returns (early_result, enriched_text).

    If early_result is not None, caller should return it immediately.
    """
    attached_path = await download_attachment(channel, message)
    if not text and not attached_path:
        return None, ""  # signals "nothing to do" — caller checks

    enriched = text or ""
    if attached_path:
        result, enriched = await route_attachment(attached_path, enriched, prefix, state)
        if result is not None:
            return result, enriched

    if prefix:
        enriched = f"{prefix}\n{enriched}"
    return None, enriched


async def process_message(channel: "TelegramChannel", message: Message, state: FSMContext) -> str | None:
    """Process message through agent and return response."""
    text = message.text or message.caption or ""
    user = message.from_user
    if not user:
        return None

    from services.telegram.permissions import get_response_prefix

    prefix = get_response_prefix(message.chat.id, channel.cfg)

    early_result, enriched = await _handle_attachment(channel, message, state, text, prefix)
    if early_result is not None:
        return early_result
    if not enriched:
        return None

    try:
        response = await run_agent(enriched, state=state)
        await _save_audit(user.id if user else None, enriched, response or "")
        return response
    except Exception as e:
        logger.error("[Telegram] Agent error: %s", e)
        await _save_audit(user.id if user else None, enriched, f"ERROR: {str(e)}")
        return None
