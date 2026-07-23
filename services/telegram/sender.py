# services/telegram/sender.py
"""All outgoing Telegram sends — UNIVERSAL Token Bucket protection."""

import asyncio
import logging
import re
from pathlib import Path
from typing import Any, Optional

from aiogram.exceptions import TelegramRetryAfter
from aiogram.types import FSInputFile, Message

from services.telegram.formatting import chunk_text, markdown_to_entities
from services.thinking_parser import strip_thinking_content

from .cooldown import ErrorCooldown

logger = logging.getLogger(__name__)

_FILE_EXPORT_RE = re.compile(r"\[FILE_EXPORT:\s*(.*?)\]")
# Detect URLs (http/https) in message text to suppress link previews globally.
_URL_RE = re.compile(r"https?://", re.IGNORECASE)


def _has_url(text: str) -> bool:
    """True if text contains an http(s):// link (triggers preview suppression)."""
    return bool(_URL_RE.search(text))


async def send_response(
    message: Message,
    text: str,
    cfg,
    limiter,
    reply_markup: Any | None = None,
) -> None:
    """Send response with chunking, entity conversion, and FILE_EXPORT support.

    ALL outgoing messages pass through the GlobalOutboxLimiter.
    """
    if not text:
        return

    export_paths: list[str] = []

    def _capture(m: "re.Match[str]") -> str:
        export_paths.append(m.group(1).strip())
        return ""

    text = _FILE_EXPORT_RE.sub(_capture, text).strip()
    text = strip_thinking_content(text)
    chunks = chunk_text(text, cfg.text_chunk_limit, cfg.chunk_mode)

    for i, chunk in enumerate(chunks):
        try:
            plain, entities = markdown_to_entities(chunk)
            kwargs: dict[str, Any] = {"text": plain, "entities": entities}
            if i == 0:
                kwargs["reply_to_message_id"] = (
                    message.reply_to_message.message_id if message.reply_to_message else message.message_id
                )
            if reply_markup and i == len(chunks) - 1:
                kwargs["reply_markup"] = reply_markup
            if _has_url(chunk):
                kwargs["disable_web_page_preview"] = True
            await limiter.acquire(tokens=1)
            await message.answer(**kwargs)
        except Exception as e:
            logger.error("[Telegram] Send failed: %s", e)

    for fp in export_paths:
        try:
            p = Path(fp)
            if p.is_file():
                await limiter.acquire(tokens=1)
                await message.answer_document(FSInputFile(str(p)))
            else:
                logger.warning("[Telegram] FILE_EXPORT path not found: %s", fp)
                await limiter.acquire(tokens=1)
                await message.answer(f"⚠️ קובץ פלט לא נמצא: {fp}")
        except Exception as e:
            logger.error("[Telegram] Failed to send document %s: %s", fp, e)


async def send_error(
    message: Message,
    error_text: str,
    cfg,
    error_cooldown: ErrorCooldown,
    limiter,
) -> None:
    """Send error with cooldown, policy check, and rate limiting."""
    from services.channels_config import ErrorPolicy

    chat_id = message.chat.id
    error_policy = cfg.error_policy
    sid = str(chat_id)
    if sid in cfg.groups and cfg.groups[sid].error_policy:
        error_policy = cfg.groups[sid].error_policy or error_policy

    if error_policy == ErrorPolicy.SILENT:
        return

    cooldown = cfg.error_cooldown_ms
    if sid in cfg.groups and cfg.groups[sid].error_cooldown_ms is not None:
        cooldown = cfg.groups[sid].error_cooldown_ms

    if not error_cooldown.can_send(chat_id, cooldown):
        return

    try:
        await limiter.acquire(tokens=1)
        await message.answer(f"⚠️ {error_text}")
    except Exception as e:
        logger.error("[Telegram] Failed to send error: %s", e)


async def send_message(
    bot,
    chat_id: int | str,
    text: str,
    cfg,
    limiter,
    reply_to: int | None = None,
    reply_markup: Any | None = None,
) -> bool:
    """Public API: send message to specific chat with FloodWait retry."""
    if not bot:
        return False

    try:
        chunks = chunk_text(text, cfg.text_chunk_limit, cfg.chunk_mode)
        for i, chunk in enumerate(chunks):
            plain, entities = markdown_to_entities(chunk)
            kwargs: dict[str, Any] = {
                "chat_id": chat_id,
                "text": plain,
                "entities": entities,
            }
            if i == 0 and reply_to:
                kwargs["reply_to_message_id"] = reply_to
            if reply_markup and i == len(chunks) - 1:
                kwargs["reply_markup"] = reply_markup
            if _has_url(chunk):
                kwargs["disable_web_page_preview"] = True

            # Universal outbound throttle
            await limiter.acquire(tokens=1)

            _max_attempts = 3
            for _attempt in range(_max_attempts):
                try:
                    await bot.send_message(**kwargs)
                    break
                except TelegramRetryAfter as exc:
                    _wait = float(exc.retry_after) + 0.5
                    logger.warning(
                        "[Telegram] 429 FloodWait chat=%s chunk=%d/%d — sleeping %.1fs (attempt %d/%d)",
                        chat_id,
                        i + 1,
                        len(chunks),
                        _wait,
                        _attempt + 1,
                        _max_attempts,
                    )
                    await asyncio.sleep(_wait)
            else:
                logger.error(
                    "[Telegram] Send failed after %d FloodWait retries (chat=%s chunk=%d/%d)",
                    _max_attempts,
                    chat_id,
                    i + 1,
                    len(chunks),
                )
                return False
        return True
    except Exception as e:
        logger.error("[Telegram] Send failed: %s", e)
        return False
