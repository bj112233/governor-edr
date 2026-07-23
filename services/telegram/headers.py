# services/telegram/headers.py
"""SSOT for Telegram message headers + safe send (replaces parse_mode=None).

Every Telegram message that contains user-derived data (file paths, PIDs,
process names, IPs) MUST pass through safe_answer() — never message.answer()
with parse_mode=None. The latter silently drops formatting AND bypasses the
html.escape protection in strip_markdown(), exposing the bot to
BadRequest: can't parse entities if a future refactor adds parse_mode.

Architecture:
  - format_header(): unified header builder (replaces 9 divergent patterns)
  - safe_answer(): message.answer() wrapper that always routes through
    markdown_to_entities() — zero parse_mode=None in the codebase.
"""

import logging
from typing import Any

from aiogram.types import Message

from services.telegram.formatting import chunk_text, markdown_to_entities

logger = logging.getLogger(__name__)

# Standard separator — single visual width, renders consistently across
# Telegram clients (Markdown/HTML/plain). 25 chars matches the widest
# existing header (alert_dispatcher uses 22, reports use 29 — 25 is the
# median and the new standard).
SEPARATOR = "━" * 25


def format_header(emoji: str, title: str, subtitle: str | None = None) -> str:
    """Build a unified message header.

    Args:
        emoji: Leading emoji (e.g. "🛡️", "📅", "🧠").
        title: Header title (e.g. "CTI SITREP").
        subtitle: Optional second line (e.g. date or category).

    Returns:
        Formatted header string ending with a separator line + newline.
        All text is returned as-is (no Markdown) — the caller passes the
        full message through markdown_to_entities() which html-escapes
        user content before sending.
    """
    lines = [f"{emoji} {title}"]
    if subtitle:
        lines.append(subtitle)
    lines.append(SEPARATOR)
    return "\n".join(lines) + "\n"


async def safe_answer(
    message: Message,
    text: str,
    *,
    chunk_limit: int = 3800,
    reply_markup: Any | None = None,
) -> None:
    """Send text via markdown_to_entities — zero parse_mode=None.

    Drop-in replacement for:
        await message.answer(chunk, parse_mode=None)

    Routes every chunk through strip_markdown() → html.escape() →
    html_to_entities(), so user-derived special chars (_, *, [, <, &)
    are escaped before reaching the Telegram API. This prevents
    BadRequest: can't parse entities on threat alerts containing
    file paths like C:\\Users\\foo_bar or PIDs with underscores.

    Args:
        message: aiogram Message to answer.
        text: Raw text (may contain Markdown — will be converted).
        chunk_limit: Max chars per chunk (Telegram hard cap is 4096).
        reply_markup: Optional InlineKeyboard attached to last chunk.
    """
    if not text:
        return
    chunks = chunk_text(text, limit=chunk_limit, mode="newline")
    for i, chunk in enumerate(chunks):
        try:
            plain, entities = markdown_to_entities(chunk)
            kwargs: dict[str, Any] = {"text": plain, "entities": entities}
            if reply_markup and i == len(chunks) - 1:
                kwargs["reply_markup"] = reply_markup
            await message.answer(**kwargs)
        except Exception as exc:
            logger.error("[headers] safe_answer failed on chunk %d: %s", i, exc)
            # Last-resort fallback: plain text, no entities, no parse_mode.
            # This guarantees delivery even if entity conversion crashes.
            try:
                await message.answer(chunk)
            except Exception:
                logger.error("[headers] plain fallback also failed — message lost")
