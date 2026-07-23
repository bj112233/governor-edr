# services/telegram/handlers.py
"""Telegram slash-command handlers (extracted from TelegramChannel)."""

import asyncio
import logging
import re
from typing import TYPE_CHECKING, Any

from aiogram.enums import ChatType
from aiogram.types import Message
from aiogram.utils.formatting import Bold, Code, Text

from services.alert_history import (
    async_save_audit_log,
    get_latest_intel_alerts,
    get_latest_system_metrics,
)
from services.bot_memory import recall_context
from services.skills_engine import get_skills_engine
from services.telegram.commands import (
    _MCP_URL,
    INTEL_COMMANDS,
    INTEL_COMMANDS_WITH_ARGS,
)
from services.telegram.formatting import chunk_text
from services.telegram.handlers_render import (
    build_skill_meta,
    render_skill_categories,
    render_threat_row,
)
from services.telegram.headers import safe_answer
from services.telegram.mcp_bridge import call_mcp

if TYPE_CHECKING:
    from services.telegram import TelegramChannel

logger = logging.getLogger(__name__)


async def cmd_start(channel: "TelegramChannel", message: Message) -> None:
    """Handle /start command — reset conversation context."""
    user = message.from_user
    if not user:
        return

    # SECURITY: permission check BEFORE any destructive operation
    if message.chat.type == ChatType.PRIVATE:
        allowed = channel.is_dm_allowed(user.id)
        if not allowed:
            await channel.send_error(message, "אין הרשאה לשלוח הודעות ישירות.")
            return

    # Clear active conversation context (FSM state), NOT long-term memory.
    # Long-term recall (memories table) must persist across sessions.
    # clear_conversation_memory() was archiving ALL memories on every /start —
    # effectively giving the agent amnesia. Removed.

    try:
        from services.agent.context import clear_last_document

        clear_last_document()
        logger.info("[Telegram] Cleared last_document on /start")
    except Exception as e:
        logger.warning("[Telegram] Failed to clear last_document on /start: %s", e)

    if message.chat.type == ChatType.PRIVATE:
        await message.answer("👋 שלום! אני Claw 🐾\nשלח לי הודעה ואענה לך.")


async def cmd_skills(message: Message) -> None:
    """Handle /skills command — show dynamically loaded skills (2026 format)."""
    engine = get_skills_engine()
    skill_meta = build_skill_meta(engine)
    lines = render_skill_categories(engine, skill_meta)
    text = "\n".join(lines)
    await safe_answer(message, text)


async def cmd_help(message: Message) -> None:
    """Handle /help command with synced command registry."""
    basic_commands = [
        "/start — 🚀 התחלת שיחה + איפוס זיכרון",
        "/help — 📋 תפריט זה",
        "/skills — 🛠️ Skills זמינים + דוגמאות שימוש",
        "/status — 📊 סטטוס מערכת (CPU/RAM/Z-Scores)",
        "/intel — 🚨 איומים אחרונות (24 שעות)",
        "/stats — 📈 טלמטריה (LLM calls, tools latency)",
        "/threatscan — 🛡️ ציד איומים מערכתי (TTP Override + LLM)",
    ]

    system_lines = [f"/{cmd} — {title}" for cmd, (_, title) in INTEL_COMMANDS.items()]

    arg_lines = [
        f"/{cmd} — {title} (<{arg_key}>)"
        for cmd, (_, title, arg_key, _) in INTEL_COMMANDS_WITH_ARGS.items()
        if cmd != "intel"  # Overridden by native cmd_intel handler
    ]

    parts: list[Any] = [
        "🤖 ",
        Bold("Claw 🐾 — תפריט פקודות"),
        "\n\n",
        Bold("── כללי ──"),
        "\n",
    ]
    for line in basic_commands:
        parts.extend([f"• {line}\n"])

    parts.extend(["\n", Bold("── ניטור מערכת ──"), "\n"])
    for line in system_lines:
        parts.extend([f"• {line}\n"])

    parts.extend(["\n", Bold("── כלים עם ארגומנט ──"), "\n"])
    for line in arg_lines:
        parts.extend([f"• {line}\n"])

    parts.extend(
        [
            "\n",
            Bold("── סקילים (שיחה טבעית) ──"),
            "\n",
            "מזג אוויר, שערי מטבע, מניות, תרגום, ניווט, חדשות,\n",
            "ניתוח קבצים, גרידת אתרים, חומת אש, מודיעין, הצפנה — פשוט בקש בעברית.\n",
            "ראה ",
            Code("/skills"),
            " לדוגמאות.",
        ]
    )

    content = Text(*parts)
    await message.answer(**content.as_kwargs())


def make_intel_handler(channel: "TelegramChannel", tool_name: str, title: str):
    """Factory that creates a Telegram command handler for an MCP tool."""

    async def handler(message: Message) -> None:
        user = message.from_user
        if not user or not channel.is_dm_allowed(user.id):
            return
        await message.answer(f"{title} — טוען…")
        text = await call_mcp(_MCP_URL, tool_name)
        await async_save_audit_log(
            tool=f"telegram_intel/{tool_name}",
            args=f"user_id={user.id}",
            result=text[:500],
            client_ip="telegram",
            duration_ms=0,
        )
        await channel._send_response(message, f"**{title}**\n\n{text}")

    return handler


def make_arg_handler(
    channel: "TelegramChannel",
    tool_name: str,
    title: str,
    arg_key: str,
    default: str = "",
):
    """Factory for slash commands that accept text after the command."""

    async def handler(message: Message) -> None:
        user = message.from_user
        if not user or not channel.is_dm_allowed(user.id):
            return

        # Parse argument from message text
        text = message.text or ""
        parts = text.split(maxsplit=1)
        arg_value = parts[1].strip() if len(parts) > 1 else default

        # Special handling for empty required args
        if not arg_value and default == "":
            await message.answer(f"❌ נדרש ארגומנט ל-{title}. דוגמה: /{parts[0][1:]} <{arg_key}>")
            return

        # Build arguments dict
        arguments: dict[str, Any] = {}
        if tool_name == "terminate_process":
            try:
                arguments = {"pid": int(arg_value)}
            except ValueError:
                await message.answer("❌ PID חייב להיות מספר שלם.")
                return
        elif tool_name == "read_file":
            arguments = {"path": arg_value, "max_lines": 100}
        else:
            arguments = {arg_key: arg_value}

        await message.answer(f"{title} — טוען…")
        text = await call_mcp(_MCP_URL, tool_name, arguments)
        await async_save_audit_log(
            tool=f"telegram_intel/{tool_name}",
            args=f"user_id={user.id} {arg_key}={arg_value}",
            result=text[:500],
            client_ip="telegram",
            duration_ms=0,
        )
        await channel._send_response(message, f"**{title}**\n\n{text}")

    return handler


# Diagnostic commands extracted to handlers_diag.py (SRP)
from services.telegram.handlers_diag import (  # noqa: E402,F401
    cmd_intel,
    cmd_stats,
    cmd_status,
    cmd_threatscan,
)
