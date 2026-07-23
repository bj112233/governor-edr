"""Telegram event broadcaster — forwards Sentinel events to admin. Leaf module."""

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Optional

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from config import TELEGRAM_CHAT_ID
from services.formatters import format_event_for_telegram
from services.sentinel_events import event_bus

if TYPE_CHECKING:
    from services.telegram import TelegramChannel

logger = logging.getLogger(__name__)

# Event types consumed only by the C2 dashboard / internal consumers.
# These must NOT be forwarded to Telegram — they are not user-facing and
# would leak raw dict repr via the formatter fallback.
_TELEGRAM_SKIP_TYPES: frozenset[str] = frozenset({"dag_update"})


def _build_action_buttons(actions: dict) -> list[InlineKeyboardButton]:
    """Build IP/PID block buttons from remediation actions."""
    btns: list[InlineKeyboardButton] = []
    ip = actions.get("ip")
    pid = actions.get("pid")
    alert_id = actions.get("alert_id", "")
    if ip:
        btns.append(InlineKeyboardButton(text="🔴 Block IP", callback_data=f"rem_blk_{alert_id}"))
    if pid:
        btns.append(InlineKeyboardButton(text="💀 Kill PID", callback_data=f"rem_kil_{alert_id}"))
    return btns


def _build_auto_buttons(rem: dict, btns: list[InlineKeyboardButton]) -> None:
    """Add auto-queued block/kill buttons if not already present."""
    auto_block = rem.get("auto_block_queued")
    if auto_block and not any(b.text.startswith("🔴") for b in btns):
        btns.append(InlineKeyboardButton(text="🔴 Approve Block", callback_data=f"rem_ablk_{auto_block}"))

    auto_kill = rem.get("kill_process_queued")
    if auto_kill and not any(b.text.startswith("💀") for b in btns):
        kill_pid = rem.get("kill_pid", "?")
        btns.append(InlineKeyboardButton(text=f"💀 Approve Kill PID:{kill_pid}", callback_data=f"rem_akil_{auto_kill}"))


def _build_alert_keyboard(event: Any) -> InlineKeyboardMarkup | None:
    """Build inline keyboard for alert events with remediation buttons."""
    rem = event.data.get("remediation") or {}
    if not isinstance(rem, dict):
        rem = {}
    actions = rem.get("actions")

    btns: list[InlineKeyboardButton] = []
    if actions:
        btns = _build_action_buttons(actions)

    _build_auto_buttons(rem, btns)

    if not btns:
        return None

    ignore_id = actions.get("alert_id", "") if actions else ""
    btns.append(InlineKeyboardButton(text="🟢 Ignore", callback_data=f"rem_ign_{ignore_id}"))
    return InlineKeyboardMarkup(inline_keyboard=[btns])


async def _wait_for_bot(tg: "TelegramChannel", timeout_s: int = 60) -> bool:
    """Wait up to timeout_s for bot to be ready. Returns True if ready."""
    for _ in range(timeout_s):
        if tg.bot is not None:
            return True
        await asyncio.sleep(1)
    return False


async def _forward_event(tg: "TelegramChannel", event, chat_id: str) -> None:
    """Format and send a single event to Telegram."""
    text = format_event_for_telegram(event)
    keyboard = _build_alert_keyboard(event) if event.event_type == "alert" else None
    ok = await tg.send_message(chat_id, text, reply_markup=keyboard)
    if ok:
        logger.info("[Broadcaster] Delivered %s (%s)", event.event_type, event.id)
    else:
        logger.error("[Broadcaster] Failed to deliver event %s to Telegram", event.id)


async def _telegram_event_broadcaster(tg: "TelegramChannel") -> None:
    """Consume events from event bus and forward to Telegram admin."""
    chat_id = TELEGRAM_CHAT_ID
    if not chat_id:
        logger.warning("[Broadcaster] TELEGRAM_CHAT_ID not set — events will not be forwarded.")
        return

    if not await _wait_for_bot(tg):
        logger.error("[Broadcaster] Telegram bot not ready after 60s — aborting.")
        return

    queue: asyncio.Queue | None = None
    try:
        queue = await event_bus.subscribe()
        logger.info("[Broadcaster] Subscribed to event bus → chat %s", chat_id)

        while True:
            event = await queue.get()
            if event.event_type in _TELEGRAM_SKIP_TYPES:
                logger.debug(
                    "[Broadcaster] Skipping %s (%s) — dashboard-only event type",
                    event.event_type,
                    event.id,
                )
                continue
            try:
                await _forward_event(tg, event, chat_id)
            except Exception as e:
                logger.error("[Broadcaster] Error forwarding event: %s", e, exc_info=True)
    finally:
        if queue is not None:
            await event_bus.unsubscribe(queue)
