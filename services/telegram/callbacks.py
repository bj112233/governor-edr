# services/telegram/callbacks.py
"""Callback query handler for Sentinel remediation inline keyboards.

Uses ACTIVE_ALERTS_CACHE (from alert_dispatcher) to retrieve full context
without exceeding Telegram's 64-byte callback_data limit.
"""

import asyncio
import logging
from typing import Optional

from aiogram import Bot
from aiogram.types import CallbackQuery

from services.alert_dispatcher import ACTIVE_ALERTS_CACHE
from services.net_baseline import add_to_baseline
from services.remediation_engine import block_ip_in_firewall, kill_process

logger = logging.getLogger(__name__)

_BLOCK_PREFIX = "rem_blk_"
_KILL_PREFIX = "rem_kil_"
_IGNORE_PREFIX = "rem_ign_"
_AUTO_BLOCK_PREFIX = "rem_ablk_"
_AUTO_KILL_PREFIX = "rem_akil_"


def _resolve_alert_context(data: str) -> tuple[str, dict | None]:
    """Resolve callback_data → (alert_id, cached_context).

    Returns ("", None) for unknown prefixes. Pops the alert from the cache;
    logs + returns ("", <sentinel>) when the alert expired (caller short-circuits).
    """
    if data.startswith(_BLOCK_PREFIX):
        alert_id = data[len(_BLOCK_PREFIX) :]
    elif data.startswith(_KILL_PREFIX):
        alert_id = data[len(_KILL_PREFIX) :]
    elif data.startswith(_IGNORE_PREFIX):
        alert_id = data[len(_IGNORE_PREFIX) :]
    elif data.startswith(_AUTO_BLOCK_PREFIX):
        # Auto-block: callback_data is the pending_actions row ID
        row_id = data[len(_AUTO_BLOCK_PREFIX) :]
        return f"ablk_{row_id}", {"_auto_block_id": int(row_id) if row_id.isdigit() else 0}
    elif data.startswith(_AUTO_KILL_PREFIX):
        # Auto-kill: callback_data is the pending_actions row ID
        row_id = data[len(_AUTO_KILL_PREFIX) :]
        return f"akil_{row_id}", {"_auto_kill_id": int(row_id) if row_id.isdigit() else 0}
    else:
        return "", None

    if data.startswith(_AUTO_BLOCK_PREFIX) or data.startswith(_AUTO_KILL_PREFIX):
        return "", None  # handled above

    cached = ACTIVE_ALERTS_CACHE.pop(alert_id, None)
    if not cached:
        logger.warning("[Callback] Alert ID '%s' expired or unknown. Ignoring.", alert_id)
    return alert_id, cached


async def _execute_remediation_action(data: str, cached: dict | None) -> tuple[bool, str, str]:
    """Execute the remediation action (block/kill/ignore).

    Returns (ok, detail_msg, result_text).
    """
    ip = cached.get("ip") if cached else None
    port = cached.get("port", 0) if cached else 0
    proc_name = cached.get("proc_name", "unknown") if cached else "unknown"

    if data.startswith(_AUTO_BLOCK_PREFIX):
        return await _handle_auto_block(cached)
    if data.startswith(_AUTO_KILL_PREFIX):
        return await _handle_auto_kill(cached)
    if data.startswith(_BLOCK_PREFIX):
        if not ip:
            return False, "", "NO_IP"
        ok, detail_msg = await asyncio.to_thread(block_ip_in_firewall, ip)
        return ok, detail_msg, f"🚨 NEUTRALIZED 🚨\n\n🔴 Block IP {ip}:\n{detail_msg}"
    if data.startswith(_KILL_PREFIX):
        ok, detail_msg = await asyncio.to_thread(kill_process, None, proc_name)
        return ok, detail_msg, f"🚨 NEUTRALIZED 🚨\n\n💀 Kill {proc_name}:\n{detail_msg}"

    # ignore branch
    ok = True
    detail_msg = "Ignored by user."
    result_text = "🟢 התראה הושתקה. למדתי את הצימוד הזה כבטוח."

    # ── CLOSED-LOOP LEARNING: reject pending auto-kill/auto-block actions ──
    auto_kill_id = cached.get("_auto_kill_id", 0) if cached else 0
    auto_block_id = cached.get("_auto_block_id", 0) if cached else 0
    if auto_kill_id or auto_block_id:
        await _reject_and_learn(auto_kill_id, auto_block_id)

    # ── LEARN: teach the system this combo is benign ──
    if ip and port and proc_name:
        try:
            await add_to_baseline(proc_name, ip, port)
            logger.info(
                "[Callback] Learned benign combo from user dismissal: %s -> %s:%d",
                proc_name,
                ip,
                port,
            )
        except Exception as exc:
            logger.error("[Callback] Failed to learn baseline: %s", exc)
    else:
        logger.warning(
            "[Callback] Cannot learn: missing context (ip=%s, port=%s, proc=%s)",
            ip,
            port,
            proc_name,
        )
    return ok, detail_msg, result_text


def _is_degraded_mode() -> bool:
    """Check if the agent is in DEGRADED mode (Critic offline).

    Queries the LLMBridge circuit breaker. Returns False on any error
    (fail-safe: don't block remediation on a bridge query failure).
    """
    try:
        from services.llm_bridge.bridge import LLMBridge

        return LLMBridge.get_instance().is_degraded()
    except Exception:
        return False


async def _handle_auto_block(cached: dict | None) -> tuple[bool, str, str]:
    """Auto-block: fetch IP from pending_actions DB, then execute."""
    row_id = cached.get("_auto_block_id", 0) if cached else 0
    if not row_id:
        return False, "", "❌ Invalid auto-block ID"
    try:
        from services.pending_actions import get_action, update_status

        action = await get_action(row_id)
        if not action:
            return False, "", "❌ Auto-block action not found"
        if action["status"] != "PENDING_APPROVAL":
            return False, "", f"❌ Action already {action['status']}"

        if _is_degraded_mode():
            await update_status(row_id, "FAILED")
            logger.warning("[Callback] Auto-block refused: DEGRADED mode (Critic offline).")
            return (
                False,
                "DEGRADED mode — Critic offline",
                "⛔ BLOCKED: DEGRADED mode — Critic offline, destructive actions refused.",
            )

        auto_ip = action["target"]
        ok, detail_msg = await asyncio.to_thread(block_ip_in_firewall, auto_ip)
        await update_status(row_id, "APPROVED" if ok else "FAILED")
        return ok, detail_msg, f"🚨 AUTO-BLOCK APPROVED 🚨\n\n🔴 Block IP {auto_ip}:\n{detail_msg}"
    except Exception as exc:
        logger.error("[Callback] Auto-block failed: %s", exc)
        return False, str(exc), f"❌ Auto-block failed: {exc}"


async def _handle_auto_kill(cached: dict | None) -> tuple[bool, str, str]:
    """Auto-kill: fetch composite target from pending_actions DB, verify, then execute."""
    row_id = cached.get("_auto_kill_id", 0) if cached else 0
    if not row_id:
        return False, "", "❌ Invalid auto-kill ID"
    try:
        from services.pending_actions import get_action, update_status

        action = await get_action(row_id)
        if not action:
            return False, "", "❌ Auto-kill action not found"
        if action["status"] != "PENDING_APPROVAL":
            return False, "", f"❌ Action already {action['status']}"

        target = action["target"]
        if "|" not in target:
            await update_status(row_id, "ABORTED")
            return False, "", f"❌ Unsafe target format (no name guard): {target}"

        pid_str, expected_name = target.split("|", 1)
        pid = int(pid_str) if pid_str.isdigit() else 0
        if not pid:
            await update_status(row_id, "ABORTED")
            return False, "", f"❌ Invalid PID: {pid_str}"

        if _is_degraded_mode():
            await update_status(row_id, "FAILED")
            logger.warning("[Callback] Auto-kill refused: DEGRADED mode (Critic offline).")
            return (
                False,
                "DEGRADED mode — Critic offline",
                "⛔ BLOCKED: DEGRADED mode — Critic offline, destructive actions refused.",
            )

        import psutil

        try:
            proc = psutil.Process(pid)
            actual_name = proc.name()
            if actual_name.lower() != expected_name.lower():
                await update_status(row_id, "ABORTED")
                logger.warning(
                    "[Callback] PID RECYCLING detected: PID %d is now '%s', expected '%s'. Aborting kill.",
                    pid,
                    actual_name,
                    expected_name,
                )
                return (
                    False,
                    "",
                    (
                        f"⛔ PID RECYCLING ABORT\n\n"
                        f"PID {pid} was '{expected_name}' but is now '{actual_name}'.\n"
                        f"Kill aborted to prevent collateral damage."
                    ),
                )
        except psutil.NoSuchProcess:
            await update_status(row_id, "ALREADY_DEAD")
            return True, "Process already terminated", f"ℹ️ PID {pid} ({expected_name}) already dead."

        ok, detail_msg = await asyncio.to_thread(kill_process, pid, expected_name)
        await update_status(row_id, "APPROVED" if ok else "FAILED")
        return ok, detail_msg, f"🚨 AUTO-KILL APPROVED 🚨\n\n💀 Kill {expected_name} (PID {pid}):\n{detail_msg}"
    except Exception as exc:
        logger.error("[Callback] Auto-kill failed: %s", exc)
        return False, str(exc), f"❌ Auto-kill failed: {exc}"


async def _reject_and_learn(auto_kill_id: int, auto_block_id: int) -> None:
    """Reject pending auto-kill/auto-block actions and store parameter-scoped lessons.

    Closed-loop learning: HITL rejection → error_lessons.db → search_lessons surfaces
    the lesson when the agent investigates the SAME target again.

    CRITICAL: tool_name is scoped to the target (e.g., "kill_process:svchost.exe"),
    NOT the bare tool name. This prevents Tool Starvation — the global kill_process
    rank stays at 100, but if the agent tries to kill svchost.exe again, the lesson
    surfaces via search_lessons (+20 bonus) and the trigger_context warns it.

    Exponential recovery is handled by _tool_ranker._decay_factor (7-day half-life).
    """
    try:
        from services.error_memory import store_lesson
        from services.pending_actions import get_action, update_status

        for row_id, action_type in [(auto_kill_id, "kill_process"), (auto_block_id, "block_ip")]:
            if not row_id:
                continue
            action = await get_action(row_id)
            if action and action["status"] == "PENDING_APPROVAL":
                await update_status(row_id, "REJECTED")
                target = action.get("target", "")
                threat_ctx = action.get("threat_context", "")

                # Extract parameter scope: process name from "pid|name", or IP from target
                if action_type == "kill_process" and "|" in target:
                    _, proc_name = target.split("|", 1)
                    scoped_target = proc_name
                else:
                    scoped_target = target

                # Parameter-scoped tool_name: "kill_process|svchost.exe" not "kill_process"
                # Delimiter: | (pipe) — illegal in Windows paths, absent in IPv6 addresses.
                # Prevents delimiter collision: ":" appears in IPv6 (2001:db8::1) and
                # Windows drive letters (C:\), which would break split(':', 1) parsing.
                scoped_tool = f"{action_type}|{scoped_target}"
                error_sig = f"hitl_rejected|{action_type}|{scoped_target}"
                trigger = f"User rejected auto-queued {action_type} for {scoped_target}. Context: {threat_ctx}"
                resolution = f"Do not auto-queue {action_type} on {scoped_target} — user assessed as benign."
                await store_lesson(error_sig, trigger, resolution, tool_name=scoped_tool)
                logger.info(
                    "[Callback] HITL rejection stored (parameter-scoped): %s:%s rejected (row=%d)",
                    action_type,
                    scoped_target,
                    row_id,
                )
    except Exception as exc:
        logger.error("[Callback] Failed to store HITL rejection lesson: %s", exc)


async def _edit_callback_message(
    bot: Bot, callback: CallbackQuery, chat_id: int, message_id: int, result_text: str
) -> bool:
    """Edit the original message to show the result. Returns True on success."""
    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=result_text,
            reply_markup=None,
        )
        return True
    except Exception as e:
        logger.error("[Callback] edit_message failed: %s", e)
        return False


def _is_known_action(data: str) -> bool:
    """True when data carries a recognized remediation prefix."""
    return (
        data.startswith(_BLOCK_PREFIX)
        or data.startswith(_KILL_PREFIX)
        or data.startswith(_IGNORE_PREFIX)
        or data.startswith(_AUTO_BLOCK_PREFIX)
        or data.startswith(_AUTO_KILL_PREFIX)
    )


async def handle_callback_query(callback: CallbackQuery, bot: Bot) -> None:
    data = callback.data or ""
    msg = callback.message
    if not msg:
        await callback.answer("No message context", show_alert=True)
        return

    if not _is_known_action(data):
        await callback.answer("Unknown action", show_alert=True)
        return

    chat_id = msg.chat.id
    message_id = msg.message_id

    # ── Resolve alert_id → full context from in-memory cache ──
    alert_id, cached = _resolve_alert_context(data)
    if alert_id and not cached:
        await callback.answer("Alert expired. Please ignore.", show_alert=True)
        return

    ok, detail_msg, result_text = await _execute_remediation_action(data, cached)
    if result_text == "NO_IP":
        await callback.answer("No IP in alert context", show_alert=True)
        return

    # Edit original message: remove buttons, show result
    if not await _edit_callback_message(bot, callback, chat_id, message_id, result_text):
        await callback.answer(f"Result: {detail_msg}", show_alert=True)
        return

    await callback.answer("✅ בוצע" if ok else "❌ נכשל", show_alert=not ok)
