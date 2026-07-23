"""MCP tool handlers — business logic isolated from MCP registry."""

import asyncio
import logging

from services.interfaces import get_message_gateway
from services.monitor_engine import get_system_snapshot
from services.os_module import kill_process_by_name
from services.pending_actions import clear_pending, get_pending
from services.sentinel_events import event_bus

logger = logging.getLogger(__name__)


async def approve_pending_action_tool() -> str:
    """Execute the pending action after user approval."""
    action = await get_pending()
    if action is None:
        return "אין פעולה ממתינה לאישור."
    await clear_pending()
    act_type = action.get("action", "")
    target = action.get("target", "")
    reason = action.get("reason", "")
    try:
        if act_type == "block_ip":
            from services.action_tools import block_ip

            result = await block_ip(target)
        elif act_type == "unblock_ip":
            from services.action_tools import unblock_ip

            result = await unblock_ip(target)
        elif act_type == "manage_service":
            from services.action_tools import manage_service

            result = await manage_service(target.get("action", ""), target.get("name", ""))
        elif act_type == "defender_scan":
            from services.action_tools import defender_scan

            result = await defender_scan()
        elif act_type == "terminate_process":
            from services.system_intel import terminate_process

            result = terminate_process(int(target))
        elif act_type == "kill_process":
            result = await kill_process_by_name(target)
        elif act_type == "run_powershell":
            from services.action_tools import _run_powershell_exec

            result = await _run_powershell_exec(target)
        elif act_type == "screenshot":
            from services.action_tools import _local_screenshot_exec

            result = await asyncio.to_thread(_local_screenshot_exec)
        else:
            return f"❌ סוג פעולה לא מוכר: {act_type}"
        return f"✅ פעולה בוצעה ({act_type} → {target})\nסיבה: {reason}\nתוצאה: {result}"
    except Exception as e:
        logger.error("[mcp_handlers] approve_pending_action_tool failed: %s", e)
        return f"❌ שגיאה בביצוע {act_type}: {e}"


async def deny_pending_action_tool() -> str:
    """Cancel the pending action."""
    action = await get_pending()
    if action is None:
        return "אין פעולה ממתינה לביטול."
    await clear_pending()
    return f"🚫 פעולה בוטלה: {action.get('action')} → {action.get('target')}"


async def sentinel_get_system_snapshot_full() -> str:
    """Get comprehensive system snapshot with formatted output."""
    try:
        snapshot = await get_system_snapshot()
        cpu = snapshot.get("cpu", 0)
        mem = snapshot.get("mem", 0)
        c_icon = "🔴" if cpu > 85 else "🟡" if cpu > 60 else "🟢"
        m_icon = "🔴" if mem > 85 else "🟡" if mem > 70 else "🟢"
        now = __import__("datetime").datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        SEP = "─" * 21
        lines = [
            "**🛡️ Sentinel — תמונת מערכת**",
            f"_עודכן: {now}_",
            SEP,
            "**💡 עומסים:**",
            f"{c_icon} CPU: {cpu:.0f}%   {m_icon} RAM: {mem:.0f}%",
        ]
        gpu_info = snapshot.get("gpu", {})
        if gpu_info and "name" in gpu_info:
            lines.append(f"🎮 GPU: {gpu_info['name']} ({gpu_info.get('status', 'Unknown')})")
        elif gpu_info and "error" in gpu_info:
            lines.append(f"🎮 GPU: {gpu_info['error']}")
        disk_alerts = snapshot.get("disk_alerts", [])
        if disk_alerts:
            lines.append("**⚠️ התראות דיסק:**")
            for alert in disk_alerts:
                lines.append(f"- {alert}")
        else:
            lines.append("- ✅ דיסקים: תקין")
        # ── Information Hiding (v2): network connections are NOT shown here ──
        # The snapshot must NOT pre-digest "חיבורים חשודים: ✅ אין" — that
        # causes the LLM to skip get_external_connections (Token Optimization).
        # Force the ReAct tree to call get_external_connections for network data.
        lines.extend(["", SEP, "**🌐 חיבורי רשת:** קרא ל-`get_external_connections` לבדיקת חיבורים חיצוניים."])
        top_procs = snapshot.get("top_procs", [])
        if top_procs:
            lines.extend(["", SEP, "**⚙️ תהליכים (CPU):**"])
            for p in top_procs[:5]:
                c = p.get("cpu_percent", 0)
                icon = "🔴" if c > 50 else "🟡" if c > 20 else "🟢"
                lines.append(f"- {icon} {p.get('name', '?'):<28} {c:.0f}%  (PID {p.get('pid', '?')})")
        alert_needed = snapshot.get("alert_needed", False)
        lines.extend(
            [
                "",
                SEP,
                f"{'⚠️ **התראה פעילה!**' if alert_needed else '✅ **מצב מערכת: תקין**'}",
            ]
        )
        return "\n".join(lines)
    except Exception as e:
        logger.error("[mcp_handlers] sentinel_get_system_snapshot_full failed: %s", e)
        return f"❌ שגיאה בקבלת תמונת מערכת: {e}"


async def sentinel_get_pending_events(limit: int = 10) -> str:
    """Get pending events from event bus."""
    try:
        events = event_bus.get_pending_events(limit)
        if not events:
            return "📭 אין אירועים ממתינים ב-Event Bus."
        lines = [f"📋 אירועים ממתינים ({len(events)}):", ""]
        for i, e in enumerate(events, 1):
            ts = e.get("timestamp", "N/A")
            etype = e.get("event_type", "unknown")
            sev = e.get("priority", "N/A")
            data = e.get("data", {})
            if etype == "alert":
                desc = data.get("analysis") or "ללא תיאור"
            elif etype == "daily_digest":
                desc = data.get("ai_analysis") or data.get("report") or "ללא תיאור"
            elif etype == "critical_override":
                desc = data.get("message") or "ללא תיאור"
            else:
                desc = "ללא תיאור"
            if len(str(desc)) > 200:
                desc = str(desc)[:197] + "..."
            lines.append(f"{i}. [{ts}] {etype} | {sev}")
            lines.append(f"   {desc}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        logger.error("[mcp_handlers] sentinel_get_pending_events failed: %s", e)
        return f"❌ שגיאה בקבלת אירועים: {e}"


async def sentinel_clear_event_queue() -> str:
    """Clear the event queue."""
    try:
        count = event_bus.clear_queue()
        return f"🗑️ נוקו {count} אירועים מתור ה-Event Bus."
    except Exception as e:
        logger.error("[mcp_handlers] sentinel_clear_event_queue failed: %s", e)
        return f"❌ שגיאה בניקוי תור: {e}"


async def telegram_list_pairings() -> str:
    """List pending Telegram pairings."""
    try:
        channel = get_message_gateway()
        if not channel:
            return "❌ Telegram channel not available"
        pending = await channel.list_pending_pairings()
        if not pending:
            return "✅ אין בקשות pairing ממתינות"
        lines = [f"🔐 בקשות Pairing ממתינות ({len(pending)}):", ""]
        for p in pending:
            lines.append(f"קוד: `{p['code']}`")
            lines.append(f"  משתמש: {p['user_name']} (ID: {p['user_id']})")
            lines.append(f"  נוצר: {p['created_at']}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        logger.error("[mcp_handlers] telegram_list_pairings failed: %s", e)
        return f"❌ שגיאה בקבלת pairings: {e}"


async def telegram_approve_pairing(code: str) -> str:
    """Approve a Telegram pairing request."""
    try:
        channel = get_message_gateway()
        if not channel:
            return "❌ Telegram channel not available"
        result = await channel.approve_pairing(code)
        if result:
            return f"✅ קוד `{code}` אושר\nמשתמש: {result.get('user_name', 'Unknown')} ({result.get('user_id', 'N/A')})"
        return f"❌ קוד `{code}` לא נמצא או כבר אושר"
    except Exception as e:
        logger.error("[mcp_handlers] telegram_approve_pairing failed: %s", e)
        return f"❌ שגיאה באישור pairing: {e}"


async def telegram_send_message(chat_id: str, message: str) -> str:
    """Send a message to Telegram."""
    try:
        channel = get_message_gateway()
        if not channel:
            return "❌ Telegram channel not available"
        success = await channel.send_message(chat_id, message)
        if success:
            return f"✅ הודעה נשלחה ל-{chat_id}"
        return f"❌ שגיאה בשליחה ל-{chat_id}"
    except Exception as e:
        logger.error("[mcp_handlers] telegram_send_message failed: %s", e)
        return f"❌ שגיאה בשליחת הודעה: {e}"


__all__ = [
    "approve_pending_action_tool",
    "deny_pending_action_tool",
    "sentinel_get_system_snapshot_full",
    "sentinel_get_pending_events",
    "sentinel_clear_event_queue",
    "telegram_list_pairings",
    "telegram_approve_pairing",
    "telegram_send_message",
    "trigger_news_digest_tool",
    "recent_memory_tool",
    "skill_file_analyst",
    "skill_web_scraper",
    "skill_intel",
    "osint_hunt_tool",
]


# ── Re-exports for backward compatibility ──
from services.tools.mcp_skill_handlers import (  # noqa: E402,F401
    osint_hunt_tool,
    recent_memory_tool,
    skill_file_analyst,
    skill_intel,
    skill_web_scraper,
    trigger_news_digest_tool,
)
