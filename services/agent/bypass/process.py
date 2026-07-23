# services/agent/bypass/process.py
"""Deterministic bypass for process queries — routes directly to system tools.

"show processes" / "רשימת תהליכים" → get_process_list (no LLM step).
"kill PID 1234" / "הרוג תהליך 1234" → terminate_process (pending approval).
"""

import logging

from services.agent.routing.intent_routers import _is_process_query
from services.bot_memory import async_store_conversation

logger = logging.getLogger(__name__)


async def _direct_process_list_bypass(user_question: str) -> str:
    """Deterministic bypass: call get_process_list handler directly."""
    from services.tools_registry import LLM_TOOL_MAP

    handler = LLM_TOOL_MAP.get("get_process_list")
    if handler is None:
        return "⚠️ כלי רשימת תהליכים לא זמין."
    logger.info("[AGENT] Process-list bypass activated")
    try:
        if __import__("asyncio").iscoroutinefunction(handler):
            result = await handler()
        else:
            result = await __import__("asyncio").to_thread(handler)
    except Exception as e:
        logger.error("[AGENT] Process-list bypass failed: %s", e)
        return "⚠️ שגיאה באחזור רשימת תהליכים."
    if not result:
        return "⚠️ לא התקבלו תהליכים."
    try:
        await async_store_conversation(user_question, str(result))
    except Exception:
        pass
    return str(result)


async def _direct_process_kill_bypass(pid: int, user_question: str) -> str:
    """Deterministic bypass: call terminate_process handler directly."""
    from services.tools_registry import LLM_TOOL_MAP

    handler = LLM_TOOL_MAP.get("terminate_process")
    if handler is None:
        return "⚠️ כלי סיום תהליך לא זמין."
    logger.info("[AGENT] Process-kill bypass activated: PID=%d", pid)
    try:
        if __import__("asyncio").iscoroutinefunction(handler):
            result = await handler(pid=pid)
        else:
            result = await __import__("asyncio").to_thread(handler, pid=pid)
    except Exception as e:
        logger.error("[AGENT] Process-kill bypass failed: %s", e)
        return f"⚠️ שגיאה בסיום תהליך {pid}."
    try:
        await async_store_conversation(user_question, str(result))
    except Exception:
        pass
    return str(result)


async def _try_process_bypass(q: str) -> str | None:
    """Detect process query and route to the appropriate system tool."""
    detected = _is_process_query(q)
    if not detected:
        return None
    action, pid = detected
    if action == "kill" and pid is not None:
        return await _direct_process_kill_bypass(pid, q)
    return await _direct_process_list_bypass(q)
