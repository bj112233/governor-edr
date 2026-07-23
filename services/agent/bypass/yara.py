# services/agent/bypass/yara.py
"""Deterministic bypass for YARA scan queries — routes directly to scan_file_yara.

"yara scan C:\\malware.exe" / "סריקת yara על file.bin" → scan_file_yara tool.
"""

import logging

from services.agent.routing.intent_routers import _is_yara_query
from services.bot_memory import async_store_conversation

logger = logging.getLogger(__name__)


async def _direct_yara_bypass(filepath: str, user_question: str) -> str:
    """Deterministic bypass: call scan_file_yara handler directly."""
    from services.tools_registry import LLM_TOOL_MAP

    handler = LLM_TOOL_MAP.get("scan_file_yara")
    if handler is None:
        return "⚠️ כלי סריקת YARA לא זמין."
    logger.info("[AGENT] YARA bypass activated: filepath=%s", filepath)
    try:
        import asyncio

        if asyncio.iscoroutinefunction(handler):
            result = await handler(filepath=filepath)
        else:
            result = await asyncio.to_thread(handler, filepath=filepath)
    except Exception as e:
        logger.error("[AGENT] YARA bypass failed: %s", e)
        return f"⚠️ שגיאה בסריקת YARA עבור {filepath}."
    if not result:
        return f"⚠️ סריקת YARA עבור {filepath} לא החזירה תוצאות."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return str(result)


async def _try_yara_bypass(q: str) -> str | None:
    """Detect YARA scan query and route to scan_file_yara bypass."""
    filepath = _is_yara_query(q)
    if filepath:
        return await _direct_yara_bypass(filepath, q)
    return None
