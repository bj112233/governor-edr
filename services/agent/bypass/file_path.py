# services/agent/bypass/file_path.py
"""Deterministic bypass for file-analyst queries — routes file paths directly to the skill.

When a user asks to summarize/analyze/OCR a file with an explicit path,
skip the LLM tool-selection step and invoke file-analyst directly.
"""

import logging

from services.agent.routing.intent_routers import _is_file_path_query
from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)


async def _direct_file_path_bypass(path: str, action: str, user_question: str) -> str:
    """Deterministic bypass: call skill_file-analyst directly."""
    engine = get_skills_engine()
    logger.info("[AGENT] File-path bypass activated: action=%s path=%s", action, path)
    try:
        result = await engine.execute("file-analyst", action, {"path": path})
    except Exception as e:
        logger.error("[AGENT] File-path bypass failed: %s", e)
        return f"⚠️ שגיאה בניתוח הקובץ {path}."
    if not result or result.startswith("❌"):
        return f"⚠️ ניתוח הקובץ {path} נכשל."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result


async def _try_file_path_bypass(q: str) -> str | None:
    """Detect file-path query and route to file-analyst bypass."""
    detected = _is_file_path_query(q)
    if detected:
        path, action = detected
        return await _direct_file_path_bypass(path, action, q)
    return None
