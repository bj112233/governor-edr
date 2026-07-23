# services/agent/bypass/eml.py
"""Deterministic bypass: .eml/.msg → email-forensics skill (no LLM)."""

import logging

from services.agent.routing.intent_routers import _is_eml_query
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)


async def _direct_eml_bypass(path: str, command: str, user_question: str) -> str:
    """Deterministic bypass: call skill_email-forensics directly."""
    engine = get_skills_engine()
    result = await engine.execute("email-forensics", command, {"path": path})
    if result is None:
        return "⚠️ email-forensics skill failed to execute. The file may be corrupted or inaccessible."
    if isinstance(result, str):
        return result
    return str(result)


async def _try_eml_bypass(q: str) -> str | None:
    """Detect .eml/.msg query and route to email-forensics bypass."""
    detected = _is_eml_query(q)
    if detected:
        path, command = detected
        logger.info("[Bypass] email-forensics bypass: path=%s command=%s", path, command)
        return await _direct_eml_bypass(path, command, q)
    return None
