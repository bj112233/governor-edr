# services/agent/bypass/cve.py
"""Deterministic bypass for CVE queries — routes directly to osint_hunt.

CVE queries (e.g. "CVE-2024-3094", "מה זה CVE-2023-22515") skip the LLM
tool-selection step and invoke the OSINT engine-in-engine directly.
"""

import logging

from services.agent.routing.intent_routers import _is_cve_query
from services.bot_memory import async_store_conversation

logger = logging.getLogger(__name__)


async def _direct_cve_bypass(cve_id: str, user_question: str) -> str:
    """Deterministic bypass: call osint_hunt_tool directly with the CVE ID."""
    from services.tools.mcp_skill_handlers import osint_hunt_tool

    logger.info("[AGENT] CVE bypass activated: %s", cve_id)
    try:
        result = await osint_hunt_tool(topic=cve_id)
    except Exception as e:
        logger.error("[AGENT] CVE bypass failed: %s", e)
        return f"⚠️ שגיאה בחיפוש OSINT עבור {cve_id}."
    if not result or result.startswith("❌"):
        return f"⚠️ לא ניתן לאחזר מידע עבור {cve_id}."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result


async def _try_cve_bypass(q: str) -> str | None:
    """Detect CVE query and route to osint_hunt bypass."""
    cve_id = _is_cve_query(q)
    if cve_id:
        return await _direct_cve_bypass(cve_id, q)
    return None
