# services/agent/bypass/pcap.py
"""Deterministic bypass: .pcap/.pcapng → pcap-analyst skill (no LLM)."""

import logging

from services.agent.routing.intent_routers import _is_pcap_query
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)


async def _direct_pcap_bypass(path: str, command: str, user_question: str) -> str:
    """Deterministic bypass: call skill_pcap-analyst directly."""
    engine = get_skills_engine()
    result = await engine.execute("pcap-analyst", command, {"path": path})
    if result is None:
        return "⚠️ pcap-analyst skill failed to execute. The file may be corrupted or inaccessible."
    if isinstance(result, str):
        return result
    return str(result)


async def _try_pcap_bypass(q: str) -> str | None:
    """Detect .pcap/.pcapng query and route to pcap-analyst bypass."""
    detected = _is_pcap_query(q)
    if detected:
        path, command = detected
        logger.info("[Bypass] pcap-analyst bypass: path=%s command=%s", path, command)
        return await _direct_pcap_bypass(path, command, q)
    return None
