"""Telegram message bridge route for local MCP server.

Extracted from local_mcp_server.py (SRP). Receives Telegram messages via
HTTP and routes them through the Sentinel Agent with conversational
detection and IDE-instruction cleaning.
"""

import logging
from typing import Any

from fastapi import Depends

from services.local_mcp_server import _verify_mcp_auth
from services.local_mcp_server import app as _app
from services.text_utils import clean_ide_instructions

app: Any = _app  # type: ignore[has-type]

logger = logging.getLogger(__name__)

try:
    from services.agent import run_agent
except ImportError:
    run_agent = None

try:
    from services.agent import _SKILL_KEYWORD_MAP, _is_conversational
except ImportError:
    _SKILL_KEYWORD_MAP = {}
    _is_conversational = None

from pydantic import BaseModel


class TelegramMessageRequest(BaseModel):
    message: str
    user_id: int = 0
    user_name: str = "Unknown"
    chat_id: int = 0


@app.post("/telegram/message", dependencies=[Depends(_verify_mcp_auth)])
async def telegram_message(req: TelegramMessageRequest):
    """קבלת הודעה וביצוע עיבוד דרך Sentinel Agent."""
    if run_agent is None:
        return {"error": "Agent not available"}

    try:
        logger.info(f"[TelegramBridge] Message from {req.user_name}: {req.message[:50]}...")

        cleaned_message = clean_ide_instructions(req.message)

        from services.agent import _SKILL_KEYWORD_MAP, _is_conversational

        q = cleaned_message.lower()
        matched_skills = [kw for kw in _SKILL_KEYWORD_MAP if kw in q]
        logger.info(
            f"[TelegramBridge-DEBUG] query='{cleaned_message[:40]}' "
            f"lowercase='{q[:40]}' matched_skills={matched_skills}"
        )

        is_conv = await _is_conversational(cleaned_message)
        logger.info(f"[TelegramBridge] Conversational check: text='{cleaned_message[:30]}...' result={is_conv}")

        if is_conv:
            logger.info("[TelegramBridge] Using conversational shortcut (no tools)")
            result = await run_agent(cleaned_message)
        else:
            enriched = f"[מבצע: {req.user_name}] {cleaned_message}"
            logger.info(f"[TelegramBridge] Using enriched text with agent: {enriched[:50]}...")
            result = await run_agent(enriched)

        return {"response": result, "handled": True}
    except Exception as e:
        logger.error(f"[TelegramBridge] Error: {e}", exc_info=True)
        return {"response": f"שגיאה בעיבוד: {str(e)}", "handled": False, "error": str(e)}
