"""FSM Node: FINALIZE — store conversation, persist lessons, return output."""

import logging
import os

from ...bot_memory import _is_nonpersistable_response, async_store_conversation
from ...error_memory import store_lesson
from ...memory_db import store_message as _store_message
from .._context import AgentState, _AgentContext
from .._helpers import _fire_and_forget

logger = logging.getLogger(__name__)


async def _node_finalize(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Store conversation, persist lessons, return output."""
    final_text = ctx.output
    logger.info("[AGENT-DIAG] final_answer: len=%d preview=%r", len(final_text), final_text[:300])
    try:
        await async_store_conversation(ctx.user_question, final_text)
    except Exception as e:
        logger.debug("[AGENT] Memory storage failed: %s", e)
    _fire_and_forget(_store_message("agent", final_text))
    if ctx._last_error and not _is_nonpersistable_response(final_text):
        _fire_and_forget(
            store_lesson(
                error_signature=ctx._last_error,
                trigger_context=ctx.user_question,
                resolution=final_text,
            )
        )
    # ── Temp File Bridge: cleanup accumulated temp files ──
    for _tf in getattr(ctx, "_temp_files", []):
        try:
            os.unlink(_tf)
            logger.debug("[BRIDGE] Cleaned up temp file: %s", _tf)
        except OSError:
            pass
    ctx._temp_files.clear()

    return AgentState.FINALIZE, final_text


async def _node_error(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Graceful degradation — salvage gathered data or return error message."""
    # ── Temp File Bridge: cleanup on error too ──
    for _tf in getattr(ctx, "_temp_files", []):
        try:
            os.unlink(_tf)
        except OSError:
            pass
    ctx._temp_files.clear()

    # ── Fail-Safe Reporting: salvage gathered data on max-steps exhaustion ──
    _error_msg = getattr(ctx, "error_msg", "") or "Unknown error"
    if "Maximum steps exceeded" in _error_msg:
        _raw = getattr(ctx, "_last_raw_tool_result", "")
        _buffer = getattr(ctx, "_tool_outputs_buffer", [])
        _salvaged = ""
        if _buffer:
            _salvaged = "\n\n".join(f"[{e['name']}] {e['result']}" for e in _buffer)
        elif _raw and len(_raw) > 10:
            _salvaged = _raw
        if _salvaged:
            # Truncate to 2500 chars — Telegram limit is 4096, leave room for header
            _MAX_SALVAGE = 2500
            if len(_salvaged) > _MAX_SALVAGE:
                _salvaged = _salvaged[:_MAX_SALVAGE] + "\n...[DATA TRUNCATED]"
            logger.info(
                "[FAIL-SAFE] Max steps triggered. Salvaging %d chars of tool data.",
                len(_salvaged),
            )
            _report = (
                "⚠️ **המערכת ביצעה ניתוח עמוק מדי וקטעה את הפעולה כדי לשמור על משאבים.**\n"
                "להלן הנתונים הגולמיים שהצלחתי לאסוף עד לנקודת החיתוך:\n\n"
                f"```text\n{_salvaged}\n```"
            )
            # Route through FINALIZE so conversation + lessons are persisted
            ctx.output = _report
            return AgentState.FINALIZE, _report

    return AgentState.ERROR, f"🚨 Agent error: {_error_msg}"
