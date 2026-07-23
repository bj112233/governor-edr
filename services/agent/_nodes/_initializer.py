"""FSM Node: INITIALIZE — build context, select tools, inject memory."""

import logging

from ...bot_memory import async_store_conversation
from ...llm_bridge import LLMBridge, is_llm_ready
from ...memory_db import store_message as _store_message
from ...skills_engine import get_skills_engine
from ...text_utils import clean_ide_instructions
from .._bypasses import _BYPASS_HANDLERS
from .._context import AgentState, _AgentContext
from .._helpers import _fire_and_forget
from ..routing import _is_conversational
from ._initializer_helpers import (
    _build_history_messages,
    _inject_directive,
    _inject_memory,
    _select_tools,
)

logger = logging.getLogger(__name__)


async def _run_pre_compute(user_question: str, system_prompt: str) -> tuple[str, str | None, str]:
    """Pre-compute deterministic enrichment (hard facts injection).

    Returns (updated_system_prompt, intent, hard_facts_str).
    hard_facts_str is stored in _AgentContext so the critic entity audit
    can verify IPs/IOCs from deterministic enrichment (not just tool outputs).
    """
    try:
        from services.pre_compute_router import format_pre_compute_facts, pre_compute

        report = await pre_compute(user_question)
        hard_facts = format_pre_compute_facts(report) or ""
        if hard_facts:
            system_prompt += f"\n\n{hard_facts}"
        intent = report.intent.get("intent") if report.intent else None
        logger.info(
            "[AGENT] Pre-compute: intent=%s, %d IOCs enriched — hard facts injected (%d chars).",
            intent or "none",
            len(report.enriched),
            len(hard_facts),
        )
        return system_prompt, intent, hard_facts
    except Exception as exc:
        logger.warning("[AGENT] Pre-compute failed (non-fatal): %s", exc)
        return system_prompt, None, ""


def _apply_tool_visibility(active_tools: list, intent: str | None) -> list:
    """Context Collapse — hide tools irrelevant to detected intent."""
    try:
        from services.tools.tool_visibility import filter_tools_by_intent

        before = len(active_tools)
        active_tools = filter_tools_by_intent(active_tools, intent)
        hidden = before - len(active_tools)
        if hidden:
            logger.info(
                "[AGENT] Context collapse: intent=%s, hidden %d tools (%d→%d).",
                intent or "none",
                hidden,
                before,
                len(active_tools),
            )
    except Exception as exc:
        logger.warning("[AGENT] Tool visibility filter failed (non-fatal): %s", exc)
    return active_tools


async def _build_agent_context(raw_question: str, allow_bypasses: bool = True) -> _AgentContext:
    """Pre-flight: build the full message list, select tools, inject memory."""
    user_question = clean_ide_instructions(raw_question)

    # --- 1. Bypass check (skipped when allow_bypasses=False, e.g. Threat Hunter) ---
    if allow_bypasses:
        for handler in _BYPASS_HANDLERS:
            result = await handler(user_question)
            if result is not None:
                _fire_and_forget(_store_message("agent", result))
                return _AgentContext(
                    user_question=user_question,
                    messages=[],
                    active_tools=[],
                    step_max_tokens=0,
                    bypass_response=result,
                )

    # --- 2. LLM readiness ---
    if not is_llm_ready():
        return _AgentContext(
            user_question=user_question,
            messages=[],
            active_tools=[],
            step_max_tokens=0,
            is_llm_ready=False,
        )

    # --- 3. Load skills ---
    skills_engine = get_skills_engine()
    skills_tools = skills_engine.get_tools()
    if skills_tools:
        logger.info("[AGENT] Loaded %d skills", len(skills_tools))
        skill_names = [s.get("function", {}).get("name", "?") for s in skills_tools]
        logger.info("[AGENT-DEBUG] Available skills: %s", skill_names)
    else:
        logger.warning("[AGENT-DEBUG] No skills loaded!")

    # --- 4. Tool selection (with pre-fetched lessons to avoid double embedding) ---
    from services.error_memory import search_lessons as _search_lessons

    _prefetched_lessons = await _search_lessons(user_question, limit=5, threshold=0.75)
    active_tools, system_prompt = await _select_tools(user_question, skills_tools, _prefetched_lessons)

    # --- 4.5. Pre-compute deterministic enrichment (hard facts injection) ---
    system_prompt, _pre_compute_intent, _hard_facts = await _run_pre_compute(user_question, system_prompt)

    # --- 4.6. Context Collapse — hide tools irrelevant to detected intent ---
    active_tools = _apply_tool_visibility(active_tools, _pre_compute_intent)

    # --- 5. Memory injections (reuse pre-fetched lessons) ---
    system_prompt = await _inject_memory(system_prompt, user_question, _prefetched_lessons)

    # --- 5.5. No-ReAct auto-correction — inject aggressive format directive
    # if the model has repeatedly collapsed to free-form text in this session ---
    from .._noreact_tracker import get_directive

    _noreact_directive = get_directive()
    if _noreact_directive:
        system_prompt += _noreact_directive
        logger.warning("[AGENT] No-ReAct directive injected (repeated format collapse detected).")
        logger.info("[AGENT] Injected NO-REACT directive into current prompt (TTL=900s).")

    _diag_tool_names = [t.get("function", {}).get("name", "?") for t in active_tools]
    logger.info("[AGENT-DIAG] tools_sent=%d: %s", len(_diag_tool_names), _diag_tool_names)

    # System time
    from datetime import datetime

    _now = datetime.now().strftime("%A, %Y-%m-%d %H:%M:%S")
    system_prompt += f"\n\n[SYSTEM TIME: {_now}]"

    # --- 6-7. Build message list with conversation history ---
    history_msgs, _history_msgs_added = await _build_history_messages(user_question)
    messages: list[dict[str, str]] = [{"role": "system", "content": system_prompt}] + history_msgs

    # --- 8. Directive injection ---
    messages = _inject_directive(messages, user_question, active_tools, _history_msgs_added)

    # --- 9. Token budget ---
    step_max_tokens = 1024 if not active_tools else 1500

    return _AgentContext(
        user_question=user_question,
        messages=messages,
        active_tools=active_tools,
        step_max_tokens=step_max_tokens,
        _hard_facts=_hard_facts,
    )


async def _node_initialize(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Build context, check bypass/LLM readiness, select tools, inject memory."""
    _fire_and_forget(_store_message("user", ctx.user_question))
    built = await _build_agent_context(ctx.user_question, allow_bypasses=ctx.allow_bypasses)

    ctx.messages = built.messages
    ctx.active_tools = built.active_tools
    ctx.step_max_tokens = built.step_max_tokens
    ctx.bypass_response = built.bypass_response
    ctx.is_llm_ready = built.is_llm_ready
    ctx.subtasks = built.subtasks
    ctx._hard_facts = built._hard_facts

    if ctx.bypass_response is not None:
        ctx.output = ctx.bypass_response
        return AgentState.FINALIZE, ctx.bypass_response

    if not ctx.is_llm_ready:
        ctx.output = "⏳ מנוע ה-AI עדיין נטען לזיכרון. נסה שוב בעוד 30 שניות."
        return AgentState.FINALIZE, ctx.output

    ctx.engine = LLMBridge.get_instance()

    if not ctx.active_tools:
        msg = await ctx.engine.agent_step(ctx.messages, max_tokens=ctx.step_max_tokens, json_schema=False)
        answer = msg.content or "⚠️ לא התקבלה תשובה."
        try:
            await async_store_conversation(ctx.user_question, answer)
        except Exception as e:
            logger.debug("[AGENT] Memory storage failed: %s", e)
        _fire_and_forget(_store_message("agent", answer))
        ctx.output = answer
        return AgentState.FINALIZE, answer

    return AgentState.PLANNER, None
