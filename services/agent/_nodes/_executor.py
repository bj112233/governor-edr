"""FSM Node: EXECUTE — single ReAct tick: LLM call → parse → tool execution."""

import json
import logging

from .._context import AgentState, _AgentContext
from .._helpers import _has_tool_outputs_in_history
from .._react_parser import parse_react_response
from ..utils import _trim_messages, sanitize_agent_history
from ._executor_phases import (
    apply_resource_guard,
    execute_critical_calls,
    execute_safe_calls,
    handle_no_tool_calls,
    llm_call,
    partition_tool_calls,
)
from .state_manager import handle_subtask_preparation

logger = logging.getLogger(__name__)


def _compute_max_tokens(ctx: _AgentContext) -> int:
    """Compute max_tokens budget with schema fatigue nudge for final_answer."""
    if ctx.subtasks and ctx.current_subtask_idx >= 0:
        return min(ctx.step_max_tokens, 768)
    if _has_tool_outputs_in_history(ctx) and ctx.step_count >= 2:
        _call_max_tokens = max(ctx.step_max_tokens, 6000)
        logger.info("[AGENT-DIAG] Expanded max_tokens to %d for final_answer generation", _call_max_tokens)
        if not ctx._schema_nudge_injected:
            ctx._schema_nudge_injected = True
            ctx.messages.append(
                {
                    "role": "user",
                    "content": (
                        "<system_reminder>"
                        "You have tool results. You MUST output valid JSON with a tool_call. "
                        "If you need more data, call the next tool. "
                        "If you have enough data to answer, call final_answer. "
                        "DO NOT output plain text outside of JSON."
                        "</system_reminder>"
                    ),
                }
            )
        return _call_max_tokens
    return ctx.step_max_tokens


def _compute_allowed_tools(ctx: _AgentContext) -> set[str]:
    """Build the allowed-tool set, applying emergency/degraded mode restrictions."""
    _allowed = {t.get("function", {}).get("name", "") for t in ctx.active_tools}
    _allowed.add("final_answer")

    # Emergency mode: lock action space to final_answer only
    if getattr(ctx, "is_emergency_mode", False):
        logger.info("[AGENT] 🛡️ Emergency mode: restricted tools to 'final_answer' only.")
        return {"final_answer"}

    # DEGRADED mode: block critical tools when Critic is offline.
    # Closes a Fail-Open vulnerability where prompt injection → False DEGRADED
    # → unvalidated critical tool access.
    if getattr(ctx, "_degraded_mode", False):
        from ...tools_registry import REGISTRY

        _allowed = {name for name, spec in REGISTRY.items() if spec.safety_level != "critical"}
        _allowed.add("final_answer")
        logger.warning(
            "[AGENT] 🛡️ DEGRADED mode — critical tools blocked (Critic offline). Allowed: %d tools + final_answer.",
            len(_allowed) - 1,
        )
    return _allowed


def _handle_empty_tool_calls(
    ctx: _AgentContext,
    tool_calls: list,
) -> tuple[AgentState, str | None] | None:
    """Return early-exit state if tool_calls is empty after all fallbacks, else None."""
    if ctx.step_count == 0 and ctx.active_tools and not tool_calls:
        ctx.output = "⚠️ לא הבנתי בדיוק מה לעשות. אנא נסח מחדש או ציין במפורש איזה פעולה לבצע."
        return AgentState.FINALIZE, ctx.output
    if not tool_calls:
        ctx.output = "⚠️ כשל במבנה הסוכן (לא החזיר JSON חוקי)."
        return AgentState.FINALIZE, ctx.output
    return None


async def _node_execute(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Single ReAct tick: LLM call → parse → tool execution."""
    ctx.messages = _trim_messages(ctx.messages)

    # ── Subtask State Manager (SRP extract) ──
    _handled, _next_state, _output = await handle_subtask_preparation(ctx)
    if not _handled:
        assert _next_state is not None
        return _next_state, _output

    _diag_total_chars = sum(len(json.dumps(m, ensure_ascii=False, default=str)) for m in ctx.messages)
    logger.info(
        "[AGENT-DIAG] step=%d total_msg_chars=%d msgs=%d",
        ctx.step_count,
        _diag_total_chars,
        len(ctx.messages),
    )

    _call_max_tokens = _compute_max_tokens(ctx)

    # ── LLM call with overflow retry ──
    content, _err_state, _err_msg = await llm_call(ctx, _call_max_tokens)
    if _err_state is not None:
        ctx.error_msg = _err_msg or ""
        return _err_state, None

    assert content is not None
    logger.info("[AGENT-DIAG] llm_response: content_len=%d preview=%r", len(content), content[:120])

    parsed = parse_react_response(content)
    tool_calls = parsed["tool_calls"]

    # ── In-flight ReAct correction ──
    # If the parser salvaged free-form text (no ReAct structure), inject a
    # system warning into the conversation so the model sees the correction
    # in its history on any follow-up turn in this session.
    if parsed.get("no_react_salvaged"):
        ctx.messages.append(
            {
                "role": "system",
                "content": (
                    "[SYSTEM WARNING] You provided a 'Thought' but skipped the 'Action' JSON. "
                    "You MUST output valid JSON tool calls using the ReAct format: "
                    'Thought: <reasoning>\\nAction: <tool_name>\\nAction Input: {"key": "value"}'
                ),
            }
        )
        logger.warning("[AGENT] In-flight ReAct correction injected (step %d).", ctx.step_count)

    # ── No-tool-call handling ──
    if not tool_calls:
        _handled, _next_state, _output, _override = await handle_no_tool_calls(ctx, parsed, tool_calls)
        if _handled:
            return _next_state, _output
        tool_calls = _override

    # ── Empty tool calls after fallbacks → early exit ──
    _empty_exit = _handle_empty_tool_calls(ctx, tool_calls)
    if _empty_exit is not None:
        return _empty_exit

    ctx.messages.append({"role": "assistant", "content": sanitize_agent_history(content)})
    logger.info("[AGENT] step=%d: %d tool calls", ctx.step_count, len(tool_calls))

    _allowed_tool_names = _compute_allowed_tools(ctx)

    thought = parsed.get("thought", "")
    if thought:
        logger.info("[AGENT-COGNITION] %s", thought)

    # ── Phase 0: Partition into safe/critical ──
    _safe_calls, _critical_calls, _early_state, _early_output = await partition_tool_calls(
        ctx, tool_calls, thought, _allowed_tool_names
    )
    if _early_state is not None:
        return _early_state, _early_output

    # ── Phase 0.5: Resource guard ──
    _safe_calls, _critical_calls, _all_blocked, _rg_reason = apply_resource_guard(_safe_calls, _critical_calls)
    if _all_blocked:
        _warn = f"[RESOURCE GATE] System under stress ({_rg_reason}). All heavy tool calls deferred. Use final_answer with available data."
        logger.warning(_warn)
        ctx.messages.append({"role": "user", "content": _warn})
        return AgentState.EXECUTE, None

    # ── Phase 1: Execute safe calls in parallel ──
    _early = await execute_safe_calls(ctx, _safe_calls)
    if _early is not None:
        return _early  # type: ignore[return-value]

    # ── Phase 2: Execute critical calls sequentially ──
    return await execute_critical_calls(ctx, _critical_calls)
