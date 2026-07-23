"""Partition helpers — extracted from _executor_phases.py (SRP / file-length gate).

Per-tool-call validation: name resolution, authorization, error-lesson,
blocked-tool handling, safety-level classification.
"""

import json
import logging

from ...error_memory import store_lesson
from ...tools_registry import REGISTRY
from .._context import _DANGEROUS_TOOLS, _AgentContext
from .._helpers import _fire_and_forget

logger = logging.getLogger(__name__)


def _resolve_tool_name(fn_name: str, tool_call: dict, allowed: set[str]) -> str:
    """Resolve tool name by trying sentinel_/skill_ prefixes (LLM often drops them)."""
    if fn_name in allowed:
        return fn_name
    for prefix in ("sentinel_", "skill_"):
        if f"{prefix}{fn_name}" in allowed:
            logger.info("[AGENT] Resolved tool name: %s → %s", tool_call["name"], f"{prefix}{fn_name}")
            tool_call["name"] = f"{prefix}{fn_name}"
            return f"{prefix}{fn_name}"
    return fn_name


async def _handle_none_subtask_advance(ctx: _AgentContext) -> None:
    """Auto-advance subtask when model calls 'none' (implicit completion)."""
    current = ctx.subtasks[ctx.current_subtask_idx]
    current["result"] = "No action needed — auto-advanced."
    current["status"] = "done"
    ctx._task_results[str(current.get("id", ctx.current_subtask_idx))] = current["result"]
    ctx.current_subtask_idx += 1
    # ── DAG emit: pending → done ──
    from .._dag_emitter import emit_subtask_transition

    await emit_subtask_transition(ctx, str(current.get("id", ctx.current_subtask_idx - 1)), "pending", "done")
    logger.info(
        "[AGENT] Model called 'none' on subtask %d/%d — auto-advancing.",
        ctx.current_subtask_idx,
        len(ctx.subtasks),
    )
    if ctx.current_subtask_idx < len(ctx.subtasks):
        next_task = ctx.subtasks[ctx.current_subtask_idx]
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    f"[SYSTEM] Subtask {ctx.current_subtask_idx} skipped (no action needed). "
                    f"Now executing subtask {ctx.current_subtask_idx + 1}: "
                    f"{next_task.get('description', '')}\n"
                    f"Call the appropriate tool for this subtask. "
                    f"Do NOT call any tool to acknowledge or wait for advancement."
                ),
            }
        )


async def _check_authorization(
    ctx: _AgentContext,
    fn_name: str,
    allowed: set[str],
) -> bool:
    """Return True if tool is authorized (or auto-advanced via 'none'), False to skip."""
    if fn_name in allowed:
        return True
    # Special case: model calls 'none'/'(none)' when it has no action.
    _normalized = fn_name.lower().strip("()<>/ ")
    if _normalized == "none" and ctx.subtasks and ctx.current_subtask_idx < len(ctx.subtasks):
        await _handle_none_subtask_advance(ctx)
        return False
    error_msg = f"Security Error: Tool '{fn_name}' is NOT authorized. Allowed: {sorted(allowed)}"
    logger.warning("[AGENT] Blocked unauthorized tool: '%s'", fn_name)
    ctx._last_error = f"Unauthorized tool '{fn_name}'"
    ctx.messages.append({"role": "user", "content": f"<tool_output>\n{error_msg}\n</tool_output>"})
    return False


def _handle_error_lesson(
    ctx: _AgentContext,
    fn_name: str,
    fn_args: dict,
    thought: str,
) -> None:
    """Capture or store error-lesson for JSON parse failures."""
    if "CRITICAL_ERROR" in fn_args:
        ctx._last_parse_error = str(fn_args.get("your_raw_input", "")).strip() or str(fn_args["CRITICAL_ERROR"])
        logger.warning("[AGENT] Error-lesson: captured JSON parse failure.")
    elif ctx._last_parse_error is not None:
        _recovered = json.dumps(
            {"thought": thought, "tool_call": {"name": fn_name, "arguments": fn_args}},
            ensure_ascii=False,
            default=str,
        )
        _fire_and_forget(
            store_lesson(
                error_signature=ctx._last_parse_error,
                trigger_context=ctx.user_question,
                resolution=_recovered,
                tool_name=fn_name,
            )
        )
        logger.info("[AGENT] Error-lesson: JSON recovery stored.")
        ctx._last_parse_error = None


def _is_safe_tool(fn_name: str) -> bool:
    """Determine if a tool is safe (auto-execute) vs critical (needs approval)."""
    tool_spec = REGISTRY.get(fn_name)
    if tool_spec is not None:
        return tool_spec.safety_level == "safe"
    if fn_name.startswith("skill_"):
        return fn_name not in _DANGEROUS_TOOLS
    return False


def _handle_blocked_tool(ctx: _AgentContext, fn_name: str) -> None:
    """Circuit breaker: inject dynamic replan for blocked tools."""
    from .circuit_breaker import _replan_prompt

    error_msg = ctx._last_error or f"Tool '{fn_name}' is blocked after repeated failures."
    replan = _replan_prompt(fn_name, error_msg, ctx, blocked=True)
    logger.warning("[AGENT] Blocked tool '%s' (circuit breaker). Injecting dynamic replan.", fn_name)
    ctx._last_error = f"Tool '{fn_name}' blocked"
    ctx.messages.append({"role": "user", "content": replan})
