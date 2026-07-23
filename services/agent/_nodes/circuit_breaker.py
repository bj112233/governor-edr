"""Circuit Breaker Controller — failure detection, dynamic replanning, self-healing.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
Sprint 6: Replaced static _SKILL_FALLBACKS dictionary with LLM-driven
dynamic replanning. The LLM chooses the alternative path, not a hardcoded map.

Responsibility:
  1. Detect tool execution errors
  2. On first failure: inject raw error + available tools → LLM replans
  3. On >=2 consecutive failures: activate circuit breaker
     - Block the tool (prevent death loops)
     - Mark task as failed / block dependents
     - Inject recovery subtask with dynamic replan prompt
"""

import logging
from typing import Any

from .._context import AgentState, _AgentContext
from .._helpers import (
    _build_recovery_task,
    _fire_and_forget,
    _sanitize_subtask_messages,
    _synthesize_results,
)

logger = logging.getLogger(__name__)

# NOTE: 🚨 is intentionally NOT a generic error prefix. Many skills/formatters use
# it decoratively for ALERT content (firewall 'drops' → "🚨 N DROP events", weather
# alerts, SOC reports, intel, system-snapshot severity). A successful alert result
# must not be misclassified as a tool failure. Real crashes are caught separately
# via the "🚨 [SYSTEM CRASH]" marker in _is_error_result().
_ERROR_PREFIXES = ("❌", "⏱️", "Security Error", "Error:", "Exception:", "Timeout")


def _normalize_error_signature(tool_result: str, fn_name: str) -> str:
    """Extract a stable, dedup-friendly error signature from a tool result.

    Dynamic data (memory addresses, PIDs, timestamps) would break GROUP BY
    in get_tool_stats(). We normalize to a fixed signature per error class.
    """
    _result = str(tool_result)
    if "[SYSTEM CRASH]" in _result:
        # Extract exception type from "🚨 [SYSTEM CRASH] Tool 'x' failed: TypeError"
        _parts = _result.split("failed:")
        if len(_parts) >= 2:
            _exc_type = _parts[-1].strip().split("(")[0].strip()
            return f"SYSTEM_CRASH_{_exc_type}"
        return "SYSTEM_CRASH_UNKNOWN"
    if _result.lstrip().startswith("⏱️") or "Timeout" in _result:
        return "TIMEOUT"
    if "Security Error" in _result or "NOT authorized" in _result:
        return "SECURITY_VIOLATION"
    if _result.lstrip().startswith("❌"):
        return "LOGICAL_ERROR"
    return "UNKNOWN_ERROR"


def _available_tool_names(ctx: _AgentContext) -> list[str]:
    """Extract non-blocked tool names from active_tools for replan prompt."""
    names = []
    for t in ctx.active_tools:
        name = t.get("function", {}).get("name", "")
        if name and name != "final_answer" and name not in ctx._blocked_tools:
            names.append(name)
    return names


def _replan_prompt(
    fn_name: str,
    error_msg: str,
    ctx: _AgentContext,
    *,
    blocked: bool = False,
) -> str:
    """Build a dynamic replan prompt that delegates alternative selection to the LLM.

    The LLM receives:
    - The raw error from the failed tool
    - The list of still-available tools
    - The original user objective
    - Instruction to replan and use a DIFFERENT tool
    """
    available = _available_tool_names(ctx)
    tools_str = ", ".join(available) if available else "[no other tools available]"

    blocked_str = " This tool is now BLOCKED — do NOT call it again." if blocked else ""
    objective = ctx.user_question[:200]

    return (
        f"[SYSTEM — Dynamic Replanning]\n"
        f"Tool '{fn_name}' failed with error: {error_msg}.{blocked_str}\n"
        f"Original objective: {objective}\n"
        f"Available tools: [{tools_str}]\n"
        f"REPLAN: Think step-by-step and choose a DIFFERENT tool to achieve the objective. "
        f"Do NOT retry '{fn_name}'. If no alternative tool can help, "
        f"call final_answer with the data you already gathered."
    )


def _store_alert_event(fn_name: str, error_text: str, session_id: str, chain_id: str) -> None:
    from services.bot_memory.highlevel import inject_event

    _fire_and_forget(
        inject_event(
            event_type="tool_error",
            description=f"{fn_name} failed: {error_text}",
            severity=2,
            source="executor",
            session_id=session_id,
            chain_id=chain_id,
        )
    )


def _is_error_result(tool_result: str) -> bool:
    _s = str(tool_result).lstrip()
    # Real tool crash: executor emits "🚨 [SYSTEM CRASH] ...". Detect it explicitly
    # so we don't have to treat the decorative 🚨 alert emoji as an error prefix.
    if _s.startswith("🚨") and "[SYSTEM CRASH]" in _s[:40]:
        return True
    return _s.startswith(_ERROR_PREFIXES)


async def _store_crash_lesson(fn_name: str, error_signature: str, user_question: str) -> None:
    """Persist a normalized error lesson so the Tool Ranker can penalize unstable tools.

    Uses stable error_signature (SYSTEM_CRASH_TypeError, TIMEOUT, etc.) to
    ensure GROUP BY in get_tool_stats() aggregates correctly.
    """
    from services.error_memory import store_lesson

    try:
        await store_lesson(
            error_signature=error_signature,
            trigger_context=user_question[:200],
            resolution=f"Tool '{fn_name}' is unstable. Ranker should penalize.",
            tool_name=fn_name,
        )
        logger.info("[CIRCUIT BREAKER] Stored crash lesson: %s → %s", fn_name, error_signature)
    except Exception as exc:
        logger.debug("[CIRCUIT BREAKER] store_lesson failed: %s", exc)


async def handle_tool_result(
    ctx: _AgentContext,
    fn_name: str,
    fn_args: dict,
    tool_result: str,
    execute_tool,
) -> tuple[str, bool, AgentState | None, str | None]:
    """Process tool execution result. Detect errors, inject replan, check circuit breaker.

    Returns:
        (updated_tool_result, is_error, next_state, output)
        If next_state is not None, the caller must return (next_state, output) immediately.
    """
    _is_error = _is_error_result(tool_result)
    logger.warning("[CIRCUIT-BREAKER] %s result_preview=%r is_error=%s", fn_name, str(tool_result)[:120], _is_error)

    if _is_error:
        ctx._consecutive_tool_failures += 1
        ctx._last_error = f"{fn_name}: {str(tool_result).strip()[:200]}"

        # ── Store normalized lesson for Tool Ranker (closed-loop reinforcement) ──
        # Normalized signature prevents dynamic data (PIDs, addresses) from
        # breaking GROUP BY in get_tool_stats().
        _sig = _normalize_error_signature(tool_result, fn_name)
        _fire_and_forget(_store_crash_lesson(fn_name, _sig, ctx.user_question))

        _store_alert_event(
            fn_name,
            str(tool_result).strip()[:200],
            getattr(ctx, "session_id", ""),
            getattr(ctx, "_current_chain_id", ""),
        )

        # Dynamic Replanning: on first failure, inject error + available tools
        # The LLM will choose an alternative in the next round — no static map.
        if ctx._consecutive_tool_failures == 1:
            error_msg = str(tool_result).strip()[:300]
            replan = _replan_prompt(fn_name, error_msg, ctx, blocked=False)
            logger.warning(
                "[AGENT] Tool '%s' failed (1st). Injecting dynamic replan prompt.",
                fn_name,
            )
            ctx.messages.append(
                {"role": "user", "content": f"<tool_output>\n{tool_result}\n</tool_output>\n\n{replan}"}
            )
            # Return to EXECUTE — LLM picks alternative tool next round
            return tool_result, _is_error, AgentState.EXECUTE, None
    else:
        ctx._consecutive_tool_failures = 0

    # Circuit Breaker Activation (2nd consecutive failure)
    if ctx._consecutive_tool_failures >= 2:
        logger.error("[CIRCUIT BREAKER] Tool '%s' failed 2 times. Blocking + dynamic replan.", fn_name)
        ctx._consecutive_tool_failures = 0
        ctx._blocked_tools.add(fn_name)

        error_msg = str(tool_result).strip()[:300]

        if ctx.subtasks and ctx.current_subtask_idx >= 0:
            current = ctx.subtasks[ctx.current_subtask_idx]
            task_id = str(current.get("id", f"T{ctx.current_subtask_idx}"))

            current["status"] = "failed"
            current["error"] = f"Tool '{fn_name}' failed twice. Blocked."
            ctx._failed_tasks.add(task_id)
            ctx._task_results[task_id] = f"[FAILURE] {current['error']}"

            # Block dependent tasks
            for st in ctx.subtasks:
                deps = st.get("depends_on", [])
                if isinstance(deps, list) and task_id in [str(d) for d in deps]:
                    dep_id = str(st.get("id", "T" + str(ctx.subtasks.index(st))))
                    dep_type = st.get("dependency_type", "hard")
                    if dep_type == "soft":
                        logger.info(
                            "[PLANNER] Task '%s' depends on failed '%s' but dependency_type='soft' — allowing partial data.",
                            dep_id,
                            task_id,
                        )
                        continue
                    ctx._blocked_by_failure.add(dep_id)
                    st["status"] = "blocked"
                    st["error"] = f"Blocked: depends on failed task '{task_id}'"
                    logger.warning(
                        "[PLANNER] Task '%s' blocked — depends on failed '%s'",
                        dep_id,
                        task_id,
                    )

            # Inject recovery subtask with dynamic replan (no static fallback_cmd)
            _recovery = _build_recovery_task(task_id, fn_name, error_msg, ctx.user_question)
            ctx.subtasks.insert(ctx.current_subtask_idx + 1, _recovery)
            logger.info(
                "[PLANNER] Injected recovery task '%s' at position %d.",
                _recovery["id"],
                ctx.current_subtask_idx + 1,
            )

            # Dynamic replan prompt — LLM chooses the alternative
            replan = _replan_prompt(fn_name, error_msg, ctx, blocked=True)
            ctx.messages.append({"role": "user", "content": replan})

            ctx.current_subtask_idx += 1
            if ctx.current_subtask_idx < len(ctx.subtasks):
                ctx._subtask_injected_for = ""
                ctx.messages = _sanitize_subtask_messages(ctx.messages)
                return tool_result, _is_error, AgentState.EXECUTE, None

            results = [s["result"] for s in ctx.subtasks if s.get("status") in ("done", "failed", "blocked")]
            ctx.draft_answer = await _synthesize_results(
                ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used
            )
            return tool_result, _is_error, AgentState.CRITIC, None
        else:
            # Non-subtask mode — dynamic replan with blocked tool
            replan = _replan_prompt(fn_name, error_msg, ctx, blocked=True)
            ctx.messages.append({"role": "user", "content": replan})
            return tool_result, _is_error, AgentState.EXECUTE, None

    return tool_result, _is_error, None, None
