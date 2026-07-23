"""Subtask State Manager — DAG state transitions and prompt injection.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
Responsibility:
  1. Subtask preparation (before LLM call):
     - Skip blocked tasks, synthesize if all done
     - Resolve dependency outputs (Late Binding)
     - Detect analysis-only subtasks
     - Inject subtask prompt with rules
  2. No-tool-call advancement (after LLM call):
     - Mark subtask done, advance index
     - Synthesize results if all subtasks done
"""

import logging
from typing import Any

from .._context import AgentState, _AgentContext
from .._helpers import _sanitize_subtask_messages, _synthesize_results
from .task_completion import _validate_subtask_payload

logger = logging.getLogger(__name__)

_ANALYSIS_KEYWORDS = (
    "analyze",
    "compare",
    "identify",
    "determine",
    "evaluate",
    "assess",
    "find the most",
    "rank",
    "select",
)


def _build_tool_rule(current: dict[str, Any], is_analysis_only: bool, is_last: bool) -> str:
    """Build the tool-usage rules for this subtask."""
    if is_analysis_only:
        return (
            "CRITICAL: This subtask is ANALYSIS-ONLY.\n"
            "You ALREADY HAVE all data needed (see DEPENDENCY DATA above).\n"
            "Call final_answer DIRECTLY with a VERBATIM QUOTE from the dependency data.\n"
            "You MUST NOT use internal training knowledge.\n"
            "You MUST NOT invent IP addresses, scores, or threat assessments.\n"
            "If the dependency data is empty or says 'No data', your answer MUST say exactly that.\n"
        )
    if is_last:
        return (
            "CRITICAL SUBTASK RULES:\n"
            "1. Call EXACTLY ONE tool to complete this subtask.\n"
            "2. IMMEDIATELY after receiving the tool output, call final_answer with the result.\n"
            "3. Do NOT call additional tools. Do NOT gather extra data.\n"
        )
    return (
        "CRITICAL SUBTASK RULES:\n"
        "1. Call EXACTLY ONE tool to complete this subtask.\n"
        "2. Do NOT call final_answer. The system advances automatically after the tool returns.\n"
        "3. Do NOT call additional tools. Do NOT gather extra data.\n"
        "4. Do NOT call any tool named 'wait', 'proceed', 'advance', or 'next_subtask'. "
        "These do not exist. Just call the tool for the next subtask when prompted.\n"
    )


async def handle_subtask_preparation(
    ctx: _AgentContext,
) -> tuple[bool, AgentState | None, str | None]:
    """Prepare the current subtask before LLM call.

    Returns:
        (should_continue, next_state, output)
        If should_continue is False, the caller must return (next_state, output) immediately.
    """
    if not ctx.subtasks or ctx.current_subtask_idx < 0:
        return True, None, None

    # All subtasks done — critic may have routed back to EXECUTE for revision.
    # Don't re-prepare a subtask that's past the end of the list.
    if ctx.current_subtask_idx >= len(ctx.subtasks):
        return True, None, None

    current = ctx.subtasks[ctx.current_subtask_idx]
    desc = current.get("description", "")

    # ── Skip blocked tasks (dependency failure) ──
    if current.get("status") == "blocked":
        task_id = str(current.get("id", ctx.current_subtask_idx))
        current["result"] = current.get("error", "Blocked by dependency failure.")
        ctx._task_results[task_id] = current["result"]
        # ── DAG emit: pending → blocked ──
        from .._dag_emitter import emit_subtask_transition

        await emit_subtask_transition(ctx, task_id, "pending", "blocked")
        ctx.current_subtask_idx += 1
        if ctx.current_subtask_idx < len(ctx.subtasks):
            return False, AgentState.EXECUTE, None
        results = [s["result"] for s in ctx.subtasks if s.get("status") in ("done", "failed", "blocked")]
        ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
        return False, AgentState.CRITIC, None

    # ── Dependency Injection (prevents Token Bloat) ──
    dep_block = ""
    dep_parts: list[str] = []
    deps = current.get("depends_on", [])
    if deps:
        for dep_id in deps:
            dep_key = str(dep_id)
            if dep_key in ctx._task_results:
                dep_parts.append(f"[Task {dep_key} output]:\n{ctx._task_results[dep_key]}")
            else:
                logger.warning("[EXECUTOR] Missing dependency output: %s", dep_key)
        if dep_parts:
            dep_block = "\n\n=== Dependency Results ===\n" + "\n\n".join(dep_parts) + "\n===\n"

    # ── Prompt Injection (once per subtask) ──
    if ctx._subtask_injected_for != desc:
        _is_analysis_only = bool(dep_parts) and any(kw in desc.lower() for kw in _ANALYSIS_KEYWORDS)
        _is_last = ctx.current_subtask_idx == len(ctx.subtasks) - 1
        _tool_rule = _build_tool_rule(current, _is_analysis_only, _is_last)

        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    f"[SUBTASK {ctx.current_subtask_idx + 1}/{len(ctx.subtasks)}] {desc}\n"
                    f"{dep_block}"
                    f"{_tool_rule}"
                    "4. final_answer MUST be BRIEF — raw data/observations only (max 500 chars).\n"
                    "   Do NOT write a full report. The final synthesis will create the report.\n"
                    "5. final_answer is how you mark this subtask as DONE."
                ),
            }
        )
        ctx._subtask_injected_for = desc

    return True, None, None


async def handle_no_tool_call(
    ctx: _AgentContext,
    fallback_text: str,
) -> tuple[bool, AgentState | None, str | None]:
    """Handle LLM response with no tool call in subtask mode.

    Returns:
        (handled, next_state, output)
        If handled is True, the caller must return (next_state, output) immediately.
    """
    if not ctx.subtasks or ctx.current_subtask_idx < 0 or ctx.current_subtask_idx >= len(ctx.subtasks):
        return False, None, None

    current = ctx.subtasks[ctx.current_subtask_idx]

    # ── Strict Validator: reject hollow payloads before auto-advance ──
    # Without this, "אין לי מידע על כך" or empty echoes get marked "done",
    # cascading hallucinations to downstream subtasks.
    if not _validate_subtask_payload(fallback_text):
        ctx._premature_fa_count += 1
        if ctx._premature_fa_count >= 3:
            logger.error(
                "[INTERCEPTOR] Subtask %d/%d: 3x hollow no-tool output. Marking FAILED and advancing.",
                ctx.current_subtask_idx + 1,
                len(ctx.subtasks),
            )
            current["result"] = "⚠️ Subtask skipped — no valid data gathered."
            current["status"] = "failed"
            task_id = str(current.get("id", ctx.current_subtask_idx))
            ctx._task_results[task_id] = current["result"]
            ctx._premature_fa_count = 0
            # ── DAG emit: pending → failed ──
            from .._dag_emitter import emit_subtask_transition

            await emit_subtask_transition(ctx, task_id, "pending", "failed")
            ctx.current_subtask_idx += 1
            ctx._subtask_injected_for = ""
            ctx._last_raw_tool_result = ""
            ctx._subtask_tool_count = 0
            if ctx.current_subtask_idx < len(ctx.subtasks):
                ctx.messages = _sanitize_subtask_messages(ctx.messages)
                return True, AgentState.EXECUTE, None
            results = [s["result"] for s in ctx.subtasks if s.get("status") in ("done", "failed")]
            ctx.draft_answer = await _synthesize_results(
                ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used
            )
            return True, AgentState.CRITIC, None

        logger.warning(
            "[INTERCEPTOR] Subtask %d/%d: hollow no-tool output (attempt %d). "
            "Blocking auto-advance, nudging for real tool call. preview=%.80s",
            ctx.current_subtask_idx + 1,
            len(ctx.subtasks),
            ctx._premature_fa_count,
            fallback_text,
        )
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    f"[SYSTEM BLOCK — SUBTASK {ctx.current_subtask_idx + 1}/{len(ctx.subtasks)}]\n"
                    f"Your output was REJECTED — it contains no real data (empty/apology/no-info).\n"
                    f"This subtask requires REAL DATA from a tool call.\n\n"
                    f"MANDATORY ACTION:\n"
                    f"1. Call the appropriate tool for this subtask NOW.\n"
                    f"2. After receiving tool output, call final_answer with the result.\n\n"
                    f"Subtask description: {current.get('description', '')}\n"
                    f"Available tools: {[t.get('function', {}).get('name', '?') for t in ctx.active_tools if t.get('function', {}).get('name') != 'final_answer']}"
                ),
            }
        )
        return True, AgentState.EXECUTE, None

    logger.info(
        "[AGENT] Subtask auto-advance: subtask %d/%d done (step %d)",
        ctx.current_subtask_idx + 1,
        len(ctx.subtasks),
        ctx.step_count,
    )
    current["result"] = fallback_text
    current["status"] = "done"
    task_id = str(current.get("id", ctx.current_subtask_idx))
    ctx._task_results[task_id] = fallback_text
    ctx.current_subtask_idx += 1
    ctx._subtask_tool_count = 0  # reset per-subtask counter
    # ── DAG emit: pending → done ──
    from .._dag_emitter import emit_subtask_transition

    await emit_subtask_transition(ctx, task_id, "pending", "done")

    if ctx.current_subtask_idx < len(ctx.subtasks):
        ctx._subtask_injected_for = ""
        ctx.messages = _sanitize_subtask_messages(ctx.messages)
        return True, AgentState.EXECUTE, None

    results = [s["result"] for s in ctx.subtasks if s.get("status") == "done"]
    ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
    return True, AgentState.CRITIC, None
