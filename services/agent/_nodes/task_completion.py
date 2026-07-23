"""Task Completion Handler — final_answer processing and subtask advancement.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
Responsibility: Handle final_answer tool calls — extract text, mark subtasks
done, intercept premature final_answers, and route to critic or finalize.
"""

import logging
import re

from .._branch_rules import _evaluate_branch_rules
from .._context import AgentState, _AgentContext
from .._helpers import _get_last_tool_output, _synthesize_results
from ._branch_executor import apply_skip_to_final

logger = logging.getLogger(__name__)

# ── Payload Validation: detect hollow / apology / echo outputs ──────────────
# LLMs under stress produce "I don't have that information" or empty
# <tool_output> echoes. These must NOT count as subtask completion.

_APOLOGY_PATTERNS = [
    re.compile(r"אין\s+לי\s+מידע", re.IGNORECASE),
    re.compile(r"לא\s+מצאתי", re.IGNORECASE),
    re.compile(r"איני\s+(?:יכול|יכולה|מסוגל)", re.IGNORECASE),
    re.compile(r"אין\s+ב(?:רשותי|ידי)\s+מידע", re.IGNORECASE),
    re.compile(r"לא\s+הצלחתי\s+ל(?:מצוא|אתר)", re.IGNORECASE),
    re.compile(r"i\s+cannot\s+(?:find|provide|access)", re.IGNORECASE),
    re.compile(r"i\s+don'?t\s+have\s+(?:that|any|the)\s+information", re.IGNORECASE),
    re.compile(r"no\s+(?:data|information|results?)\s+(?:found|available)", re.IGNORECASE),
    re.compile(r"unable\s+to\s+(?:find|retrieve|access|determine)", re.IGNORECASE),
]

_TOOL_OUTPUT_RE = re.compile(r"<tool_output>\s*(.*?)\s*</tool_output>", re.DOTALL)


def _validate_subtask_payload(text: str) -> bool:
    """Strict Validator: returns True if the payload contains real data.

    Rejects:
      1. Empty Payload — whitespace-only or bare empty tags.
      2. Apology Filter — text is ONLY an LLM refusal/apology with no data.
      3. Echo Wrapper — <tool_output> wrapper with empty/whitespace content.
    """
    if not text or not text.strip():
        return False

    _stripped = text.strip()

    # Strip <tool_output> wrapper and check inner content
    _m = _TOOL_OUTPUT_RE.search(_stripped)
    if _m:
        _inner = _m.group(1).strip()
        if not _inner:
            return False
        _stripped = _inner

    # Apology filter: if the ENTIRE text is an apology (short, no data markers)
    # Short apology = <120 chars and matches a pattern and has no JSON/numbers
    _has_data_markers = bool(re.search(r"[\d{}[\]|]", _stripped))
    if len(_stripped) < 120 and not _has_data_markers:
        for _pat in _APOLOGY_PATTERNS:
            if _pat.search(_stripped):
                return False

    return True


def _resolve_final_text(ctx: _AgentContext, fn_args: dict) -> str:
    """Extract final_text from fn_args with fallbacks to tool output / buffer."""
    final_text = (
        fn_args.get("text")
        or fn_args.get("message")
        or fn_args.get("answer")
        or fn_args.get("summary")
        or fn_args.get("response")
        or fn_args.get("content")
    )
    if final_text:
        return final_text

    last_tool_output = _get_last_tool_output(ctx.messages)
    if last_tool_output:
        logger.warning(
            "[AGENT] Fallback: final_answer empty, injected last tool_output (%d chars)",
            len(last_tool_output),
        )
        return last_tool_output

    if ctx._tool_outputs_buffer:
        _buffered = "\n\n".join(f"[{entry['name']}] {entry['result']}" for entry in ctx._tool_outputs_buffer)
        logger.warning(
            "[AGENT] Fallback: final_answer empty, context trimmed. "
            "Injected %d chars from _tool_outputs_buffer (%d tools).",
            len(_buffered),
            len(ctx._tool_outputs_buffer),
        )
        return _buffered

    return "המשימה הושלמה."


async def _handle_premature_subtask(
    ctx: _AgentContext,
    current: dict,
) -> tuple[bool, AgentState | None, str | None]:
    """Handle premature final_answer in subtask mode (no tool data)."""
    ctx._premature_fa_count += 1
    if ctx._premature_fa_count >= 3:
        logger.error(
            "[INTERCEPTOR] Subtask %d/%d: 3x premature final_answer without tools. Marking FAILED and advancing.",
            ctx.current_subtask_idx + 1,
            len(ctx.subtasks),
        )
        current["result"] = "⚠️ Subtask skipped — no tool data gathered."
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
        ctx._subtask_tool_count = 0  # reset per-subtask counter
        if ctx.current_subtask_idx < len(ctx.subtasks):
            return True, AgentState.EXECUTE, None
        results = [s["result"] for s in ctx.subtasks if s.get("status") in ("done", "failed")]
        ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
        return True, AgentState.CRITIC, None

    logger.warning(
        "[INTERCEPTOR] Subtask %d/%d: premature final_answer (attempt %d) — NO tool data. "
        "Blocking final_answer, forcing tool execution.",
        ctx.current_subtask_idx + 1,
        len(ctx.subtasks),
        ctx._premature_fa_count,
    )
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                f"[SYSTEM BLOCK — SUBTASK {ctx.current_subtask_idx + 1}/{len(ctx.subtasks)}]\n"
                f"Your final_answer was REJECTED. You called final_answer WITHOUT executing any tool.\n"
                f"This subtask requires REAL DATA from a tool call.\n\n"
                f"MANDATORY ACTION:\n"
                f"1. Do NOT call final_answer.\n"
                f"2. Call the appropriate tool for this subtask NOW.\n"
                f"3. Only after receiving tool output, you may call final_answer.\n\n"
                f"Subtask description: {current.get('description', '')}\n"
                f"Available tools: {[t.get('function', {}).get('name', '?') for t in ctx.active_tools if t.get('function', {}).get('name') != 'final_answer']}"
            ),
        }
    )
    return True, AgentState.EXECUTE, None


async def _handle_subtask_done(
    ctx: _AgentContext,
    current: dict,
    _raw: str,
    final_text: str,
) -> tuple[bool, AgentState | None, str | None]:
    """Mark subtask done and advance to next or finalize."""
    ctx._premature_fa_count = 0
    _last_tool = _get_last_tool_output(ctx.messages)
    _dep_data = (
        _raw if (_raw and len(_raw) > 10) else (_last_tool if (_last_tool and len(_last_tool) > 20) else final_text)
    )

    # ── Strict Validator: reject hollow / apology / empty-echo payloads ──
    # Without this, the agent marks subtasks "done" with "אין לי מידע על כך"
    # or empty <tool_output></tool_output>, cascading hallucinations downstream.
    if not _validate_subtask_payload(_dep_data):
        logger.warning(
            "[INTERCEPTOR] Subtask %d/%d: hollow payload rejected (empty/apology/echo). "
            "Routing to premature handler. preview=%.80s",
            ctx.current_subtask_idx + 1,
            len(ctx.subtasks),
            _dep_data,
        )
        return await _handle_premature_subtask(ctx, current)

    current["result"] = _dep_data
    current["status"] = "done"
    task_id = str(current.get("id", ctx.current_subtask_idx))
    ctx._task_results[task_id] = _dep_data
    ctx.current_subtask_idx += 1
    ctx._subtask_tool_count = 0  # reset per-subtask counter
    # ── DAG emit: pending → done ──
    from .._dag_emitter import emit_subtask_transition

    await emit_subtask_transition(ctx, task_id, "pending", "done")

    # ── Branch Rules: deterministic conditional DAG routing ──
    _completed_idx = ctx.current_subtask_idx - 1
    _branch = _evaluate_branch_rules(_dep_data, ctx.subtasks, _completed_idx)
    if _branch.action == "skip_to_final":
        _skip_result = await apply_skip_to_final(ctx, _branch)
        if _skip_result is not None:
            return _skip_result

    if _branch.action == "inject":
        _new_task = {
            "id": f"T{_completed_idx + 1}_branch",
            "description": _branch.inject_description,
            "depends_on": [task_id],
            "dependency_type": "hard",
            "status": "pending",
        }
        ctx.subtasks.insert(ctx.current_subtask_idx, _new_task)
        logger.info(
            "[BRANCH-RULES] Injected subtask '%s' at position %d: %s",
            _new_task["id"],
            ctx.current_subtask_idx,
            _branch.reason,
        )

    if ctx.current_subtask_idx < len(ctx.subtasks):
        logger.info(
            "[INTERCEPTOR] Subtask %d/%d done with tool data. Advancing to next.",
            ctx.current_subtask_idx,
            len(ctx.subtasks),
        )
        next_task = ctx.subtasks[ctx.current_subtask_idx]
        interceptor_msg = (
            f"[SYSTEM] Subtask {ctx.current_subtask_idx - 1} completed. "
            f"Now executing subtask {ctx.current_subtask_idx + 1}: "
            f"{next_task.get('description', '')}\n"
            f"Call the appropriate tool for this subtask. "
            f"Do NOT call any tool to acknowledge or wait for advancement."
        )
        ctx.messages.append(
            {
                "role": "user",
                "content": f"<tool_output>\n{interceptor_msg}\n</tool_output>",
            }
        )
        ctx._subtask_injected_for = ""
        ctx._last_raw_tool_result = ""
        return True, AgentState.EXECUTE, None

    logger.info("[PLANNER] All %d subtasks done. Synthesizing...", len(ctx.subtasks))
    results = [s["result"] for s in ctx.subtasks if s.get("status") == "done"]
    ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
    return True, AgentState.CRITIC, None


def _handle_non_subtask_premature(ctx: _AgentContext) -> tuple[bool, AgentState | None, str | None] | None:
    """Intercept premature final_answer in non-subtask mode. Returns None if OK."""
    _real_tools_used = len(ctx._tools_used) > 0
    _has_actionable_tools = any(
        t.get("function", {}).get("name", "") not in ("final_answer", "") for t in ctx.active_tools
    )
    # Late-step escape: if we're at step 8+ and still no tools used, let the
    # model through — forcing more tool attempts at this point creates a death
    # loop that ends in "Maximum steps exceeded" with no user output at all.
    _late_step = ctx.step_count >= 8
    if _has_actionable_tools and not _real_tools_used and not _late_step:
        logger.warning(
            "[EXECUTOR] Premature final_answer intercepted (step %d): 0 tools used, %d available. "
            "Forcing tool execution.",
            ctx.step_count,
            len(ctx.active_tools) - 1,
        )
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    "[SYSTEM INTERCEPT] You called final_answer but have NOT executed any tools yet. "
                    "Your previous output was a PLAN, not an answer. "
                    "You MUST call the appropriate tools FIRST to gather data, "
                    "THEN call final_answer with the results. "
                    "Call a tool NOW."
                ),
            }
        )
        return True, AgentState.EXECUTE, None
    if _late_step and not _real_tools_used:
        logger.warning(
            "[EXECUTOR] Late-step escape (step %d): allowing final_answer despite 0 tools. Avoiding death loop.",
            ctx.step_count,
        )
    return None


async def handle_final_answer(
    ctx: _AgentContext,
    fn_args: dict,
) -> tuple[bool, AgentState | None, str | None]:
    """Process a final_answer tool call.

    Returns:
        (handled, next_state, output)
        If handled is True, the caller must return (next_state, output) immediately.
    """
    # Empty final_answer detection: model called final_answer without text.
    # If tool data exists, nudge twice to synthesize before falling back to raw data.
    _has_text_arg = any(fn_args.get(k) for k in ("text", "message", "answer", "summary", "response", "content"))
    if not _has_text_arg and ctx.step_count > 0:
        _raw = getattr(ctx, "_last_raw_tool_result", "")
        _has_tool_data = bool(_raw and len(_raw) > 10) or len(ctx._tools_used) > 0 or bool(ctx._tool_outputs_buffer)
        if _has_tool_data and ctx._empty_fa_nudge_count < 2:
            ctx._empty_fa_nudge_count += 1
            logger.warning(
                "[AGENT] final_answer called with empty text (step %d). Nudging for synthesis.",
                ctx.step_count,
            )
            ctx.messages.append(
                {
                    "role": "user",
                    "content": (
                        "CRITICAL: Your internal planning was NOT the final answer. "
                        "You called final_answer without providing the 'text' argument. "
                        "Write the complete report NOW as the 'text' argument. "
                        "Do not repeat your planning — output the actual report. "
                        "Keep cyber terms in English: MITRE ATT&CK, TTP, IOC, Encoded Commands, Execution Policy Bypass. "
                        "You have tool data available; synthesize it into a clear, structured response."
                    ),
                }
            )
            return True, AgentState.EXECUTE, None

    final_text = _resolve_final_text(ctx, fn_args)

    # Subtask mode
    if ctx.subtasks and 0 <= ctx.current_subtask_idx < len(ctx.subtasks):
        current = ctx.subtasks[ctx.current_subtask_idx]
        _raw = getattr(ctx, "_last_raw_tool_result", "")
        _has_tool_data = bool(_raw and len(_raw) > 10) or ctx._subtask_tool_count > 0
        # Emergency mode or prior subtask data → allow synthesis without new tool call
        _is_synthesis = getattr(ctx, "is_emergency_mode", False) or bool(ctx._task_results)

        if not _has_tool_data and not _is_synthesis:
            return await _handle_premature_subtask(ctx, current)
        return await _handle_subtask_done(ctx, current, _raw, final_text)

    # Non-subtask mode
    intercepted = _handle_non_subtask_premature(ctx)
    if intercepted is not None:
        return intercepted

    ctx.draft_answer = final_text
    return True, AgentState.CRITIC, None
