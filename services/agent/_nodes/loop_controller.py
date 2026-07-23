"""Loop Detection Controller — prevents infinite tool-call loops.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
Responsibility: detect repeated (tool_name, args_hash) pairs and
apply subtask-aware or non-subtask recovery strategies.
"""

import hashlib
import json
import logging
from typing import Any

from .._context import AgentState, _AgentContext
from .._helpers import _get_last_tool_output, _sanitize_subtask_messages, _synthesize_results

logger = logging.getLogger(__name__)


def build_call_key(fn_name: str, fn_args: Any, subtask_idx: int = -1) -> tuple[int, str, str]:
    """Build a deterministic hash key for loop detection.

    Two calls with the same name and arguments receive the same key,
    regardless of dict ordering or non-ASCII text.

    The subtask_idx is included so that the same tool called in
    different subtasks is NOT considered a loop — the final synthesis
    subtask legitimately needs fresh data from tools already used
    during investigation subtasks.
    """
    _args_hash = hashlib.sha256(json.dumps(fn_args, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return (subtask_idx, fn_name, _args_hash)


async def handle_loop(
    ctx: _AgentContext,
    fn_name: str,
    fn_args: Any,
) -> tuple[bool, AgentState | None, str | None]:
    """Detect and handle tool-call loops.

    Returns:
        (handled, next_state, output)
        If handled is True, the caller must return (next_state, output) immediately.
        If handled is False, the caller should proceed with normal execution.
    """
    call_key = build_call_key(fn_name, fn_args, ctx.current_subtask_idx)
    if call_key not in ctx._executed_history:
        return False, None, None

    logger.warning("[AGENT] Loop detected: %s called twice. Blocking.", fn_name)
    _prev_output = _get_last_tool_output(ctx.messages) or ""

    # ── Subtask-aware recovery ──
    if ctx.subtasks and ctx.current_subtask_idx >= 0:
        # First loop on this subtask → one corrective nudge
        if ctx._loop_nudge_idx != ctx.current_subtask_idx:
            ctx._loop_nudge_idx = ctx.current_subtask_idx
            logger.warning(
                "[AGENT] Loop in subtask %d — nudging for correction.",
                ctx.current_subtask_idx + 1,
            )
            ctx.messages.append(
                {
                    "role": "user",
                    "content": (
                        f"<tool_output>\n{_prev_output}\n</tool_output>\n\n"
                        f"[SYSTEM ALERT: LOOP DETECTED] "
                        f"Tool '{fn_name}' was ALREADY executed with these exact arguments "
                        f"(output above). Do NOT repeat it. "
                        f"IMMEDIATELY use 'final_answer' to deliver the report. "
                        f"Respond strictly using the ReAct format:\n"
                        f"Action: final_answer\n"
                        f'Action Input: {{"text": "YOUR_FULL_REPORT_HERE"}}'
                    ),
                }
            )
            return True, AgentState.EXECUTE, None

        # Second consecutive loop → genuinely stuck. Advance, preferring
        # THIS run's own raw output; never silently inherit foreign data.
        current = ctx.subtasks[ctx.current_subtask_idx]
        _own_raw = getattr(ctx, "_last_raw_tool_result", "")
        current["result"] = _own_raw or "⚠️ No new data — redundant tool call blocked."
        current["status"] = "done"
        task_id = str(current.get("id", ctx.current_subtask_idx))
        ctx._task_results[task_id] = current["result"]
        ctx.current_subtask_idx += 1

        if ctx.current_subtask_idx < len(ctx.subtasks):
            logger.info(
                "[PLANNER] Subtask %d/%d done (loop-blocked). Advancing.",
                ctx.current_subtask_idx,
                len(ctx.subtasks),
            )
            ctx._subtask_injected_for = ""
            ctx.messages = _sanitize_subtask_messages(ctx.messages)
            return True, AgentState.EXECUTE, None

        # All subtasks done
        results = [s["result"] for s in ctx.subtasks if s.get("status") == "done"]
        ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
        return True, AgentState.CRITIC, None

    # ── Non-subtask mode — aggressive cognitive command ──
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                f"<tool_output>\n{_prev_output}\n</tool_output>\n\n"
                f"[SYSTEM ALERT: LOOP DETECTED] "
                f"You have already called '{fn_name}' with these exact parameters. "
                f"Do NOT call it again. You have sufficient data. "
                f"IMMEDIATELY use the 'final_answer' tool to generate the report. "
                f"Respond strictly using the ReAct format:\n"
                f"Action: final_answer\n"
                f'Action Input: {{"text": "YOUR_FULL_REPORT_HERE"}}'
            ),
        }
    )
    return True, AgentState.EXECUTE, None
