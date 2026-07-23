"""Branch rule executor — applies BranchDecision to the agent context.

Extracted from task_completion.py to keep it under 300 LLOC.
Single responsibility: execute skip_to_final and inject decisions.
"""

import logging

from .._branch_rules import BranchDecision
from .._context import AgentState, _AgentContext
from .._helpers import _synthesize_results

logger = logging.getLogger(__name__)


async def apply_skip_to_final(
    ctx: _AgentContext, _branch: BranchDecision
) -> tuple[bool, AgentState, str | None] | None:
    """Apply skip_to_final: skip intermediate subtasks, jump to synthesis.

    Finds the final_answer/synthesis subtask and jumps to it, skipping all
    intermediate scan subtasks. If no final_answer subtask exists, synthesizes
    from completed results and returns CRITIC state.
    Returns None if the caller should continue normal advancement (jumped to
    final_answer subtask), or a (handled, state, output) tuple if synthesizing.
    """
    from .._dag_emitter import emit_subtask_transition

    _final_idx = None
    for i in range(ctx.current_subtask_idx, len(ctx.subtasks)):
        if "final_answer" in str(ctx.subtasks[i].get("description", "")).lower():
            _final_idx = i
            break

    if _final_idx is not None:
        _skipped = 0
        for st in ctx.subtasks[ctx.current_subtask_idx : _final_idx]:
            st["status"] = "skipped"
            st["result"] = f"[SKIPPED by branch rule] {_branch.reason}"
            ctx._task_results[str(st.get("id", "?"))] = st["result"]
            await emit_subtask_transition(ctx, str(st.get("id", "?")), "pending", "skipped")
            _skipped += 1
        ctx.current_subtask_idx = _final_idx
        logger.info(
            "[BRANCH-RULES] Skip-to-final: %s. Skipped %d intermediate subtasks, jumping to synthesis.",
            _branch.reason,
            _skipped,
        )
        return None  # caller continues to final_answer subtask

    # No final_answer subtask — synthesize from what we have
    _skipped = 0
    for st in ctx.subtasks[ctx.current_subtask_idx :]:
        st["status"] = "skipped"
        st["result"] = f"[SKIPPED by branch rule] {_branch.reason}"
        ctx._task_results[str(st.get("id", "?"))] = st["result"]
        await emit_subtask_transition(ctx, str(st.get("id", "?")), "pending", "skipped")
        _skipped += 1
    logger.info(
        "[BRANCH-RULES] Skip-to-final (no synthesis subtask): %s. Skipped %d remaining.",
        _branch.reason,
        _skipped,
    )
    results = [s["result"] for s in ctx.subtasks if s.get("status") == "done"]
    ctx.draft_answer = await _synthesize_results(ctx.user_question, results, ctx.engine, tools_used=ctx._tools_used)
    return True, AgentState.CRITIC, None
