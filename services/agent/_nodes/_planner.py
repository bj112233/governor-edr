"""FSM Node: PLANNER — decompose task if warranted."""

import logging

from .._context import AgentState, _AgentContext
from .._helpers import _decompose_task, _should_decompose, _topological_sort

logger = logging.getLogger(__name__)


async def _node_planner(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Decompose task if warranted, then hand off to EXECUTE."""
    if ctx.active_tools and _should_decompose(ctx.user_question):
        raw_tasks = await _decompose_task(ctx.user_question, ctx.active_tools, ctx.engine)
        if len(raw_tasks) > 1:
            # SAFETY FALLBACK: DAG → linear on any validation failure
            try:
                ctx.subtasks = _topological_sort(raw_tasks)
                logger.info(
                    "[PLANNER] DAG sorted: %s",
                    [t.get("id") for t in ctx.subtasks],
                )
            except Exception as exc:
                logger.warning(
                    "[PLANNER] DAG validation failed (%s). Fallback to linear.",
                    exc,
                )
                for t in raw_tasks:
                    t.pop("depends_on", None)
                ctx.subtasks = raw_tasks

            ctx.current_subtask_idx = 0
            ctx._task_results = {}
            logger.info("[PLANNER] Multi-subtask mode: %d steps", len(ctx.subtasks))

            # ── Emit initial DAG to C2 dashboard (all nodes = pending) ──
            from .._dag_emitter import emit_dag_initial

            await emit_dag_initial(ctx)

            # ── Dynamic step allocation: scale max_steps to subtask count ──
            # Each subtask needs ≥3 steps (tool selection + execution + advance/retry).
            # +5 envelope for planner + critic + finalize + recovery nudge.
            # Hard cap 35 prevents runaway loops from planner hallucinations.
            _BASE_ROUNDS = 5
            _STEPS_PER_SUBTASK = 3
            _HARD_LIMIT = 35
            _calculated = _BASE_ROUNDS + (len(ctx.subtasks) * _STEPS_PER_SUBTASK)
            _new_max = min(_calculated, _HARD_LIMIT)
            if _new_max > ctx.max_steps:
                logger.info(
                    "[AGENT-FSM] Dynamic step allocation: scaling max_steps from %d to %d for %d subtasks.",
                    ctx.max_steps,
                    _new_max,
                    len(ctx.subtasks),
                )
                ctx.max_steps = _new_max

    return AgentState.EXECUTE, None
