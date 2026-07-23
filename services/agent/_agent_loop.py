"""Agent execution orchestrator: ReAct loop with explicit FSM routing."""

import asyncio
import logging

import openai
from aiogram.fsm.context import FSMContext

from config import LLM_TIMEOUT

from ._context import AgentState, _AgentContext
from ._state_handlers import _STATE_HANDLERS

logger = logging.getLogger(__name__)

__all__ = ["run_agent"]

# ── Emergency Step Reserve ──────────────────────────────────────────────
# When the critic rejects the final draft at the step boundary, grant
# +2 steps so the LLM can correct and emit the required output format
# (e.g. THREAT_SCORE). Fires once per session, only on the final
# subtask, only on a critic-retry (EXECUTE after CRITIC rejection).
_RESERVE_STEPS = 2


def _should_grant_emergency_reserve(ctx: _AgentContext, current_state: AgentState) -> bool:
    """Return True if the 3 reserve conditions are all met."""
    is_final_subtask = not ctx.subtasks or ctx.current_subtask_idx >= len(ctx.subtasks) - 1
    is_critic_retry = current_state == AgentState.EXECUTE and bool(ctx.draft_answer)
    return is_final_subtask and is_critic_retry and not ctx._emergency_reserve_used


def _check_step_budget(ctx: _AgentContext, current_state: AgentState) -> AgentState | None:
    """Check step budget; return new state if budget exceeded, else None.

    Grants emergency reserve if conditions met, else routes to ERROR.
    """
    if ctx.step_count < ctx.max_steps:
        return None
    if _should_grant_emergency_reserve(ctx, current_state):
        ctx._emergency_reserve_used = True
        ctx.is_emergency_mode = True
        ctx.max_steps += _RESERVE_STEPS
        logger.warning(
            "[AGENT-FSM] 🛡️ Emergency reserve: +%d steps granted at "
            "step %d (critic retry on final subtask, draft=%d chars). "
            "Tool action space locked to final_answer only.",
            _RESERVE_STEPS,
            ctx.step_count,
            len(ctx.draft_answer),
        )
        ctx.messages.append(
            {
                "role": "system",
                "content": (
                    "⚠️ SYSTEM OVERRIDE: EMERGENCY BUDGET ACTIVE. "
                    "You are strictly FORBIDDEN from using any tool except 'final_answer'. "
                    "Synthesize the final report IMMEDIATELY using only currently available data. "
                    "You MUST include <SCORE>0.X</SCORE> at the end (0.0=safe, 1.0=critical)."
                ),
            }
        )
        return None
    ctx.error_msg = f"Maximum steps exceeded ({ctx.max_steps})."
    return AgentState.ERROR


def _inject_recovery_nudge(ctx: _AgentContext) -> None:
    """Inject recovery nudge at step max-1 to force final_answer synthesis."""
    if ctx.step_count != ctx.max_steps - 1 or ctx._recovery_nudge_injected:
        return
    ctx._recovery_nudge_injected = True
    logger.warning("[AGENT-FSM] Recovery nudge at step %d/%d — forcing final_answer.", ctx.step_count, ctx.max_steps)
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                "CRITICAL WARNING: You have 1 step left before termination. "
                "You MUST immediately call final_answer with whatever data you have collected so far. "
                "DO NOT use any other tools. Summarize your findings NOW."
            ),
        }
    )


def _check_degraded_mode(ctx: _AgentContext, current_state: AgentState) -> AgentState | None:
    """Skip planner/critic when TPOT degraded. Returns new state or None.

    SECURITY: When DEGRADED, the Critic node is skipped. The Executor
    checks ctx._degraded_mode and blocks safety_level="critical" tools
    to prevent unvalidated destructive actions (Fail-Safe, not Fail-Open).
    """
    if current_state not in (AgentState.PLANNER, AgentState.CRITIC):
        return None
    from ..llm_bridge.bridge import LLMBridge

    if not LLMBridge.get_instance().is_degraded():
        return None
    logger.warning(
        "[AGENT-FSM] DEGRADED mode — skipping %s, routing to FAST-PATH. "
        "Critical tools will be blocked in EXECUTE (Critic offline).",
        current_state.value,
    )
    ctx._degraded_mode = True
    if current_state == AgentState.PLANNER:
        return AgentState.EXECUTE
    # Critic skipped → finalize immediately (fast-path only)
    if ctx.draft_answer and not ctx.output:
        ctx.output = ctx.draft_answer
    return AgentState.FINALIZE


async def _execute_handler(
    ctx: _AgentContext,
    current_state: AgentState,
) -> tuple[AgentState, AgentState]:
    """Execute a state handler with error handling. Returns (executed_state, new_state)."""
    executed_state = current_state
    try:
        current_state, output = await _STATE_HANDLERS[current_state](ctx)
        if output is not None:
            ctx.output = output
        ctx.step_count += 1
        logger.info("[AGENT-FSM] state=%s step=%d/%d", current_state.value, ctx.step_count, ctx.max_steps)
    except openai.APIConnectionError:
        logger.error("[AGENT] Failed to connect to LLM endpoint.")
        ctx.error_msg = "Connection Error: Ensure KoboldCpp is running with a model loaded."
        current_state = AgentState.ERROR
    except (TimeoutError, openai.APITimeoutError):
        logger.error("[AGENT] Timeout waiting for LLM response.")
        ctx.error_msg = f"Agent timeout (>{LLM_TIMEOUT}s). Check GPU/RAM."
        current_state = AgentState.ERROR
    except Exception as e:
        logger.exception("[AGENT-FSM] Node %s crashed", current_state.value)
        ctx.error_msg = str(e)
        current_state = AgentState.ERROR
    return executed_state, current_state


def _run_pre_checks(ctx: _AgentContext, current_state: AgentState) -> tuple[AgentState, bool]:
    """Run pre-checks for non-terminal states. Returns (new_state, should_continue).

    If should_continue is True, the loop should `continue` with new_state.
    If False, proceed to handler execution with current_state (unchanged).
    """
    if current_state in (AgentState.FINALIZE, AgentState.ERROR):
        return current_state, False

    budget_state = _check_step_budget(ctx, current_state)
    if budget_state is not None:
        return budget_state, True

    _inject_recovery_nudge(ctx)

    degraded_state = _check_degraded_mode(ctx, current_state)
    if degraded_state is not None:
        ctx.step_count += 1
        return degraded_state, True

    return current_state, False


async def run_agent(
    user_question: str,
    max_rounds: int = 10,
    state: FSMContext | None = None,
    allow_bypasses: bool = True,
) -> str:
    """
    Explicit FSM agent loop — nodes: INITIALIZE → PLANNER → EXECUTE → CRITIC → FINALIZE.
    Each node is isolated, testable, and declares its successor via return state.

    When allow_bypasses=False, all bypass handlers are skipped — the agent
    MUST go through the full ReAct loop. Used by Threat Hunter to force
    deep investigation instead of fast-path system reports.
    """
    ctx = _AgentContext(
        user_question=user_question,
        max_steps=max_rounds,
        state=state,
        allow_bypasses=allow_bypasses,
    )
    current_state = AgentState.INITIALIZE

    while True:
        current_state, should_continue = _run_pre_checks(ctx, current_state)
        if should_continue:
            continue

        if current_state not in _STATE_HANDLERS:
            ctx.error_msg = f"Unknown state: {current_state}"
            current_state = AgentState.ERROR
            continue

        executed_state, current_state = await _execute_handler(ctx, current_state)

        # ── Exit after terminal handler completes its side effects ──
        if executed_state == AgentState.FINALIZE:
            break
        if executed_state == AgentState.ERROR and current_state == AgentState.ERROR:
            break

    return (
        ctx.output
        if current_state == AgentState.FINALIZE
        else f"🚨 Agent error: {ctx.error_msg}"
        if ctx.error_msg
        else "⚠️ Unknown agent error."
    )
