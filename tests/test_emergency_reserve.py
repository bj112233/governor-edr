# tests/test_emergency_reserve.py
"""Regression: Emergency Step Reserve for critic-retry at step boundary.

Bug (bot.log 2026-06-25 16:05): Threat hunt with 8 subtasks exhausted
26/26 steps during investigation. The critic rejected the final draft
(missing_facts=8) at step 25, routing back to EXECUTE at step 26.
Step 26 = max → ERROR killed the agent before it could re-emit
THREAT_SCORE. The 1374-char synthesis (with score) was discarded.

Fix: when step_count >= max_steps AND (final subtask) AND (critic-retry
with existing draft) AND (reserve not yet used), grant +2 steps.
"""

from services.agent._agent_loop import _should_grant_emergency_reserve
from services.agent._context import AgentState, _AgentContext


def test_emergency_reserve_field_defaults_false():
    """_emergency_reserve_used must exist and default to False."""
    assert "_emergency_reserve_used" in _AgentContext.__dataclass_fields__
    ctx = _AgentContext.__new__(_AgentContext)
    # Field is declared with default False — verify via dataclass fields
    field = _AgentContext.__dataclass_fields__["_emergency_reserve_used"]
    assert field.default is False


def test_is_emergency_mode_field_defaults_false():
    """is_emergency_mode must exist and default to False."""
    assert "is_emergency_mode" in _AgentContext.__dataclass_fields__
    field = _AgentContext.__dataclass_fields__["is_emergency_mode"]
    assert field.default is False


def test_reserve_conditions_met_when_critic_retry_on_final_subtask():
    """The 3 reserve conditions must all be True in the bug scenario:
    final subtask + EXECUTE state (critic retry) + draft exists.
    """
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = [{"id": "T1"}, {"id": "T2"}, {"id": "T3"}]
    ctx.current_subtask_idx = 2  # last subtask (0-indexed)
    ctx.draft_answer = "THREAT_SCORE: 0.3 ..."  # 1374 chars in real run
    ctx._emergency_reserve_used = False

    assert _should_grant_emergency_reserve(ctx, AgentState.EXECUTE) is True


def test_reserve_conditions_not_met_mid_investigation():
    """Reserve must NOT fire during active investigation (non-final subtask)."""
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = [{"id": "T1"}, {"id": "T2"}, {"id": "T3"}]
    ctx.current_subtask_idx = 0  # first subtask — still investigating
    ctx.draft_answer = ""
    ctx._emergency_reserve_used = False

    assert _should_grant_emergency_reserve(ctx, AgentState.EXECUTE) is False


def test_reserve_conditions_not_met_without_draft():
    """Reserve must NOT fire if there's no draft to salvage."""
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = [{"id": "T1"}]
    ctx.current_subtask_idx = 0
    ctx.draft_answer = ""  # no draft — nothing to salvage
    ctx._emergency_reserve_used = False

    assert _should_grant_emergency_reserve(ctx, AgentState.EXECUTE) is False


def test_reserve_conditions_not_met_in_planner_state():
    """Reserve must NOT fire in PLANNER state (not a critic retry)."""
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = [{"id": "T1"}]
    ctx.current_subtask_idx = 0
    ctx.draft_answer = "some draft"
    ctx._emergency_reserve_used = False

    assert _should_grant_emergency_reserve(ctx, AgentState.PLANNER) is False


def test_reserve_conditions_not_met_when_already_used():
    """Reserve fires only once per session."""
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = [{"id": "T1"}]
    ctx.current_subtask_idx = 0
    ctx.draft_answer = "draft"
    ctx._emergency_reserve_used = True  # already consumed

    assert _should_grant_emergency_reserve(ctx, AgentState.EXECUTE) is False


def test_reserve_conditions_met_for_single_task_no_subtasks():
    """Single-task (no DAG) with draft + EXECUTE → reserve eligible."""
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.subtasks = []  # no DAG — direct task
    ctx.draft_answer = "answer with THREAT_SCORE: 0.5"
    ctx._emergency_reserve_used = False

    assert _should_grant_emergency_reserve(ctx, AgentState.EXECUTE) is True


if __name__ == "__main__":
    test_emergency_reserve_field_defaults_false()
    test_reserve_conditions_met_when_critic_retry_on_final_subtask()
    test_reserve_conditions_not_met_mid_investigation()
    test_reserve_conditions_not_met_without_draft()
    test_reserve_conditions_not_met_in_planner_state()
    test_reserve_conditions_not_met_when_already_used()
    test_reserve_conditions_met_for_single_task_no_subtasks()
    print("OK")
