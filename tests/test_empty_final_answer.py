# tests/test_empty_final_answer.py
"""Regression tests for empty final_answer handling.

Bug: model called `Action: final_answer` without `Action Input` (empty args).
_resolve_final_text fell back to raw tool data from buffer → user got raw
data instead of synthesized answer.

Fix: handle_final_answer now detects empty text arg, nudges model twice to
synthesize before falling back to raw data.
"""

import pytest

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes.task_completion import handle_final_answer


def _make_ctx(step_count=2, has_tool_data=True):
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.step_count = step_count
    ctx.subtasks = []
    ctx.current_subtask_idx = -1
    ctx._last_raw_tool_result = "CPU: 6%, RAM: 40%" if has_tool_data else ""
    ctx._tools_used = [{"name": "get_system_snapshot"}] if has_tool_data else []
    ctx._tool_outputs_buffer = [{"name": "get_system_snapshot", "result": "CPU: 6%"}] if has_tool_data else []
    ctx._premature_fa_count = 0
    ctx._empty_fa_nudge_count = 0
    ctx.active_tools = []
    ctx.messages = []
    ctx.draft_answer = ""
    ctx.user_question = "נתח את המערכת"
    ctx._degraded_mode = False
    return ctx


@pytest.mark.asyncio
async def test_empty_final_answer_nudges_when_tool_data_exists():
    """Empty final_answer with tool data → nudge (EXECUTE), not raw data fallback."""
    ctx = _make_ctx(step_count=2, has_tool_data=True)
    handled, next_state, output = await handle_final_answer(ctx, {})
    assert handled is True
    assert next_state == AgentState.EXECUTE
    assert output is None
    assert ctx._empty_fa_nudge_count == 1
    assert len(ctx.messages) == 1  # nudge injected
    assert "internal planning was NOT the final answer" in ctx.messages[0]["content"]
    assert "Encoded Commands" in ctx.messages[0]["content"]
    assert "Execution Policy Bypass" in ctx.messages[0]["content"]


@pytest.mark.asyncio
async def test_empty_final_answer_nudges_twice_before_fallback():
    """Second empty final_answer → one more nudge, not raw data fallback yet."""
    ctx = _make_ctx(step_count=2, has_tool_data=True)
    ctx._empty_fa_nudge_count = 1  # already nudged once
    handled, next_state, output = await handle_final_answer(ctx, {})
    assert handled is True
    assert next_state == AgentState.EXECUTE
    assert output is None
    assert ctx._empty_fa_nudge_count == 2
    assert ctx.draft_answer == ""


@pytest.mark.asyncio
async def test_empty_final_answer_falls_back_after_two_nudges():
    """Third empty final_answer → falls back to raw data (no infinite loop)."""
    ctx = _make_ctx(step_count=2, has_tool_data=True)
    ctx._empty_fa_nudge_count = 2  # already nudged twice
    handled, next_state, output = await handle_final_answer(ctx, {})
    assert handled is True
    assert next_state == AgentState.CRITIC
    assert "CPU" in ctx.draft_answer  # raw data fallback


@pytest.mark.asyncio
async def test_empty_final_answer_no_tool_data_falls_back():
    """Empty final_answer with no tool data → no nudge, immediate fallback."""
    ctx = _make_ctx(step_count=2, has_tool_data=False)
    handled, next_state, output = await handle_final_answer(ctx, {})
    assert handled is True
    assert ctx._empty_fa_nudge_count == 0  # no nudge when no data


@pytest.mark.asyncio
async def test_non_empty_final_answer_skips_nudge():
    """final_answer with text → normal flow, no nudge."""
    ctx = _make_ctx(step_count=2, has_tool_data=True)
    handled, next_state, output = await handle_final_answer(ctx, {"text": "דוח מערכת מלא"})
    assert handled is True
    assert next_state == AgentState.CRITIC
    assert ctx.draft_answer == "דוח מערכת מלא"
    assert ctx._empty_fa_nudge_count == 0
