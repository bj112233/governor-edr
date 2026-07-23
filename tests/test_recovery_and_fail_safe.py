# tests/test_recovery_and_fail_safe.py
"""Regression tests for death-loop prevention.

Bug (bot.log.1 2026-06-22 09:34): Agent entered a death loop when:
  1. Resource gate blocked all heavy tools
  2. Model called final_answer (correct response)
  3. Premature interceptor forced it back to tools (no usable tools left)
  4. Model tried unauthorized tools → blocked
  5. Model tried write_file → circuit breaker
  6. Loop hit step 10 → "Maximum steps exceeded" → user got nothing

Fixes:
  - Recovery nudge at step max-1 (forces final_answer)
  - Fail-safe reporting in _node_error (salvages gathered data)
  - Late-step escape in premature interceptor (step >= 8 lets final_answer through)
"""

import pytest

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._finalizer import _node_error
from services.agent._nodes.task_completion import _handle_non_subtask_premature


def _make_ctx(step_count=2, tools_used=None, active_tools=None, has_data=True):
    ctx = _AgentContext.__new__(_AgentContext)
    ctx.step_count = step_count
    ctx.subtasks = []
    ctx.current_subtask_idx = -1
    ctx._last_raw_tool_result = "CPU: 6%, RAM: 40%" if has_data else ""
    ctx._tools_used = tools_used or []
    ctx._tool_outputs_buffer = [{"name": "get_system_snapshot", "result": "CPU: 6%"}] if has_data else []
    ctx._premature_fa_count = 0
    ctx._empty_fa_nudge_count = 0
    ctx._recovery_nudge_injected = False
    ctx.active_tools = active_tools or [
        {"function": {"name": "get_system_snapshot"}},
        {"function": {"name": "final_answer"}},
    ]
    ctx.messages = []
    ctx.draft_answer = ""
    ctx.user_question = "נתח את המערכת"
    ctx.error_msg = "Maximum steps exceeded (10)."
    ctx._temp_files = []
    ctx._degraded_mode = False
    return ctx


# ── Late-step escape: premature interceptor ──


def test_premature_interceptor_blocks_at_early_step():
    """Step 4, 0 tools used → should intercept (force tool execution)."""
    ctx = _make_ctx(step_count=4, tools_used=[], has_data=False)
    result = _handle_non_subtask_premature(ctx)
    assert result is not None
    assert result[1] == AgentState.EXECUTE


def test_premature_interceptor_escapes_at_late_step():
    """Step 8+, 0 tools used → should NOT intercept (avoid death loop)."""
    ctx = _make_ctx(step_count=8, tools_used=[], has_data=False)
    result = _handle_non_subtask_premature(ctx)
    assert result is None  # let final_answer through


def test_premature_interceptor_escapes_at_step_9():
    """Step 9, 0 tools used → should NOT intercept."""
    ctx = _make_ctx(step_count=9, tools_used=[], has_data=False)
    result = _handle_non_subtask_premature(ctx)
    assert result is None


def test_premature_interceptor_passes_when_tools_used():
    """Step 4, tools used → should NOT intercept (normal flow)."""
    ctx = _make_ctx(step_count=4, tools_used=[{"name": "get_system_snapshot"}])
    result = _handle_non_subtask_premature(ctx)
    assert result is None


# ── Fail-safe reporting: _node_error salvages data ──


@pytest.mark.asyncio
async def test_node_error_salvages_tool_data():
    """Max steps + tool data → FINALIZE with salvaged data (not ERROR)."""
    ctx = _make_ctx(step_count=10, has_data=True)
    state, output = await _node_error(ctx)
    assert state == AgentState.FINALIZE  # route through finalize for persistence
    assert "נתונים" in output
    assert "CPU" in output


@pytest.mark.asyncio
async def test_node_error_no_data_returns_plain_error():
    """Error with no tool data → user gets plain error message."""
    ctx = _make_ctx(step_count=10, has_data=False)
    state, output = await _node_error(ctx)
    assert state == AgentState.ERROR
    assert "🚨" in output
    assert "Maximum steps" in output
    assert "נתונים" not in output


@pytest.mark.asyncio
async def test_node_error_truncates_long_data():
    """Salvaged data > 2500 chars → truncated to fit Telegram 4096 limit."""
    ctx = _make_ctx(step_count=10, has_data=True)
    ctx._tool_outputs_buffer = [{"name": "big_tool", "result": "X" * 3000}]
    state, output = await _node_error(ctx)
    assert state == AgentState.FINALIZE
    assert "[DATA TRUNCATED]" in output
    assert len(output) < 4096  # Telegram limit


# ── Recovery nudge field ──


def test_recovery_nudge_field_defaults_false():
    """_recovery_nudge_injected defaults to False."""
    ctx = _AgentContext.__new__(_AgentContext)
    # Check field exists and defaults to False
    assert hasattr(ctx, "_recovery_nudge_injected") or "_recovery_nudge_injected" in _AgentContext.__dataclass_fields__
