# tests/test_executor_empty_tool_calls.py
"""Tests for _handle_empty_tool_calls — early-exit on empty tool_calls.

Covers lines 79-84 of _executor.py:
- step_count=0 + active_tools + no tool_calls → FINALIZE with user message
- no tool_calls (any step) → FINALIZE with error message
- tool_calls present → returns None (continue)
"""

from unittest.mock import MagicMock

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._executor import _handle_empty_tool_calls


def _make_ctx(step_count=0, active_tools=None):
    ctx = MagicMock(spec=_AgentContext)
    ctx.step_count = step_count
    ctx.active_tools = active_tools or []
    ctx.output = None
    return ctx


class TestHandleEmptyToolCalls:
    def test_step0_with_tools_no_calls_returns_user_message(self):
        """step_count=0 + active_tools + no tool_calls → FINALIZE with user message."""
        ctx = _make_ctx(step_count=0, active_tools=[{"function": {"name": "scan"}}])
        result = _handle_empty_tool_calls(ctx, [])
        assert result is not None
        state, output = result
        assert state == AgentState.FINALIZE
        assert "לא הבנתי" in output

    def test_step0_no_tools_no_calls_returns_error(self):
        """step_count=0 + no active_tools + no tool_calls → FINALIZE with error."""
        ctx = _make_ctx(step_count=0, active_tools=[])
        result = _handle_empty_tool_calls(ctx, [])
        assert result is not None
        state, output = result
        assert state == AgentState.FINALIZE
        assert "כשל במבנה" in output

    def test_step_gt0_no_calls_returns_error(self):
        """step_count > 0 + no tool_calls → FINALIZE with error."""
        ctx = _make_ctx(step_count=3, active_tools=[{"function": {"name": "scan"}}])
        result = _handle_empty_tool_calls(ctx, [])
        assert result is not None
        state, output = result
        assert state == AgentState.FINALIZE
        assert "כשל במבנה" in output

    def test_with_tool_calls_returns_none(self):
        """tool_calls present → returns None (continue execution)."""
        ctx = _make_ctx(step_count=0, active_tools=[{"function": {"name": "scan"}}])
        result = _handle_empty_tool_calls(ctx, [{"function": {"name": "scan_suspicious_procs"}}])
        assert result is None
