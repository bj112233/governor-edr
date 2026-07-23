# tests/test_none_case_insensitive.py
"""Regression: 'None' (capital N) must auto-advance, not block.

Bug (bot.log 2026-06-25 17:14): The LLM wrote 'Action: None' (capital N)
in subtask 3/5. The executor checked fn_name == 'none' (lowercase) and
fell through to the blocking path. This caused a 10-step death-loop:
LLM says None → blocked → LLM sees error → LLM says None again.
The step budget was exhausted before reaching the synthesis subtask.

Fix: fn_name.lower() == 'none' — case-insensitive check.
"""

import asyncio

from services.agent._nodes._executor_phases import partition_tool_calls


class _FakeCtx:
    def __init__(self):
        self.subtasks = [{"id": "T1", "description": "test", "status": "pending", "result": ""}]
        self.current_subtask_idx = 0
        self._executed_history = set()
        self._loop_nudge_idx = -1
        self._task_results = {}
        self._last_raw_tool_result = ""
        self._blocked_tools = set()
        self._last_error = ""
        self.messages = []
        self.user_question = "test"
        self.engine = None
        self.state = None


def test_none_capital_auto_advances():
    """'None' (capital) should auto-advance, not block."""
    ctx = _FakeCtx()
    tool_calls = [{"name": "None", "arguments": {}}]
    _safe, _critical, _next, _out = asyncio.run(
        partition_tool_calls(ctx, tool_calls, "test thought", allowed={"final_answer"})
    )
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"


def test_none_lowercase_auto_advances():
    """'none' (lowercase) should still auto-advance."""
    ctx = _FakeCtx()
    tool_calls = [{"name": "none", "arguments": {}}]
    _safe, _critical, _next, _out = asyncio.run(
        partition_tool_calls(ctx, tool_calls, "test thought", allowed={"final_answer"})
    )
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"


def test_NONE_uppercase_auto_advances():
    """'NONE' (all caps) should auto-advance."""
    ctx = _FakeCtx()
    tool_calls = [{"name": "NONE", "arguments": {}}]
    _safe, _critical, _next, _out = asyncio.run(
        partition_tool_calls(ctx, tool_calls, "test thought", allowed={"final_answer"})
    )
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"


def test_angle_bracket_none_auto_advances():
    """'<none>' (angle brackets) should auto-advance, not block.

    Bug (bot.log 2026-06-25 20:26): the LLM wrote 'Action: <none>'. The
    executor stripped only '()' so '<none>' != 'none' and fell through to
    the blocking path, causing a 3-step no-op loop (steps 6-8).
    """
    ctx = _FakeCtx()
    tool_calls = [{"name": "<none>", "arguments": {}}]
    _safe, _critical, _next, _out = asyncio.run(
        partition_tool_calls(ctx, tool_calls, "test thought", allowed={"final_answer"})
    )
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"


def test_paren_none_auto_advances():
    """'(none)' (parentheses) should auto-advance."""
    ctx = _FakeCtx()
    tool_calls = [{"name": "(none)", "arguments": {}}]
    _safe, _critical, _next, _out = asyncio.run(
        partition_tool_calls(ctx, tool_calls, "test thought", allowed={"final_answer"})
    )
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"


if __name__ == "__main__":
    test_none_capital_auto_advances()
    test_none_lowercase_auto_advances()
    test_NONE_uppercase_auto_advances()
    test_angle_bracket_none_auto_advances()
    test_paren_none_auto_advances()
    print("OK")
