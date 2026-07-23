r"""Subtask Payload Validation tests — Strict Validator for hollow outputs.

Regression: the task_completion interceptor marked subtasks "done" with
empty/apology/echo payloads, cascading hallucinations to downstream subtasks.
The validator now rejects:
  1. Empty Payload — whitespace-only or bare empty <tool_output> tags
  2. Apology Filter — "אין לי מידע", "I cannot find", etc.
  3. Echo Wrapper — <tool_output></tool_output> with no inner content

Run:  .venv\Scripts\python.exe -m pytest tests/test_subtask_payload_validation.py -v -s
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._nodes.task_completion import _validate_subtask_payload

# ── _validate_subtask_payload unit tests ────────────────────────────────────


@pytest.mark.parametrize(
    "text,expected",
    [
        # ── Empty Payload ──
        ("", False),
        ("   ", False),
        ("\n\n\t", False),
        ("<tool_output>\n</tool_output>", False),
        ("<tool_output>   </tool_output>", False),
        # ── Apology Filter (Hebrew) ──
        ("אין לי מידע על כך", False),
        ("לא מצאתי נתונים", False),
        ("איני יכול לספק מידע", False),
        ("אין ברשותי מידע על המערכת", False),
        ("לא הצלחתי למצוא תהליכים חשודים", False),
        # ── Apology Filter (English) ──
        ("I cannot find any information about this.", False),
        ("I don't have that information.", False),
        ("No data found.", False),
        ("Unable to retrieve the requested data.", False),
        # ── Real Data (should pass) ──
        ("CPU: 4.4% | RAM: 48.4% | Disk: OK", True),
        ('{"threat_score": 85, "components": {"network": 12}}', True),
        ("<tool_output>\nCPU: 4.4% | RAM: 48.4%\n</tool_output>", True),
        ("Found 3 suspicious processes: svchost.exe (PID 1234), chrome.exe (PID 5678)", True),
        ("📊 עומסי מערכת: CPU: 4% RAM: 48%", True),
        # ── Long apology with some data markers should pass ──
        ("אין לי מידע על כך, אבל הנתונים מראים CPU=4% ו-RAM=48%", True),
    ],
)
def test_validate_subtask_payload(text, expected):
    result = _validate_subtask_payload(text)
    assert result == expected, f"Expected {expected} for: {text[:80]!r}, got {result}"


# ── Integration: hollow payload routes to premature handler ─────────────────


async def test_hollow_final_answer_routes_to_premature():
    """final_answer with apology text + no per-subtask tools → premature handler."""
    from services.agent._context import AgentState, _AgentContext
    from services.agent._nodes.task_completion import handle_final_answer

    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "get_system_snapshot"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "Get system snapshot", "status": "pending"},
        {"id": "T2", "description": "Analyze", "status": "pending"},
    ]
    ctx.current_subtask_idx = 0
    ctx._subtask_tool_count = 0  # no tool used in THIS subtask

    handled, next_state, _ = await handle_final_answer(ctx, {"text": "אין לי מידע על כך"})
    assert handled is True
    assert next_state == AgentState.EXECUTE  # nudged, not advanced
    assert ctx.current_subtask_idx == 0  # still on T1
    assert ctx._premature_fa_count == 1


async def test_real_final_answer_advances_subtask():
    """final_answer with real data + per-subtask tool used → advances."""
    from services.agent._context import AgentState, _AgentContext
    from services.agent._nodes.task_completion import handle_final_answer

    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "get_system_snapshot"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "Get system snapshot", "status": "pending"},
        {"id": "T2", "description": "Analyze", "status": "pending"},
    ]
    ctx.current_subtask_idx = 0
    ctx._subtask_tool_count = 1  # tool was used in THIS subtask
    ctx._last_raw_tool_result = "CPU: 4.4% | RAM: 48.4% | Disk: OK"

    handled, next_state, _ = await handle_final_answer(ctx, {"text": "CPU: 4.4% | RAM: 48.4% | Disk: OK"})
    assert handled is True
    assert next_state == AgentState.EXECUTE  # advanced to T2
    assert ctx.current_subtask_idx == 1
    assert ctx._subtask_tool_count == 0  # reset for T2


async def test_cumulative_tools_used_does_not_leak_across_subtasks():
    """Regression: _tools_used was cumulative. Subtask 2 with no tools of its own
    but tools from subtask 1 should NOT pass the gate."""
    from services.agent._context import AgentState, _AgentContext
    from services.agent._nodes.task_completion import handle_final_answer

    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "get_process_list"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "Get snapshot", "status": "done", "result": "CPU: 4%"},
        {"id": "T2", "description": "Get processes", "status": "pending"},
    ]
    ctx.current_subtask_idx = 1  # on T2
    ctx._tools_used = [{"name": "get_system_snapshot"}]  # from T1 — cumulative
    ctx._subtask_tool_count = 0  # T2 has NOT used any tool yet
    ctx._last_raw_tool_result = ""  # no raw result for T2

    handled, next_state, _ = await handle_final_answer(ctx, {"text": "אין לי מידע על כך"})
    # Should be blocked — T2 has no tool data of its own
    assert handled is True
    assert next_state == AgentState.EXECUTE  # nudged
    assert ctx.current_subtask_idx == 1  # still on T2
    assert ctx._premature_fa_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
