r"""Interceptor Pattern tests — final_answer mid-DAG forces continuation.

Run:  .venv\Scripts\python.exe -m pytest tests/test_interceptor.py -v -s
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._executor import _node_execute


async def test_interceptor_blocks_premature_final_answer():
    """final_answer at subtask 0/3 → interceptor forces continuation to subtask 1."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "scan_lan"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "Scan network", "status": "pending"},
        {"id": "T2", "description": "Analyze results", "status": "pending"},
        {"id": "T3", "description": "Make report", "status": "pending"},
    ]
    ctx.current_subtask_idx = 0

    # Simulate LLM calling final_answer at T1 (premature)
    async def fake_agent_step(msgs, **kw):
        return type(
            "FakeMsg",
            (),
            {
                "content": '{"thought":"done","tool_calls":[{"name":"final_answer","arguments":{"text":"partial result"}}]}'
            },
        )()

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    s, _ = await _node_execute(ctx)

    # Should NOT finalize — should continue to next subtask
    assert s == AgentState.EXECUTE
    # 1st premature attempt: interceptor blocks but does NOT advance pointer.
    # Pointer only advances after 3 escalations or real tool data.
    assert ctx.current_subtask_idx == 0
    assert ctx._premature_fa_count == 1

    # Check interceptor block message in context
    last_msg = ctx.messages[-1]["content"]
    assert "SYSTEM BLOCK" in last_msg
    assert "REJECTED" in last_msg
    print("PASS: interceptor blocks premature final_answer, nudges with BLOCK message")


async def test_interceptor_allows_real_final_answer():
    """final_answer at LAST subtask with tool data → allowed to pass through."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "Task 1", "status": "pending"},
    ]
    ctx.current_subtask_idx = 0
    # Simulate that a tool was already executed (tool data present)
    ctx._last_raw_tool_result = "real tool output data here"
    ctx._tools_used.append({"name": "scan_lan"})
    ctx._subtask_tool_count = 1  # per-subtask counter (new field)

    async def fake_agent_step(msgs, **kw):
        return type(
            "FakeMsg",
            (),
            {"content": '{"thought":"done","tool_calls":[{"name":"final_answer","arguments":{"text":"done"}}]}'},
        )()

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step
    ctx.engine.complete = AsyncMock(return_value="synthesis")

    s, _ = await _node_execute(ctx)

    # Last subtask with tool data → CRITIC (review before finalize)
    assert s == AgentState.CRITIC
    print("PASS: real final_answer at last subtask → CRITIC")


def run_all():
    asyncio.run(test_interceptor_blocks_premature_final_answer())
    asyncio.run(test_interceptor_allows_real_final_answer())
    print("\n=== ALL INTERCEPTOR TESTS PASSED ===")


if __name__ == "__main__":
    run_all()
