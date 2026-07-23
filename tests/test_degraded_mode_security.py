# tests/test_degraded_mode_security.py
"""Security tests: critical tools blocked when FSM is in DEGRADED mode.

Verifies that when ctx._degraded_mode=True (Critic offline due to high TPOT),
the executor blocks safety_level="critical" tools, closing the Fail-Open
vulnerability where prompt injection → False DEGRADED → unvalidated
destructive tool access.
"""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._executor import _node_execute
from services.tools_registry import REGISTRY, ToolSpec


class FakeMsg:
    def __init__(self, content):
        self.content = content


def _tool_call(name, args):
    return json.dumps(
        {
            "thought": f"call {name}",
            "tool_calls": [{"name": name, "arguments": args}],
        }
    )


def _find_critical_tool() -> str:
    """Find a real critical tool from REGISTRY for testing."""
    for name, spec in REGISTRY.items():
        if spec.safety_level == "critical":
            return name
    pytest.skip("No critical tools in REGISTRY")


def _find_safe_tool() -> str:
    """Find a real safe tool from REGISTRY for testing."""
    for name, spec in REGISTRY.items():
        if spec.safety_level == "safe" and name != "final_answer":
            return name
    pytest.skip("No safe tools in REGISTRY")


async def test_degraded_mode_blocks_critical_tool():
    """DEGRADED mode → critical tool call → tool NOT in _allowed_tool_names."""
    critical_tool = _find_critical_tool()
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": critical_tool}}]
    ctx._degraded_mode = True  # Simulate DEGRADED

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call(critical_tool, {}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    with patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")):
        state, output = await _node_execute(ctx)

    # Critical tool should be blocked — agent loops back to EXECUTE
    # with a "not allowed" message (from partition_tool_calls filtering)
    assert state in (AgentState.EXECUTE, AgentState.FINALIZE)
    # The tool should NOT have been executed
    assert critical_tool not in ctx._executed_history


async def test_degraded_mode_allows_safe_tool():
    """DEGRADED mode → safe tool call → tool executes normally."""
    safe_tool = _find_safe_tool()
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": safe_tool}}]
    ctx._degraded_mode = True

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call(safe_tool, {}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    with (
        patch("services.agent._nodes._executor_phases._execute_tool", return_value="ok") as mock_exec,
        patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")),
    ):
        await _node_execute(ctx)

    # Safe tool should have been executed
    mock_exec.assert_called_once()


async def test_degraded_mode_allows_final_answer():
    """DEGRADED mode → final_answer → must always be allowed."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = []
    ctx._degraded_mode = True

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call("final_answer", {"answer": "done"}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    with patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")):
        state, output = await _node_execute(ctx)

    # final_answer routes to CRITIC (FSM will skip CRITIC in DEGRADED → FINALIZE)
    assert state in (AgentState.FINALIZE, AgentState.CRITIC)


async def test_normal_mode_allows_critical_tool():
    """NORMAL mode (not DEGRADED) → critical tool → executes (with HITL if dangerous)."""
    critical_tool = _find_critical_tool()
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": critical_tool}}]
    ctx._degraded_mode = False  # Normal mode

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call(critical_tool, {}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    with (
        patch("services.agent._nodes._executor_phases._execute_tool", return_value="ok") as mock_exec,
        patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")),
    ):
        await _node_execute(ctx)

    # In normal mode, critical tool should be attempted (may hit HITL, but not blocked by DEGRADED gate)
    mock_exec.assert_called_once()
