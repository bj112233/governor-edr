# tests/test_safe_tools_concurrency.py
"""Tests for global concurrency limiter on safe tool execution.

Verifies that execute_safe_calls caps parallel tool execution at
_MAX_CONCURRENT_SAFE_TOOLS (5) via asyncio.Semaphore, preventing
OS starvation when the LLM requests many tools in one ReAct tick.
"""

import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes import _executor_phases
from services.agent._nodes._executor_phases import _MAX_CONCURRENT_SAFE_TOOLS, execute_safe_calls


@pytest.fixture(autouse=True)
def _reset_semaphore():
    """Reset global semaphore between tests (event loop isolation)."""
    _executor_phases._safe_semaphore = None
    yield
    _executor_phases._safe_semaphore = None


@asynccontextmanager
async def _noop_measure(_fn):
    yield


async def test_concurrency_capped_at_max():
    """10 safe tools requested → at most _MAX_CONCURRENT_SAFE_TOOLS run at once."""
    _concurrent = 0
    _max_concurrent = 0
    _lock = asyncio.Lock()

    async def _mock_execute(fn, args):
        nonlocal _concurrent, _max_concurrent
        async with _lock:
            _concurrent += 1
            _max_concurrent = max(_max_concurrent, _concurrent)
        await asyncio.sleep(0.05)  # simulate I/O
        async with _lock:
            _concurrent -= 1
        return f"result_{fn}"

    ctx = _AgentContext(user_question="test", max_steps=10)
    safe_calls = [(f"tool_{i}", {}, f"key_{i}") for i in range(10)]

    with (
        patch("services.agent._nodes._executor_phases._execute_tool", side_effect=_mock_execute),
        patch("services.agent._nodes._executor_phases.get_telemetry") as mock_tel,
        patch("services.agent._nodes._executor_phases.maybe_inject_temp_file", side_effect=lambda c, f, a: a),
        patch("services.agent._nodes._executor_phases.handle_tool_result", new_callable=AsyncMock) as mock_htr,
        patch("services.agent._nodes._executor_phases.post_execution_pipeline", new_callable=AsyncMock),
    ):
        mock_tel.return_value.measure_tool = _noop_measure
        mock_htr.return_value = ("result", False, None, None)

        await execute_safe_calls(ctx, safe_calls)

    assert _max_concurrent <= _MAX_CONCURRENT_SAFE_TOOLS, (
        f"Concurrent tools peaked at {_max_concurrent}, expected max {_MAX_CONCURRENT_SAFE_TOOLS}"
    )


async def test_all_tools_complete():
    """All requested tools should complete despite concurrency cap."""
    _executed = []

    async def _mock_execute(fn, args):
        _executed.append(fn)
        await asyncio.sleep(0.01)
        return f"result_{fn}"

    ctx = _AgentContext(user_question="test", max_steps=10)
    safe_calls = [(f"tool_{i}", {}, f"key_{i}") for i in range(8)]

    with (
        patch("services.agent._nodes._executor_phases._execute_tool", side_effect=_mock_execute),
        patch("services.agent._nodes._executor_phases.get_telemetry") as mock_tel,
        patch("services.agent._nodes._executor_phases.maybe_inject_temp_file", side_effect=lambda c, f, a: a),
        patch("services.agent._nodes._executor_phases.handle_tool_result", new_callable=AsyncMock) as mock_htr,
        patch("services.agent._nodes._executor_phases.post_execution_pipeline", new_callable=AsyncMock),
    ):
        mock_tel.return_value.measure_tool = _noop_measure
        mock_htr.return_value = ("result", False, None, None)

        result = await execute_safe_calls(ctx, safe_calls)

    assert result is None  # No early exit
    assert len(_executed) == 8


async def test_empty_safe_calls_returns_none():
    """No safe calls → returns None immediately."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    result = await execute_safe_calls(ctx, [])
    assert result is None


async def test_single_tool_executes():
    """Single safe tool → executes normally under semaphore."""

    async def _mock_execute(fn, args):
        return f"result_{fn}"

    ctx = _AgentContext(user_question="test", max_steps=10)
    safe_calls = [("single_tool", {}, "key_0")]

    with (
        patch("services.agent._nodes._executor_phases._execute_tool", side_effect=_mock_execute),
        patch("services.agent._nodes._executor_phases.get_telemetry") as mock_tel,
        patch("services.agent._nodes._executor_phases.maybe_inject_temp_file", side_effect=lambda c, f, a: a),
        patch("services.agent._nodes._executor_phases.handle_tool_result", new_callable=AsyncMock) as mock_htr,
        patch("services.agent._nodes._executor_phases.post_execution_pipeline", new_callable=AsyncMock),
    ):
        mock_tel.return_value.measure_tool = _noop_measure
        mock_htr.return_value = ("result", False, None, None)

        result = await execute_safe_calls(ctx, safe_calls)

    assert result is None
