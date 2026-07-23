r"""Smoke tests for Self-Healing Circuit Breaker (Tool Fallback + DAG Mutation + Degradation).

Run:  .venv\Scripts\python.exe -m pytest tests/test_self_healing_circuit_breaker.py -v -s
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._helpers import _build_recovery_task
from services.agent._nodes._executor import _node_execute


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


async def test_blocked_tool_prevents_reuse():
    """Tool in ctx._blocked_tools → rejected before execution."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": "skill_intel-skill"}}]
    ctx._blocked_tools = {"skill_intel-skill"}

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call("skill_intel-skill", {"command": "sweep"}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    # ResourceGuard may append a stress message after the blocked-tool message,
    # displacing it from messages[-1]. Force "ok" so the blocked message stays last.
    with patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")):
        s, _ = await _node_execute(ctx)

    # Blocked tool → continue to next tick (EXECUTE) since no tool executed
    assert s == AgentState.EXECUTE
    # Verify dynamic replan message was injected (Sprint 6: no static fallback)
    last_msg = ctx.messages[-1]
    assert "BLOCKED" in last_msg["content"]
    assert "REPLAN" in last_msg["content"]
    print("PASS: blocked tool prevents reuse")


async def test_circuit_breaker_injects_recovery_task():
    """Tool fails 2x → circuit breaker trips → recovery task injected, dependents blocked."""
    ctx = _AgentContext(user_question="scan and report", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan and report"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "skill_intel-skill"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "scan network", "status": "pending"},
        {"id": "T2", "description": "analyze results", "status": "pending", "depends_on": ["T1"]},
    ]
    ctx.current_subtask_idx = 0
    ctx._consecutive_tool_failures = 2  # Pre-set to trigger circuit breaker

    # Patch _execute_tool to return error (simulating 2nd failure).
    # _execute_tool lives in _executor_phases (SRP refactor); ResourceGuard must
    # permit so the heavy tool isn't filtered out before execution.
    with (
        patch("services.agent._nodes._executor_phases._execute_tool") as mock_tool,
        patch("services.agent.resource_guard.ResourceGuard.check", return_value=(True, "ok")),
    ):
        mock_tool.return_value = "❌ Tool execution failed: timeout"

        async def fake_agent_step(msgs, **kw):
            return FakeMsg(_tool_call("skill_intel-skill", {"command": "sweep"}))

        ctx.engine = AsyncMock()
        ctx.engine.agent_step = fake_agent_step

        s, _ = await _node_execute(ctx)

    # Verify circuit breaker effects
    assert "skill_intel-skill" in ctx._blocked_tools
    assert ctx.subtasks[0]["status"] == "failed"
    assert "T2" in ctx._blocked_by_failure

    # Verify recovery task was injected at position 1 (T2 pushed to position 2)
    assert ctx.subtasks[1]["id"] == "T1_recovery"
    assert ctx.subtasks[1]["depends_on"] == []
    assert ctx.subtasks[2]["status"] == "blocked"
    print("PASS: circuit breaker injects recovery task and blocks dependents")


async def test_blocked_task_skipped():
    """Blocked task reached → skipped immediately, result = error message."""
    ctx = _AgentContext(user_question="scan and report", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan and report"},
    ]
    ctx.active_tools = [
        {"type": "function", "function": {"name": "skill_intel-skill"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    ctx.subtasks = [
        {"id": "T1", "description": "scan network", "status": "done", "result": "scan ok"},
        {"id": "T2", "description": "analyze results", "status": "blocked", "error": "Blocked by failed T1"},
    ]
    ctx.current_subtask_idx = 1

    async def fake_agent_step(msgs, **kw):
        return FakeMsg(_tool_call("final_answer", {"text": "done"}))

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    # Mock _synthesize_results to avoid async complexity.
    # _synthesize_results is called from state_manager (SRP refactor).
    with patch("services.agent._nodes.state_manager._synthesize_results") as mock_synth:
        mock_synth.return_value = "Done (with blocked tasks)"
        s, _ = await _node_execute(ctx)

    assert s == AgentState.CRITIC  # All subtasks done → synthesize → CRITIC (not FINALIZE)
    assert ctx.subtasks[1]["result"] == "Blocked by failed T1"
    assert "T2" in ctx._task_results
    print("PASS: blocked task skipped without LLM call")


async def test_build_recovery_task_unit():
    """_build_recovery_task returns in-degree 0 recovery subtask with dynamic error msg."""
    task = _build_recovery_task("T1", "skill_intel-skill", "timeout error", "scan network")
    assert task["id"] == "T1_recovery"
    assert task["depends_on"] == []
    assert "timeout error" in task["description"]
    assert "skill_intel-skill" in task["description"]
    assert "DIFFERENT" in task["description"]
    print("PASS: _build_recovery_task unit")


async def test_graceful_degradation_flag():
    """_degraded_mode flag on context → can be set/read."""
    ctx = _AgentContext(user_question="test")
    assert ctx._degraded_mode is False

    ctx._degraded_mode = True
    assert ctx._degraded_mode is True
    print("PASS: graceful degradation flag on context")


def test_alert_emoji_not_treated_as_error():
    """🚨-prefixed ALERT content (e.g. firewall 'drops') must NOT be a tool error.

    Bug (bot.log 2026-06-25 20:51): firewall 'drops' succeeded and returned
    "🚨 20 אירועי DROP אחרונים:" but the circuit breaker treated leading 🚨 as an
    error prefix → false UNKNOWN_ERROR crash-lesson → tool penalized + replan churn.
    """
    from services.agent._nodes.circuit_breaker import _is_error_result

    assert _is_error_result("🚨 20 אירועי DROP אחרונים:\n...") is False
    assert _is_error_result("🚨 NEUTRALIZED 🚨") is False
    # Real crash marker MUST still be detected.
    assert _is_error_result("🚨 [SYSTEM CRASH] Tool 'x' failed: TypeError") is True
    # Other genuine error prefixes unaffected.
    assert _is_error_result("❌ Command failed") is True
    assert _is_error_result("⏱️ Timeout") is True
    assert _is_error_result("clean result") is False


def run_all():
    asyncio.run(test_blocked_tool_prevents_reuse())
    asyncio.run(test_circuit_breaker_injects_recovery_task())
    asyncio.run(test_blocked_task_skipped())
    asyncio.run(test_build_recovery_task_unit())
    asyncio.run(test_graceful_degradation_flag())
    test_alert_emoji_not_treated_as_error()
    print("\n=== ALL SELF-HEALING TESTS PASSED ===")


if __name__ == "__main__":
    run_all()
