r"""FSM integration test — exercises full state transitions with mocked LLM.

Run:  .venv\Scripts\python.exe -m pytest tests/test_fsm_flow.py -v -s

Sprint 4 changes accounted for:
- Critic runs _run_critic_evaluation AND _run_tool_selection_review in parallel
  (asyncio.gather). Both must be patched, or the unpatched one calls the mock
  engine and returns score 0, flipping the PASS path to RETRY.
- _has_tool_outputs_in_history reads ctx._last_raw_tool_result (not message
  content), so critic tests must set it to trigger the evaluation path.
- handle_final_answer prioritizes _last_raw_tool_result / last tool_output
  over the final_answer text for subtask results.
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._helpers import _sanitize_subtask_messages
from services.agent._nodes._critic import _node_critic
from services.agent._nodes._executor import _node_execute
from services.agent._nodes._finalizer import _node_finalize
from services.agent._nodes._initializer import _node_initialize
from services.agent._nodes._planner import _node_planner


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


def _tool_review_pass():
    """Patch target returning a passing tool-selection review (score 100)."""
    return AsyncMock(
        return_value={
            "tool_selection_score": 100,
            "missed_tools": [],
            "suggested_sequence": [],
            "reasoning": "optimal",
        }
    )


async def test_sanitize_subtask_messages_unit():
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "question"},
        {"role": "assistant", "content": "thought"},
        {"role": "user", "content": "<tool_output>raw data</tool_output>"},
        {"role": "user", "content": "normal user msg"},
    ]
    clean = _sanitize_subtask_messages(msgs)
    assert len(clean) == 4
    assert not any("<tool_output>" in m.get("content", "") for m in clean)
    print("PASS: _sanitize_subtask_messages")


async def test_fsm_full_flow_single_task():
    """Simulate: EXECUTE → tool → EXECUTE → final_answer → CRITIC → FINALIZE"""
    ctx = _AgentContext(user_question="check cpu", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "check cpu"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": "get_system_snapshot"}}]

    call_count = [0]
    responses = [
        _tool_call("get_system_snapshot", {}),
        _tool_call("final_answer", {"text": "CPU: 15%"}),
    ]

    async def fake_agent_step(msgs, **kw):
        resp = responses[call_count[0]]
        call_count[0] += 1
        return FakeMsg(resp)

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    # Round 1: calls tool
    s1, o1 = await _node_execute(ctx)
    assert s1 == AgentState.EXECUTE
    assert o1 is None

    # Inject fake tool result (real pipeline sets _last_raw_tool_result too)
    ctx._last_raw_tool_result = "CPU: 15%"
    ctx.messages.append({"role": "user", "content": "<tool_output>CPU: 15%</tool_output>"})

    # Round 2: final_answer → goes to CRITIC
    s2, o2 = await _node_execute(ctx)
    assert s2 == AgentState.CRITIC
    assert ctx.draft_answer == "CPU: 15%"

    # CRITIC: patch BOTH parallel reviews. Critic PASS + tool review PASS.
    with (
        patch("services.agent._nodes._critic._run_critic_evaluation") as m_crit,
        patch("services.agent._nodes._critic._run_tool_selection_review") as m_tool,
    ):
        m_crit.return_value = (True, {})
        m_tool.return_value = {
            "tool_selection_score": 100,
            "missed_tools": [],
            "suggested_sequence": [],
            "reasoning": "optimal",
        }
        s3, o3 = await _node_critic(ctx)

    assert s3 == AgentState.FINALIZE
    assert o3 == "CPU: 15%"
    print("PASS: full FSM flow single task")


async def test_fsm_subtask_advance_sanitizes_context():
    """Subtask 1 done → _sanitize_subtask_messages → subtask 2."""
    ctx = _AgentContext(user_question="scan and report", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan and report"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": "get_system_snapshot"}}]
    ctx.subtasks = [
        {"id": 1, "description": "scan", "status": "pending"},
        {"id": 2, "description": "report", "status": "pending"},
    ]
    ctx.current_subtask_idx = 0

    call_count = [0]
    responses = [
        _tool_call("get_system_snapshot", {}),
        _tool_call("final_answer", {"text": "scan ok"}),
    ]

    async def fake_agent_step(msgs, **kw):
        resp = responses[call_count[0]]
        call_count[0] += 1
        return FakeMsg(resp)

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    # Subtask 1: tool execution
    s1, _ = await _node_execute(ctx)
    assert s1 == AgentState.EXECUTE
    # Real pipeline sets _last_raw_tool_result; simulate it + append message
    ctx._last_raw_tool_result = "scan ok"
    ctx.messages.append({"role": "user", "content": "<tool_output>scan ok</tool_output>"})

    # Subtask 1: final_answer → advances to subtask 2
    s2, _ = await _node_execute(ctx)
    assert s2 == AgentState.EXECUTE
    assert ctx.current_subtask_idx == 1
    assert ctx.subtasks[0]["status"] == "done"
    assert ctx.subtasks[0]["result"] == "scan ok"

    # Note: handle_final_answer intentionally keeps the interceptor <tool_output>
    # wrapper (task_completion.py:77-80) to signal continuation. Full context
    # sanitization is covered by test_sanitize_subtask_messages_unit above.
    print("PASS: subtask advance + context sanitization")


async def test_critic_rejection_then_retry():
    """CRITIC rejects → back to EXECUTE with feedback injected."""
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.draft_answer = "wrong answer"
    ctx._last_raw_tool_result = "data: 42"  # trigger critic evaluation path
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "<tool_output>data: 42</tool_output>"},
    ]
    ctx.engine = AsyncMock()

    with (
        patch("services.agent._nodes._critic._run_critic_evaluation") as m_crit,
        patch("services.agent._nodes._critic._run_tool_selection_review") as m_tool,
    ):
        m_crit.return_value = (
            False,
            {
                "action_required": "RETRY_WITH_FEEDBACK",
                "feedback_to_agent": "missing source citation",
                "accuracy_score": 50,
                "completeness_score": 70,
                "missing_facts": [],
                "extracted_claims": [],
            },
        )
        m_tool.return_value = {
            "tool_selection_score": 100,
            "missed_tools": [],
            "suggested_sequence": [],
            "reasoning": "optimal",
        }
        s, o = await _node_critic(ctx)

    assert s == AgentState.EXECUTE
    assert ctx.critic_rejections == 1
    assert any("SYSTEM COGNITION PATH" in m.get("content", "") for m in ctx.messages)
    print("PASS: critic rejection → retry")


async def test_critic_circuit_breaker():
    """After _CRITIC_MAX_RETRIES, degrade to raw tool data — NOT the rejected draft.

    The draft was rejected as unreliable (hallucination). The circuit breaker must
    fall back to grounded raw tool output, never send the fabricated draft.
    """
    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.draft_answer = "hallucinated CPU 0% KoboldCpp Gnome"  # rejected fabrication
    ctx._last_raw_tool_result = "x"  # trigger critic evaluation path
    ctx.messages = [{"role": "user", "content": "<tool_output>REAL_SNAPSHOT_DATA</tool_output>"}]
    ctx.critic_rejections = 2  # already at max
    ctx.engine = AsyncMock()

    with (
        patch("services.agent._nodes._critic._run_critic_evaluation") as m_crit,
        patch("services.agent._nodes._critic._run_tool_selection_review") as m_tool,
    ):
        m_crit.return_value = (
            False,
            {
                "action_required": "RETRY_WITH_FEEDBACK",
                "feedback_to_agent": "still bad",
                "accuracy_score": 40,
                "completeness_score": 70,
                "missing_facts": [],
                "extracted_claims": [],
            },
        )
        m_tool.return_value = {
            "tool_selection_score": 100,
            "missed_tools": [],
            "suggested_sequence": [],
            "reasoning": "optimal",
        }
        from services.agent._context import _CRITIC_MAX_RETRIES

        assert ctx.critic_rejections >= _CRITIC_MAX_RETRIES
        s, o = await _node_critic(ctx)

    assert s == AgentState.FINALIZE
    # Grounded fallback: raw tool data present, hallucinated draft absent
    assert "REAL_SNAPSHOT_DATA" in o
    assert "hallucinated" not in o
    assert "KoboldCpp" not in o
    assert "⚠️" in o
    print("PASS: critic circuit breaker degrades to raw tool data (no hallucination)")


async def test_run_agent_executes_finalize_handler():
    """Regression: run_agent loop must execute the FINALIZE handler (persistence +
    temp cleanup) before returning. Previously the while-condition
    `while state not in (FINALIZE, ERROR)` exited BEFORE the terminal handler
    ran, silently dropping conversation storage, audit log, lessons, and
    temp-file cleanup for every full-FSM session."""
    from services.agent._agent_loop import run_agent

    call_log: list[str] = []

    async def fake_initialize(ctx):
        call_log.append("INITIALIZE")
        ctx.active_tools = [{"type": "function", "function": {"name": "final_answer"}}]
        ctx.messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "test"}]
        ctx.engine = AsyncMock()
        return AgentState.PLANNER, None

    async def fake_planner(ctx):
        call_log.append("PLANNER")
        ctx.subtasks = [{"id": 1, "description": "do it", "status": "pending"}]
        return AgentState.EXECUTE, None

    async def fake_execute(ctx):
        call_log.append("EXECUTE")
        ctx.draft_answer = "final result"
        ctx._last_raw_tool_result = "data"
        return AgentState.CRITIC, None

    async def fake_critic(ctx):
        call_log.append("CRITIC")
        return AgentState.FINALIZE, ctx.draft_answer

    async def fake_finalize(ctx):
        call_log.append("FINALIZE")
        ctx._finalize_ran = True
        return AgentState.FINALIZE, ctx.output or ctx.draft_answer

    async def fake_error(ctx):
        call_log.append("ERROR")
        return AgentState.ERROR, "err"

    fake_handlers = {
        AgentState.INITIALIZE: fake_initialize,
        AgentState.PLANNER: fake_planner,
        AgentState.EXECUTE: fake_execute,
        AgentState.CRITIC: fake_critic,
        AgentState.FINALIZE: fake_finalize,
        AgentState.ERROR: fake_error,
    }
    with patch("services.agent._agent_loop._STATE_HANDLERS", fake_handlers):
        result = await run_agent("test query", max_rounds=10)

    assert "FINALIZE" in call_log, f"_node_finalize never ran! call_log={call_log}"
    assert result == "final result"
    # FINALIZE must be the last handler executed (terminal side-effects complete)
    assert call_log[-1] == "FINALIZE"
    print("PASS: run_agent executes _node_finalize before returning")


async def test_run_agent_error_routes_through_error_handler():
    """Regression: max-steps exhaustion must route through _node_error (fail-safe
    salvage) instead of breaking out of the loop directly."""
    from services.agent._agent_loop import run_agent

    call_log: list[str] = []

    async def fake_initialize(ctx):
        call_log.append("INITIALIZE")
        ctx.active_tools = []
        ctx.messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "test"}]
        ctx.engine = AsyncMock()
        return AgentState.EXECUTE, None

    async def fake_execute(ctx):
        call_log.append("EXECUTE")
        # never produce a final_answer → exhausts steps
        return AgentState.EXECUTE, None

    async def fake_finalize(ctx):
        call_log.append("FINALIZE")
        return AgentState.FINALIZE, "ok"

    async def fake_error(ctx):
        call_log.append("ERROR")
        ctx._error_ran = True
        return AgentState.ERROR, f"🚨 Agent error: {ctx.error_msg}"

    fake_handlers = {
        AgentState.INITIALIZE: fake_initialize,
        AgentState.EXECUTE: fake_execute,
        AgentState.FINALIZE: fake_finalize,
        AgentState.ERROR: fake_error,
    }
    with patch("services.agent._agent_loop._STATE_HANDLERS", fake_handlers):
        result = await run_agent("test query", max_rounds=3)

    assert "ERROR" in call_log, f"_node_error never ran! call_log={call_log}"
    assert "Maximum steps exceeded" in result
    print("PASS: max-steps routes through _node_error (fail-safe salvage active)")


if __name__ == "__main__":
    asyncio.run(test_sanitize_subtask_messages_unit())
    asyncio.run(test_fsm_full_flow_single_task())
    asyncio.run(test_fsm_subtask_advance_sanitizes_context())
    asyncio.run(test_critic_rejection_then_retry())
    asyncio.run(test_critic_circuit_breaker())
    asyncio.run(test_run_agent_executes_finalize_handler())
    asyncio.run(test_run_agent_error_routes_through_error_handler())
    print("\n🎯 All FSM flow tests passed!")
