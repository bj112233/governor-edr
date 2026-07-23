r"""Reflection tests — Tool Selection Review + Critic concurrency + executor tracking.

Run:  .venv\Scripts\python.exe -m pytest tests/test_reflection.py -v -s
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._helpers import _run_tool_selection_review
from services.agent._nodes._critic import _node_critic


async def test_tool_selection_review_no_tools():
    """Empty tools_used + actionable tools available → score 0 (penalty)."""
    result = await _run_tool_selection_review(
        original_query="scan network",
        tools_used=[],
        available_tools=[
            {"type": "function", "function": {"name": "scan_lan"}},
            {"type": "function", "function": {"name": "final_answer"}},
        ],
        engine=AsyncMock(),
    )
    assert result["tool_selection_score"] == 0
    assert "scan_lan" in result["missed_tools"]
    print("PASS: empty tools with actionable available → 0 score")


async def test_tool_selection_review_with_tools():
    """Tools used + available tools → review runs (plain-text SCORE format)."""
    engine = AsyncMock()
    engine.complete.return_value = "SCORE: 45"

    result = await _run_tool_selection_review(
        original_query="find suspicious IP",
        tools_used=[{"name": "scan_lan", "command": "", "output_summary": "5 devices"}],
        available_tools=[{"name": "scan_lan"}, {"name": "skill_intel-skill"}],
        engine=engine,
    )
    assert result["tool_selection_score"] == 45
    print("PASS: tool selection review scores correctly")


async def test_critic_parallel_reviews():
    """Critic runs both reviews in parallel via asyncio.gather."""
    ctx = _AgentContext(user_question="test")
    ctx.draft_answer = "test answer"
    ctx._tools_used = [{"name": "scan_lan", "command": "", "output_summary": "ok"}]
    ctx.active_tools = [{"name": "scan_lan"}, {"name": "skill_intel-skill"}]
    ctx._last_raw_tool_result = "data"
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "<tool_output>data</tool_output>"},
    ]

    with patch("services.agent._nodes._critic._run_critic_evaluation") as mock_eval:
        mock_eval.return_value = (
            True,
            {
                "accuracy_score": 90,
                "completeness_score": 80,
                "action_required": "PASS",
                "feedback_to_agent": "",
            },
        )
        with patch("services.agent._nodes._critic._run_tool_selection_review") as mock_review:
            mock_review.return_value = {
                "tool_selection_score": 100,
                "missed_tools": [],
                "suggested_sequence": [],
                "reasoning": "",
            }
            s, _ = await _node_critic(ctx)

    assert s == AgentState.FINALIZE
    # Verify both were called (parallel execution)
    mock_eval.assert_called_once()
    mock_review.assert_called_once()
    print("PASS: critic runs parallel reviews, both PASS → FINALIZE")


async def test_critic_tool_selection_forces_retry():
    """Output PASS but tool score < 60 → accepts anyway (4B reviewer over-rejects).

    Architecture decision: when the main CoVe critic says PASS, we trust it
    over the tool-selection reviewer. The 4B model's tool review is unreliable
    and over-rejects, so PASS + low tool_score → FINALIZE (not retry).
    """
    ctx = _AgentContext(user_question="test")
    ctx.draft_answer = "test answer"
    ctx._tools_used = [{"name": "scan_lan", "command": "", "output_summary": "ok"}]
    ctx.active_tools = [{"name": "scan_lan"}, {"name": "skill_intel-skill"}]
    ctx._last_raw_tool_result = "data"
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "<tool_output>data</tool_output>"},
    ]

    with patch("services.agent._nodes._critic._run_critic_evaluation") as mock_eval:
        mock_eval.return_value = (
            True,
            {
                "accuracy_score": 90,
                "completeness_score": 80,
                "action_required": "PASS",
                "feedback_to_agent": "",
            },
        )
        with patch("services.agent._nodes._critic._run_tool_selection_review") as mock_review:
            mock_review.return_value = {
                "tool_selection_score": 45,
                "missed_tools": ["skill_intel-skill"],
                "suggested_sequence": [{"tool": "skill_intel-skill", "reason": "better"}],
                "reasoning": "need deeper intel",
            }
            s, _ = await _node_critic(ctx)

    assert s == AgentState.FINALIZE
    print("PASS: output PASS + bad tool score → FINALIZE (4B over-rejects tool review)")


async def test_executor_records_tools_used():
    """Executor appends to ctx._tools_used after tool execution."""
    from services.agent._nodes._executor import _node_execute

    ctx = _AgentContext(user_question="test", max_steps=10)
    ctx.messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "test"},
    ]
    ctx.active_tools = [{"type": "function", "function": {"name": "get_system_snapshot"}}]

    async def fake_agent_step(msgs, **kw):
        return type(
            "FakeMsg", (), {"content": '{"thought":"x","tool_calls":[{"name":"get_system_snapshot","arguments":{}}]}'}
        )()

    ctx.engine = AsyncMock()
    ctx.engine.agent_step = fake_agent_step

    with patch("services.agent._nodes._executor_phases._execute_tool") as mock_exec:
        mock_exec.return_value = "CPU: 15%"
        s, _ = await _node_execute(ctx)

    assert len(ctx._tools_used) == 1
    assert ctx._tools_used[0]["name"] == "get_system_snapshot"
    print("PASS: executor records tool usage")


def run_all():
    asyncio.run(test_tool_selection_review_no_tools())
    asyncio.run(test_tool_selection_review_with_tools())
    asyncio.run(test_critic_parallel_reviews())
    asyncio.run(test_critic_tool_selection_forces_retry())
    asyncio.run(test_executor_records_tools_used())
    print("\n=== ALL REFLECTION TESTS PASSED ===")


if __name__ == "__main__":
    run_all()
