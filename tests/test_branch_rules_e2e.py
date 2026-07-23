# tests/test_branch_rules_e2e.py
"""Branch Rules / Agent DAG layer — comprehensive E2E tests.

Covers the no-tool-call handler chain, subtask state manager, branch
executor (skip_to_final), and agent-loop pre-checks (step budget,
recovery nudge, degraded mode, handler error handling).

Run:  .venv\\Scripts\\python.exe -m pytest tests/test_branch_rules_e2e.py -v --tb=short -p no:warnings
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import openai
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._agent_loop import (
    _check_degraded_mode,
    _check_step_budget,
    _execute_handler,
    _inject_recovery_nudge,
)
from services.agent._branch_rules import BranchDecision
from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._branch_executor import apply_skip_to_final
from services.agent._nodes.no_tool_handler import (
    _compute_fallback_text,
    _detect_echo_general,
    _detect_echo_subtask,
    _detect_thought_leak,
    _detect_zero_tool_failure,
    _handle_step_gt_zero,
    _route_thought_only,
    _termination_fallback,
    handle_no_tool_calls,
)
from services.agent._nodes.state_manager import (
    _build_tool_rule,
    handle_no_tool_call,
    handle_subtask_preparation,
)

# ── Helpers ─────────────────────────────────────────────────────────────────


def _make_ctx(
    user_question: str = "test question",
    max_steps: int = 10,
    step_count: int = 1,
) -> _AgentContext:
    """Build a minimal _AgentContext with engine mocked."""
    ctx = _AgentContext(user_question=user_question, max_steps=max_steps)
    ctx.engine = AsyncMock()
    ctx.step_count = step_count
    ctx.active_tools = [
        {"type": "function", "function": {"name": "get_system_snapshot"}},
        {"type": "function", "function": {"name": "final_answer"}},
    ]
    return ctx


def _subtasks_with_final() -> list[dict]:
    return [
        {"id": "T1", "description": "Scan processes", "depends_on": [], "status": "done", "result": "scan results"},
        {"id": "T2", "description": "Get network info", "depends_on": ["T1"], "status": "pending"},
        {
            "id": "T3",
            "description": "Synthesize using final_answer",
            "depends_on": ["T2"],
            "status": "pending",
        },
    ]


def _subtasks_no_final() -> list[dict]:
    return [
        {"id": "T1", "description": "Scan processes", "depends_on": [], "status": "done", "result": "scan results"},
        {"id": "T2", "description": "Get network info", "depends_on": ["T1"], "status": "pending"},
        {"id": "T3", "description": "Get disk info", "depends_on": ["T1"], "status": "pending"},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _compute_fallback_text
# ─────────────────────────────────────────────────────────────────────────────


class TestComputeFallbackText:
    def test_raw_result_over_10_chars_used(self):
        ctx = _make_ctx()
        ctx._last_raw_tool_result = "detailed raw result from tool"
        fallback, raw, last_output = _compute_fallback_text(ctx, "some thought")
        assert fallback == "detailed raw result from tool"
        assert raw == "detailed raw result from tool"

    def test_last_output_over_20_chars_used_when_raw_short(self):
        ctx = _make_ctx()
        ctx._last_raw_tool_result = "short"  # <= 10 chars
        ctx.messages = [
            {"role": "user", "content": "<tool_output>this is a longer tool output over 20 chars</tool_output>"},
        ]
        fallback, raw, last_output = _compute_fallback_text(ctx, "thought here")
        assert fallback == "this is a longer tool output over 20 chars"
        assert raw == "short"
        assert len(last_output) > 20

    def test_thought_fallback_when_no_raw_no_output(self):
        ctx = _make_ctx()
        ctx._last_raw_tool_result = ""
        ctx.messages = []
        fallback, raw, last_output = _compute_fallback_text(ctx, "my thought text")
        assert fallback == "my thought text"
        assert raw == ""
        assert last_output == ""

    def test_default_hebrew_when_all_empty(self):
        ctx = _make_ctx()
        ctx._last_raw_tool_result = ""
        ctx.messages = []
        fallback, _raw, _last_output = _compute_fallback_text(ctx, "")
        assert fallback == "המשימה הושלמה."


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _detect_echo_subtask
# ─────────────────────────────────────────────────────────────────────────────


class TestDetectEchoSubtask:
    def test_echo_detected_returns_execute_and_nudges(self):
        ctx = _make_ctx()
        parsed = {"echo_detected": True}
        result = _detect_echo_subtask(ctx, parsed)
        assert result is not None
        handled, state, output, tool_calls = result
        assert handled is True
        assert state == AgentState.EXECUTE
        assert output is None
        assert tool_calls == []
        # Nudge message was appended
        assert any("CRITICAL" in m.get("content", "") for m in ctx.messages)

    def test_no_echo_returns_none(self):
        ctx = _make_ctx()
        result = _detect_echo_subtask(ctx, {"echo_detected": False})
        assert result is None
        assert len(ctx.messages) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _detect_thought_leak
# ─────────────────────────────────────────────────────────────────────────────


class TestDetectThoughtLeak:
    def test_long_thought_no_data_triggers_leak(self):
        ctx = _make_ctx()
        long_thought = "A" * 600  # > 500 chars, no raw or last_output
        result = _detect_thought_leak(ctx, long_thought, raw="", last_output="")
        assert result is not None
        handled, state, _output, tool_calls = result
        assert handled is True
        assert state == AgentState.EXECUTE
        assert tool_calls == []
        assert any("CRITICAL ERROR" in m.get("content", "") for m in ctx.messages)

    def test_short_thought_returns_none(self):
        ctx = _make_ctx()
        result = _detect_thought_leak(ctx, "short thought", raw="", last_output="")
        assert result is None

    def test_long_thought_with_raw_returns_none(self):
        ctx = _make_ctx()
        long_thought = "B" * 600
        result = _detect_thought_leak(ctx, long_thought, raw="some raw data", last_output="")
        assert result is None

    def test_long_thought_with_last_output_returns_none(self):
        ctx = _make_ctx()
        long_thought = "C" * 600
        result = _detect_thought_leak(ctx, long_thought, raw="", last_output="tool output")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _detect_zero_tool_failure
# ─────────────────────────────────────────────────────────────────────────────


class TestDetectZeroToolFailure:
    def test_tools_available_none_used_triggers(self):
        ctx = _make_ctx()
        ctx._tools_used = []  # no tools used
        ctx.active_tools = [
            {"type": "function", "function": {"name": "get_system_snapshot"}},
            {"type": "function", "function": {"name": "final_answer"}},
        ]
        result = _detect_zero_tool_failure(ctx)
        assert result is not None
        handled, state, _output, tool_calls = result
        assert handled is True
        assert state == AgentState.EXECUTE
        assert any("CRITICAL ERROR" in m.get("content", "") for m in ctx.messages)

    def test_tools_used_returns_none(self):
        ctx = _make_ctx()
        ctx._tools_used = [{"name": "get_system_snapshot"}]
        result = _detect_zero_tool_failure(ctx)
        assert result is None

    def test_only_final_answer_available_returns_none(self):
        ctx = _make_ctx()
        ctx._tools_used = []
        ctx.active_tools = [{"type": "function", "function": {"name": "final_answer"}}]
        result = _detect_zero_tool_failure(ctx)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _detect_echo_general
# ─────────────────────────────────────────────────────────────────────────────


class TestDetectEchoGeneral:
    def test_tool_output_prefix_triggers(self):
        ctx = _make_ctx()
        parsed = {}
        fallback_text = "<tool_output>raw data here</tool_output>"
        result = _detect_echo_general(ctx, parsed, fallback_text)
        assert result is not None
        handled, state, _output, tool_calls = result
        assert handled is True
        assert state == AgentState.EXECUTE
        assert any("CRITICAL" in m.get("content", "") for m in ctx.messages)

    def test_echo_detected_flag_triggers(self):
        ctx = _make_ctx()
        parsed = {"echo_detected": True}
        result = _detect_echo_general(ctx, parsed, "normal text")
        assert result is not None
        assert result[0] is True

    def test_normal_text_returns_none(self):
        ctx = _make_ctx()
        parsed = {}
        result = _detect_echo_general(ctx, parsed, "This is a normal synthesized answer.")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _termination_fallback
# ─────────────────────────────────────────────────────────────────────────────


class TestTerminationFallback:
    def test_injects_final_answer_tool_call(self):
        ctx = _make_ctx()
        fallback_text = "synthesized result"
        handled, state, output, tool_calls = _termination_fallback(ctx, fallback_text)
        assert handled is False
        assert state == AgentState.EXECUTE
        assert output is None
        assert len(tool_calls) == 1
        assert tool_calls[0]["name"] == "final_answer"
        assert tool_calls[0]["arguments"]["text"] == "synthesized result"


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _route_thought_only
# ─────────────────────────────────────────────────────────────────────────────


class TestRouteThoughtOnly:
    def test_thought_present_routes_to_finalize(self):
        ctx = _make_ctx()
        thought_text = "I need to ask for clarification"
        result = _route_thought_only(ctx, thought_text)
        assert result is not None
        handled, state, output, tool_calls = result
        assert handled is True
        assert state == AgentState.FINALIZE
        assert output is not None
        assert "clarification" in output
        assert tool_calls == []

    def test_no_thought_returns_none(self):
        ctx = _make_ctx()
        result = _route_thought_only(ctx, "")
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — _handle_step_gt_zero (guard chain)
# ─────────────────────────────────────────────────────────────────────────────


class TestHandleStepGtZero:
    async def test_echo_subtask_guard_fires_first(self):
        ctx = _make_ctx(step_count=1)
        parsed = {"echo_detected": True}
        handled, state, _output, tool_calls = await _handle_step_gt_zero(ctx, parsed, "thought")
        assert handled is True
        assert state == AgentState.EXECUTE
        assert tool_calls == []

    async def test_termination_fallback_when_no_guards_match(self):
        """No subtasks, no echo, no thought leak, tools used → termination fallback."""
        ctx = _make_ctx(step_count=1)
        ctx.subtasks = []
        ctx._tools_used = [{"name": "get_system_snapshot"}]  # tools used → zero-tool guard won't fire
        ctx._last_raw_tool_result = "real raw data from tool"
        parsed = {}
        handled, state, output, tool_calls = await _handle_step_gt_zero(ctx, parsed, "short thought")
        assert handled is False
        assert state == AgentState.EXECUTE
        assert tool_calls[0]["name"] == "final_answer"

    async def test_thought_leak_guard_fires(self):
        ctx = _make_ctx(step_count=1)
        ctx.subtasks = []  # no subtask auto-advance
        ctx._tools_used = [{"name": "get_system_snapshot"}]  # tools used → zero-tool won't fire
        long_thought = "X" * 600
        ctx._last_raw_tool_result = ""
        ctx.messages = []
        parsed = {}
        handled, state, _output, tool_calls = await _handle_step_gt_zero(ctx, parsed, long_thought)
        assert handled is True
        assert state == AgentState.EXECUTE
        assert tool_calls == []

    async def test_zero_tool_failure_guard_fires(self):
        ctx = _make_ctx(step_count=1)
        ctx.subtasks = []  # no subtask auto-advance
        ctx._tools_used = []  # no tools used
        ctx._last_raw_tool_result = ""
        ctx.messages = []
        parsed = {}
        handled, state, _output, tool_calls = await _handle_step_gt_zero(ctx, parsed, "short")
        assert handled is True
        assert state == AgentState.EXECUTE


# ─────────────────────────────────────────────────────────────────────────────
# 1. no_tool_handler.py — handle_no_tool_calls (entry point)
# ─────────────────────────────────────────────────────────────────────────────


class TestHandleNoToolCalls:
    async def test_step_gt_zero_path(self):
        ctx = _make_ctx(step_count=1)
        ctx.subtasks = []
        ctx._tools_used = [{"name": "get_system_snapshot"}]
        ctx._last_raw_tool_result = "raw data result"
        parsed = {}
        handled, state, output, tool_calls = await handle_no_tool_calls(ctx, parsed, [])
        assert handled is False
        assert state == AgentState.EXECUTE
        assert tool_calls[0]["name"] == "final_answer"

    async def test_step_zero_with_thought_routes_to_finalize(self):
        ctx = _make_ctx(step_count=0)
        parsed = {"thought": "I need clarification from user"}
        handled, state, output, tool_calls = await handle_no_tool_calls(ctx, parsed, [])
        assert handled is True
        assert state == AgentState.FINALIZE
        assert output is not None
        assert "clarification" in output

    async def test_step_zero_no_thought_returns_default(self):
        ctx = _make_ctx(step_count=0)
        parsed = {}
        handled, state, output, tool_calls = await handle_no_tool_calls(ctx, parsed, [])
        assert handled is False
        assert state == AgentState.EXECUTE
        assert output is None
        assert tool_calls == []


# ─────────────────────────────────────────────────────────────────────────────
# 2. state_manager.py — _build_tool_rule
# ─────────────────────────────────────────────────────────────────────────────


class TestBuildToolRule:
    def test_analysis_only_rule(self):
        current = {"description": "analyze the data", "depends_on": ["T1"]}
        rule = _build_tool_rule(current, is_analysis_only=True, is_last=False)
        assert "ANALYSIS-ONLY" in rule
        assert "VERBATIM QUOTE" in rule
        assert "MUST NOT use internal training knowledge" in rule

    def test_last_subtask_rule(self):
        current = {"description": "final synthesis", "depends_on": ["T1"]}
        rule = _build_tool_rule(current, is_analysis_only=False, is_last=True)
        assert "CRITICAL SUBTASK RULES" in rule
        assert "IMMEDIATELY after receiving the tool output" in rule
        assert "call final_answer with the result" in rule

    def test_normal_subtask_rule(self):
        current = {"description": "scan processes", "depends_on": []}
        rule = _build_tool_rule(current, is_analysis_only=False, is_last=False)
        assert "CRITICAL SUBTASK RULES" in rule
        assert "Do NOT call final_answer" in rule
        assert "Do NOT call any tool named 'wait'" in rule


# ─────────────────────────────────────────────────────────────────────────────
# 2. state_manager.py — handle_subtask_preparation
# ─────────────────────────────────────────────────────────────────────────────


class TestHandleSubtaskPreparation:
    async def test_no_subtasks_returns_continue(self):
        ctx = _make_ctx()
        ctx.subtasks = []
        ctx.current_subtask_idx = -1
        should_continue, state, output = await handle_subtask_preparation(ctx)
        assert should_continue is True
        assert state is None
        assert output is None

    async def test_past_end_returns_continue(self):
        ctx = _make_ctx()
        ctx.subtasks = _subtasks_with_final()
        ctx.current_subtask_idx = 10  # past end
        should_continue, state, output = await handle_subtask_preparation(ctx)
        assert should_continue is True
        assert state is None

    async def test_blocked_task_skipped_and_advances(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "blocked task", "status": "blocked", "error": "dep failed"},
            {"id": "T2", "description": "next task", "status": "pending"},
        ]
        ctx.current_subtask_idx = 0
        with patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock):
            should_continue, state, output = await handle_subtask_preparation(ctx)
        assert should_continue is False
        assert state == AgentState.EXECUTE
        assert ctx.current_subtask_idx == 1
        assert ctx._task_results["T1"] == "dep failed"

    async def test_blocked_task_last_one_synthesizes(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "done task", "status": "done", "result": "result1"},
            {"id": "T2", "description": "blocked last", "status": "blocked", "error": "dep failed"},
        ]
        ctx.current_subtask_idx = 1
        with (
            patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock),
            patch("services.agent._nodes.state_manager._synthesize_results", new_callable=AsyncMock) as m_synth,
        ):
            m_synth.return_value = "synthesized answer"
            should_continue, state, output = await handle_subtask_preparation(ctx)
        assert should_continue is False
        assert state == AgentState.CRITIC
        assert ctx.draft_answer == "synthesized answer"

    async def test_dependency_injection_appends_dep_block(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "scan", "status": "done", "result": "scan result"},
            {
                "id": "T2",
                "description": "analyze the scan results",
                "status": "pending",
                "depends_on": ["T1"],
            },
        ]
        ctx.current_subtask_idx = 1
        ctx._task_results["T1"] = "scan result data"
        should_continue, state, output = await handle_subtask_preparation(ctx)
        assert should_continue is True
        # A subtask prompt was injected with dependency data
        injected = [m for m in ctx.messages if "SUBTASK" in m.get("content", "")]
        assert len(injected) == 1
        assert "Dependency Results" in injected[0]["content"]
        assert "scan result data" in injected[0]["content"]
        # Analysis-only because "analyze" keyword + has deps
        assert "ANALYSIS-ONLY" in injected[0]["content"]


# ─────────────────────────────────────────────────────────────────────────────
# 2. state_manager.py — handle_no_tool_call
# ─────────────────────────────────────────────────────────────────────────────


class TestHandleNoToolCallStateManager:
    async def test_no_subtasks_returns_not_handled(self):
        ctx = _make_ctx()
        ctx.subtasks = []
        ctx.current_subtask_idx = -1
        handled, state, output = await handle_no_tool_call(ctx, "fallback text")
        assert handled is False
        assert state is None

    async def test_hollow_payload_rejected_and_nudged(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "scan", "status": "pending"},
        ]
        ctx.current_subtask_idx = 0
        ctx._premature_fa_count = 0
        # "אין לי מידע" is an apology pattern → hollow
        handled, state, output = await handle_no_tool_call(ctx, "אין לי מידע על כך")
        assert handled is True
        assert state == AgentState.EXECUTE
        assert ctx._premature_fa_count == 1

    async def test_valid_payload_advances_subtask(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "scan", "status": "pending"},
            {"id": "T2", "description": "report", "status": "pending"},
        ]
        ctx.current_subtask_idx = 0
        with patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock):
            handled, state, output = await handle_no_tool_call(ctx, '{"cpu": 45.2, "memory": 60.0}')
        assert handled is True
        assert state == AgentState.EXECUTE
        assert ctx.current_subtask_idx == 1
        assert ctx.subtasks[0]["status"] == "done"
        assert ctx.subtasks[0]["result"] == '{"cpu": 45.2, "memory": 60.0}'

    async def test_valid_payload_last_subtask_synthesizes(self):
        ctx = _make_ctx()
        ctx.subtasks = [
            {"id": "T1", "description": "scan", "status": "done", "result": "result1"},
            {"id": "T2", "description": "report", "status": "pending"},
        ]
        ctx.current_subtask_idx = 1
        with (
            patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock),
            patch("services.agent._nodes.state_manager._synthesize_results", new_callable=AsyncMock) as m_synth,
        ):
            m_synth.return_value = "final synthesis"
            handled, state, output = await handle_no_tool_call(ctx, '{"data": "report content 123"}')
        assert handled is True
        assert state == AgentState.CRITIC
        assert ctx.draft_answer == "final synthesis"


# ─────────────────────────────────────────────────────────────────────────────
# 3. _branch_executor.py — apply_skip_to_final
# ─────────────────────────────────────────────────────────────────────────────


class TestApplySkipToFinal:
    async def test_final_answer_subtask_exists_jumps_to_it(self):
        ctx = _make_ctx()
        ctx.subtasks = _subtasks_with_final()
        ctx.current_subtask_idx = 1  # at T2
        branch = BranchDecision(action="skip_to_final", reason="clean system")
        with patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock):
            result = await apply_skip_to_final(ctx, branch)
        # Returns None → caller continues to final_answer subtask
        assert result is None
        assert ctx.current_subtask_idx == 2  # jumped to T3 (final_answer)
        # T2 was skipped
        assert ctx.subtasks[1]["status"] == "skipped"
        assert "[SKIPPED by branch rule]" in ctx.subtasks[1]["result"]

    async def test_no_final_answer_subtask_synthesizes(self):
        ctx = _make_ctx()
        ctx.subtasks = _subtasks_no_final()
        ctx.current_subtask_idx = 1  # at T2
        branch = BranchDecision(action="skip_to_final", reason="clean system")
        with (
            patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock),
            patch("services.agent._nodes._branch_executor._synthesize_results", new_callable=AsyncMock) as m_synth,
        ):
            m_synth.return_value = "synthesized from done results"
            result = await apply_skip_to_final(ctx, branch)
        assert result is not None
        handled, state, output = result
        assert handled is True
        assert state == AgentState.CRITIC
        assert ctx.draft_answer == "synthesized from done results"
        # T2 and T3 were skipped
        assert ctx.subtasks[1]["status"] == "skipped"
        assert ctx.subtasks[2]["status"] == "skipped"

    async def test_dag_emit_called_for_each_skipped(self):
        ctx = _make_ctx()
        ctx.subtasks = _subtasks_with_final()
        ctx.current_subtask_idx = 1
        branch = BranchDecision(action="skip_to_final", reason="test reason")
        with patch("services.agent._dag_emitter.emit_subtask_transition", new_callable=AsyncMock) as m_emit:
            await apply_skip_to_final(ctx, branch)
        # Only T2 is skipped (between idx 1 and final_idx 2)
        m_emit.assert_called_once()
        _ctx_arg, task_id, from_st, to_st = m_emit.call_args.args
        assert task_id == "T2"
        assert from_st == "pending"
        assert to_st == "skipped"


# ─────────────────────────────────────────────────────────────────────────────
# 4. _agent_loop.py — _check_step_budget
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckStepBudget:
    def test_budget_ok_returns_none(self):
        ctx = _make_ctx(max_steps=10, step_count=5)
        result = _check_step_budget(ctx, AgentState.EXECUTE)
        assert result is None

    def test_budget_exceeded_no_reserve_returns_error(self):
        ctx = _make_ctx(max_steps=10, step_count=10)
        ctx.subtasks = [{"id": "T1"}]
        ctx.current_subtask_idx = 0
        ctx.draft_answer = ""  # no draft → no reserve
        ctx._emergency_reserve_used = False
        result = _check_step_budget(ctx, AgentState.EXECUTE)
        assert result == AgentState.ERROR
        assert "Maximum steps exceeded" in ctx.error_msg

    def test_budget_exceeded_with_reserve_grants_steps(self):
        ctx = _make_ctx(max_steps=10, step_count=10)
        ctx.subtasks = [{"id": "T1"}, {"id": "T2"}]
        ctx.current_subtask_idx = 1  # final subtask
        ctx.draft_answer = "draft answer with data"
        ctx._emergency_reserve_used = False
        original_max = ctx.max_steps
        result = _check_step_budget(ctx, AgentState.EXECUTE)
        # Reserve granted → returns None (continue), max_steps increased
        assert result is None
        assert ctx.max_steps == original_max + 2
        assert ctx._emergency_reserve_used is True
        assert ctx.is_emergency_mode is True
        # Emergency system message appended
        assert any("EMERGENCY BUDGET" in m.get("content", "") for m in ctx.messages)


# ─────────────────────────────────────────────────────────────────────────────
# 4. _agent_loop.py — _inject_recovery_nudge
# ─────────────────────────────────────────────────────────────────────────────


class TestInjectRecoveryNudge:
    def test_step_max_minus_1_triggers_nudge(self):
        ctx = _make_ctx(max_steps=10, step_count=9)
        ctx._recovery_nudge_injected = False
        _inject_recovery_nudge(ctx)
        assert ctx._recovery_nudge_injected is True
        assert any("CRITICAL WARNING" in m.get("content", "") for m in ctx.messages)

    def test_already_injected_does_not_re_inject(self):
        ctx = _make_ctx(max_steps=10, step_count=9)
        ctx._recovery_nudge_injected = True
        msg_count_before = len(ctx.messages)
        _inject_recovery_nudge(ctx)
        assert len(ctx.messages) == msg_count_before

    def test_wrong_step_does_not_inject(self):
        ctx = _make_ctx(max_steps=10, step_count=5)
        ctx._recovery_nudge_injected = False
        _inject_recovery_nudge(ctx)
        assert ctx._recovery_nudge_injected is False
        assert len(ctx.messages) == 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. _agent_loop.py — _check_degraded_mode
# ─────────────────────────────────────────────────────────────────────────────


class TestCheckDegradedMode:
    def test_planner_degraded_routes_to_execute(self):
        ctx = _make_ctx()
        with patch("services.llm_bridge.bridge.LLMBridge") as m_bridge:
            m_bridge.get_instance.return_value.is_degraded.return_value = True
            result = _check_degraded_mode(ctx, AgentState.PLANNER)
        assert result == AgentState.EXECUTE
        assert ctx._degraded_mode is True

    def test_critic_degraded_with_draft_routes_to_finalize(self):
        ctx = _make_ctx()
        ctx.draft_answer = "draft answer text"
        ctx.output = ""
        with patch("services.llm_bridge.bridge.LLMBridge") as m_bridge:
            m_bridge.get_instance.return_value.is_degraded.return_value = True
            result = _check_degraded_mode(ctx, AgentState.CRITIC)
        assert result == AgentState.FINALIZE
        assert ctx._degraded_mode is True
        assert ctx.output == "draft answer text"

    def test_not_degraded_returns_none(self):
        ctx = _make_ctx()
        with patch("services.llm_bridge.bridge.LLMBridge") as m_bridge:
            m_bridge.get_instance.return_value.is_degraded.return_value = False
            result = _check_degraded_mode(ctx, AgentState.PLANNER)
        assert result is None

    def test_non_planner_critic_state_returns_none(self):
        ctx = _make_ctx()
        # EXECUTE state should never trigger degraded check
        with patch("services.llm_bridge.bridge.LLMBridge") as m_bridge:
            m_bridge.get_instance.return_value.is_degraded.return_value = True
            result = _check_degraded_mode(ctx, AgentState.EXECUTE)
        assert result is None


# ─────────────────────────────────────────────────────────────────────────────
# 4. _agent_loop.py — _execute_handler
# ─────────────────────────────────────────────────────────────────────────────


class TestExecuteHandler:
    async def test_success_increments_step_count(self):
        ctx = _make_ctx(max_steps=10, step_count=3)
        mock_handler = AsyncMock(return_value=(AgentState.CRITIC, "some output"))
        with patch("services.agent._agent_loop._STATE_HANDLERS", {AgentState.EXECUTE: mock_handler}):
            executed_state, new_state = await _execute_handler(ctx, AgentState.EXECUTE)
        assert executed_state == AgentState.EXECUTE
        assert new_state == AgentState.CRITIC
        assert ctx.step_count == 4
        assert ctx.output == "some output"

    async def test_api_connection_error_routes_to_error(self):
        ctx = _make_ctx(max_steps=10, step_count=3)
        mock_handler = AsyncMock(
            side_effect=openai.APIConnectionError(
                message="test connection error",
                request=httpx.Request("POST", "http://localhost:5001"),
            )
        )
        with patch("services.agent._agent_loop._STATE_HANDLERS", {AgentState.EXECUTE: mock_handler}):
            executed_state, new_state = await _execute_handler(ctx, AgentState.EXECUTE)
        assert new_state == AgentState.ERROR
        assert "Connection Error" in ctx.error_msg
        assert "KoboldCpp" in ctx.error_msg

    async def test_timeout_error_routes_to_error(self):
        ctx = _make_ctx(max_steps=10, step_count=3)
        mock_handler = AsyncMock(side_effect=TimeoutError())
        with patch("services.agent._agent_loop._STATE_HANDLERS", {AgentState.EXECUTE: mock_handler}):
            _executed, new_state = await _execute_handler(ctx, AgentState.EXECUTE)
        assert new_state == AgentState.ERROR
        assert "timeout" in ctx.error_msg.lower()

    async def test_generic_exception_routes_to_error(self):
        ctx = _make_ctx(max_steps=10, step_count=3)
        mock_handler = AsyncMock(side_effect=ValueError("unexpected crash"))
        with patch("services.agent._agent_loop._STATE_HANDLERS", {AgentState.EXECUTE: mock_handler}):
            _executed, new_state = await _execute_handler(ctx, AgentState.EXECUTE)
        assert new_state == AgentState.ERROR
        assert "unexpected crash" in ctx.error_msg

    async def test_success_with_none_output_does_not_overwrite(self):
        ctx = _make_ctx(max_steps=10, step_count=3)
        ctx.output = "previous output"
        mock_handler = AsyncMock(return_value=(AgentState.EXECUTE, None))
        with patch("services.agent._agent_loop._STATE_HANDLERS", {AgentState.EXECUTE: mock_handler}):
            _executed, new_state = await _execute_handler(ctx, AgentState.EXECUTE)
        assert new_state == AgentState.EXECUTE
        # output stays as previous — None doesn't overwrite
        assert ctx.output == "previous output"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-p", "no:warnings"])
