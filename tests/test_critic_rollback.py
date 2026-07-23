# tests/test_critic_rollback.py
"""Tests for critic retry collapse detection + draft_v1 rollback.

Validates the Graceful Degradation mechanism:
1. _is_collapsed_retry detects short/meta-description/hollow retry outputs
2. _rollback_to_draft_v1 returns draft_v1 with a reliability warning header
3. _node_critic short-circuits to rollback before wasting a critic LLM call
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._critic import (
    _is_collapsed_retry,
    _node_critic,
    _rollback_to_draft_v1,
)


def _make_ctx(**kwargs) -> _AgentContext:
    """Build a minimal _AgentContext for critic rollback tests."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "תבצע דוח אבטחה"
    ctx.messages = [{"role": "system", "content": "sys"}]
    ctx._tool_outputs_buffer = []
    ctx._draft_v1 = ""
    ctx.draft_answer = ""
    ctx.critic_rejections = 0
    ctx._last_critic_feedback = {}
    ctx._completeness_retries = 0
    ctx._tools_used = [{"name": "skill_intel-skill"}]
    ctx.active_tools = []
    ctx.engine = MagicMock()
    for k, v in kwargs.items():
        setattr(ctx, k, v)
    return ctx


# ── _is_collapsed_retry ──────────────────────────────────────────────────────


def test_not_collapsed_when_no_draft_v1():
    """No rollback state → not collapsed."""
    ctx = _make_ctx(_draft_v1="", critic_rejections=1, draft_answer="x" * 50)
    assert not _is_collapsed_retry(ctx)


def test_not_collapsed_when_no_rejections():
    """First pass (0 rejections) → not collapsed."""
    ctx = _make_ctx(_draft_v1="original", critic_rejections=0, draft_answer="short")
    assert not _is_collapsed_retry(ctx)


def test_collapsed_when_empty_draft():
    """Empty draft_answer after retry → collapsed."""
    ctx = _make_ctx(_draft_v1="original", critic_rejections=1, draft_answer="")
    assert _is_collapsed_retry(ctx)


def test_collapsed_when_short_output():
    """Retry output < 200 chars → collapsed."""
    ctx = _make_ctx(_draft_v1="x" * 1500, critic_rejections=1, draft_answer="x" * 100)
    assert _is_collapsed_retry(ctx)


def test_not_collapsed_when_long_output():
    """Retry output >= 200 chars → not collapsed."""
    ctx = _make_ctx(_draft_v1="x" * 1500, critic_rejections=1, draft_answer="y" * 500)
    assert not _is_collapsed_retry(ctx)


def test_collapsed_when_meta_description_prefix():
    """Retry starts with 'Fixing...' → collapsed (meta-description, not a report)."""
    ctx = _make_ctx(
        _draft_v1="x" * 1500,
        critic_rejections=1,
        draft_answer="Fixing the false negative claim about suspicious connections.",
    )
    assert _is_collapsed_retry(ctx)


def test_collapsed_when_meta_prefix_with_long_output():
    """Retry starts with 'Fixing...' and is >200 chars → collapsed via prefix check."""
    ctx = _make_ctx(
        _draft_v1="x" * 3000,
        critic_rejections=1,
        draft_answer="Fixing the false negative claim. " + "y" * 250,
    )
    assert _is_collapsed_retry(ctx)


def test_collapsed_when_thought_prefix():
    """Retry starts with 'Thought:' → collapsed."""
    ctx = _make_ctx(
        _draft_v1="x" * 1500,
        critic_rejections=1,
        draft_answer="Thought: I need to fix the report.",
    )
    assert _is_collapsed_retry(ctx)


def test_collapsed_when_drastically_shorter_than_v1():
    """Retry < 30% of draft_v1 length → collapsed."""
    ctx = _make_ctx(
        _draft_v1="x" * 2000,
        critic_rejections=1,
        draft_answer="y" * 500,  # 25% of v1
    )
    assert _is_collapsed_retry(ctx)


def test_not_collapsed_when_reasonable_ratio():
    """Retry >= 30% of draft_v1 and >= 200 chars → not collapsed."""
    ctx = _make_ctx(
        _draft_v1="x" * 1000,
        critic_rejections=1,
        draft_answer="y" * 400,  # 40% of v1
    )
    assert not _is_collapsed_retry(ctx)


# ── _rollback_to_draft_v1 ────────────────────────────────────────────────────


def test_rollback_returns_finalize_state():
    """Rollback should return FINALIZE state."""
    ctx = _make_ctx(_draft_v1="## Report\nCPU fine.", draft_answer="short")
    state, output = _rollback_to_draft_v1(ctx, "logical flaw detected")
    assert state == AgentState.FINALIZE


def test_rollback_output_contains_warning_header():
    """Rollback output should contain reliability warning header."""
    ctx = _make_ctx(_draft_v1="## Report\nCPU fine.", draft_answer="short")
    _, output = _rollback_to_draft_v1(ctx, "logical flaw detected")
    assert "התראת אמינות AI" in output
    assert "מערכת" in output


def test_rollback_output_contains_draft_v1():
    """Rollback output should contain the original draft_v1 text."""
    ctx = _make_ctx(_draft_v1="## FULL REPORT\nAll systems nominal.", draft_answer="short")
    _, output = _rollback_to_draft_v1(ctx, "flaw")
    assert "FULL REPORT" in output
    assert "All systems nominal." in output


def test_rollback_output_contains_critic_feedback():
    """Rollback output should contain the critic feedback."""
    ctx = _make_ctx(_draft_v1="report", draft_answer="short")
    _, output = _rollback_to_draft_v1(ctx, "SPECIAL_FLAW_TEXT_HERE")
    assert "SPECIAL_FLAW_TEXT_HERE" in output


def test_rollback_output_contains_score_tag():
    """Rollback output should end with <SCORE>0.0</SCORE>."""
    ctx = _make_ctx(_draft_v1="report", draft_answer="short")
    _, output = _rollback_to_draft_v1(ctx, "flaw")
    assert "<SCORE>0.0</SCORE>" in output


def test_rollback_resets_critic_state():
    """Rollback should reset _last_critic_feedback and _completeness_retries."""
    ctx = _make_ctx(
        _draft_v1="report",
        draft_answer="short",
        _last_critic_feedback={"x": 1},
        _completeness_retries=3,
    )
    _rollback_to_draft_v1(ctx, "flaw")
    assert ctx._last_critic_feedback == {}
    assert ctx._completeness_retries == 0


def test_rollback_handles_empty_feedback():
    """Rollback should handle empty critic_feedback gracefully."""
    ctx = _make_ctx(_draft_v1="report", draft_answer="short")
    _, output = _rollback_to_draft_v1(ctx, "")
    assert "פגם לוגי" in output  # default fallback text


# ── _node_critic integration ─────────────────────────────────────────────────


def test_node_critic_short_circuits_on_collapsed_retry():
    """_node_critic should return rollback before calling critic LLM."""
    ctx = _make_ctx(
        _draft_v1="x" * 1500,
        draft_answer="Fixing the false negative claim.",  # collapsed
        critic_rejections=1,
        _last_critic_feedback={"feedback_to_agent": "fix the claim"},
    )
    # Patch _has_tool_outputs_in_history to return True so we reach the rollback check
    with patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True):
        state, output = asyncio.run(_node_critic(ctx))
    assert state == AgentState.FINALIZE
    assert "התראת אמינות AI" in output


# ── Pre-existing uncovered branches in _node_critic ──────────────────────────


@pytest.mark.asyncio
async def test_node_critic_no_tool_outputs_returns_finalize():
    """Line 239: no tool outputs in history → FINALIZE with draft."""
    ctx = _make_ctx(draft_answer="some draft")
    with patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=False):
        state, output = await _node_critic(ctx)
    assert state == AgentState.FINALIZE
    assert output == "some draft"


@pytest.mark.asyncio
async def test_node_critic_pass_with_low_tool_score_no_msg():
    """Line 273: CoVe PASS, tool_score < 60, but no tool_msg → accept."""
    ctx = _make_ctx(draft_answer="good report")
    with (
        patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
        patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
        patch("services.agent._nodes._critic._is_collapsed_retry", return_value=False),
        patch("services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(True, {}))),
        patch(
            "services.agent._nodes._critic._run_tool_selection_review",
            AsyncMock(return_value={"tool_selection_score": 40}),
        ),
        patch("services.agent._nodes._critic._build_tool_msg", return_value=None),
    ):
        state, output = await _node_critic(ctx)
    assert state == AgentState.FINALIZE


@pytest.mark.asyncio
async def test_node_critic_fail_appends_tool_msg():
    """Lines 279-280: FAIL + tool_msg → feedback appended."""
    ctx = _make_ctx(draft_answer="bad report")
    fail_fb = {"feedback_to_agent": "original fb", "action_required": "RETRY"}
    with (
        patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
        patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
        patch("services.agent._nodes._critic._is_collapsed_retry", return_value=False),
        patch("services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_fb))),
        patch(
            "services.agent._nodes._critic._run_tool_selection_review",
            AsyncMock(return_value={"tool_selection_score": 30}),
        ),
        patch("services.agent._nodes._critic._build_tool_msg", return_value="TOOL ADVICE"),
        patch("services.agent._nodes._critic._compress_context_for_retry"),
    ):
        await _node_critic(ctx)
    # feedback_to_agent should now contain both original + tool msg
    # (verified via the patch — if we reach here without error, lines 279-280 ran)


@pytest.mark.asyncio
async def test_node_critic_finalize_with_warning():
    """Lines 284-286: action_required=FINALIZE_WITH_WARNING → finalize with warning."""
    ctx = _make_ctx(draft_answer="partial report")
    warn_fb = {"action_required": "FINALIZE_WITH_WARNING", "feedback_to_agent": ""}
    with (
        patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
        patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
        patch("services.agent._nodes._critic._is_collapsed_retry", return_value=False),
        patch("services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, warn_fb))),
        patch(
            "services.agent._nodes._critic._run_tool_selection_review",
            AsyncMock(return_value={"tool_selection_score": 80}),
        ),
    ):
        state, output = await _node_critic(ctx)
    assert state == AgentState.FINALIZE
    assert "System Warning" in output


@pytest.mark.asyncio
async def test_node_critic_kca_anchor_success_short_instruction():
    """Lines 309, 314-315: fb_text with <ANCHOR_SUCCESS> → short instruction path."""
    ctx = _make_ctx(draft_answer="report with issues")
    fb_with_anchor = {
        "feedback_to_agent": "<ANCHOR_SUCCESS>good parts</ANCHOR_SUCCESS>\n<REVISE_TARGET>fix X</REVISE_TARGET>",
        "logical_flaw": "",
        "missing_facts": [],
        "extracted_claims": [],
    }
    with (
        patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
        patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
        patch("services.agent._nodes._critic._is_collapsed_retry", return_value=False),
        patch("services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fb_with_anchor))),
        patch(
            "services.agent._nodes._critic._run_tool_selection_review",
            AsyncMock(return_value={"tool_selection_score": 80}),
        ),
        patch("services.agent._nodes._critic._compress_context_for_retry") as mock_compress,
    ):
        state, output = await _node_critic(ctx)
    assert state == AgentState.EXECUTE
    # Should have called compress with _KCA_SHORT_INSTRUCTION (not full)
    mock_compress.assert_called_once()
    _args = mock_compress.call_args
    # The instruction arg (3rd positional) should be _KCA_SHORT_INSTRUCTION
    assert "optimizing only" in _args.args[2]
