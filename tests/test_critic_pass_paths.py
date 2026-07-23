# tests/test_critic_pass_paths.py
"""Tests for _node_critic PASS paths, FINALIZE_WITH_WARNING, and KCA-in-fb_text.

Covers lines 270-315 of _critic.py:
- PASS with tool_score >= 60 → _accept_pass
- PASS with tool_score < 60 but no tool_msg → _accept_pass
- PASS with tool_score < 60 and tool_msg → _accept_pass (accept anyway)
- FINALIZE_WITH_WARNING action_required
- KCA blocks already in fb_text (entity audit path → short instruction)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.agent._context import AgentState, _AgentContext


def _make_ctx(draft="Draft answer about CPU and RAM."):
    """Build a minimal _AgentContext for testing."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "Scan my system"
    ctx.draft_answer = draft
    ctx.critic_rejections = 0
    ctx._critic_claims_history = []
    ctx._last_critic_feedback = {}
    ctx._completeness_retries = 0
    ctx._tools_used = []
    ctx.active_tools = []
    ctx.messages = [{"role": "system", "content": "system prompt"}]
    ctx.engine = MagicMock()
    ctx._draft_v1 = ""
    return ctx


class TestCriticPassPaths:
    """Verify PASS verdict handling in _node_critic."""

    @pytest.mark.asyncio
    async def test_pass_high_tool_score_accepts(self):
        """PASS + tool_score >= 60 → _accept_pass, FINALIZE."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx()
        pass_feedback = {"pass": True, "feedback_to_agent": "", "logical_flaw": ""}

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(True, pass_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            state, answer = await critic_mod._node_critic(ctx)

        assert state == AgentState.FINALIZE
        assert answer == ctx.draft_answer

    @pytest.mark.asyncio
    async def test_pass_low_tool_score_no_msg_accepts(self):
        """PASS + tool_score < 60 but no tool_msg → _accept_pass (line 273)."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx()
        pass_feedback = {"pass": True, "feedback_to_agent": "", "logical_flaw": ""}

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(True, pass_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 40}),
            ),
        ):
            state, answer = await critic_mod._node_critic(ctx)

        assert state == AgentState.FINALIZE
        assert answer == ctx.draft_answer

    @pytest.mark.asyncio
    async def test_pass_low_tool_score_with_msg_accepts_anyway(self):
        """PASS + tool_score < 60 + tool_msg → accept anyway (line 275)."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx()
        pass_feedback = {"pass": True, "feedback_to_agent": "", "logical_flaw": ""}

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(True, pass_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 30, "suggested_sequence": [{"tool": "better_tool"}]}),
            ),
        ):
            state, answer = await critic_mod._node_critic(ctx)

        assert state == AgentState.FINALIZE
        assert answer == ctx.draft_answer


class TestFinalizeWithWarning:
    """Verify FINALIZE_WITH_WARNING action handling (lines 283-286)."""

    @pytest.mark.asyncio
    async def test_finalize_with_warning_action(self):
        """action_required=FINALIZE_WITH_WARNING → FINALIZE with warning prefix."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx(draft="Partial report with unverified claims.")
        fail_feedback = {
            "pass": False,
            "feedback_to_agent": "partial claims",
            "logical_flaw": "",
            "action_required": "FINALIZE_WITH_WARNING",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(False, fail_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            state, answer = await critic_mod._node_critic(ctx)

        assert state == AgentState.FINALIZE
        assert "[System Warning" in answer
        assert "Partial report" in answer


class TestKcaBlocksInFbText:
    """Verify KCA blocks already in fb_text use short instruction (lines 308-314)."""

    @pytest.mark.asyncio
    async def test_entity_audit_fb_uses_short_instruction(self):
        """fb_text with <ANCHOR_SUCCESS> → short instruction path."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx()
        fail_feedback = {
            "pass": False,
            "feedback_to_agent": (
                "אופטימיזציית טיוטה — סבב שיפור ישויות.\n"
                "<ANCHOR_SUCCESS>\nהמבנה הכללי מדויק.\n</ANCHOR_SUCCESS>\n"
                "<REVISE_TARGET>\nPID 99999 not in tool data.\n</REVISE_TARGET>"
            ),
            "logical_flaw": "PID 99999 not in tool data",
            "missing_facts": [],
            "action_required": "RETRY_WITH_FEEDBACK",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(False, fail_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "<ANCHOR_SUCCESS>" in retry_content
        assert "SYSTEM COGNITION PATH" in retry_content
        # Short instruction is used (not full instruction)
        assert "optimizing only" in retry_content


class TestToolMsgAppend:
    """Verify tool_msg appended to feedback on FAIL (lines 278-280)."""

    @pytest.mark.asyncio
    async def test_tool_msg_appended_to_feedback(self):
        """FAIL + tool_msg → tool_msg appended to feedback_to_agent."""
        from services.agent._nodes import _critic as critic_mod

        ctx = _make_ctx()
        fail_feedback = {
            "pass": False,
            "feedback_to_agent": "original feedback",
            "logical_flaw": "some flaw",
            "missing_facts": [],
            "action_required": "RETRY_WITH_FEEDBACK",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation",
                AsyncMock(return_value=(False, fail_feedback)),
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 30, "suggested_sequence": [{"tool": "better_tool"}]}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        # tool_msg is appended to feedback_to_agent in the feedback dict
        stored_fb = ctx._last_critic_feedback.get("feedback_to_agent", "")
        assert "TOOL SELECTION" in stored_fb
        assert "original feedback" in stored_fb
