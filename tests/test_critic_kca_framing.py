# tests/test_critic_kca_framing.py
"""Tests for KCA (Keep-Change-Add) Positive Framing in Critic feedback.

Verifies:
- <ANCHOR_SUCCESS> block present in retry message
- <REVISE_TARGET> block for logical flaws
- <ADD_EVIDENCE> block for missing facts
- No negative tokens ("נדחתה", "פגם לוגי") in feedback_msg
- Generic fallback when no specific flaw/missing
- Retry instruction contains KCA-aligned steps
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.agent._context import _CRITIC_MAX_RETRIES, AgentState, _AgentContext


class TestKcaFraming:
    """Verify Positive Framing structure in critic retry messages."""

    def _make_ctx(self, draft="Draft answer about CPU and RAM."):
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
        ctx._draft_v1 = ""  # reset rollback state
        return ctx

    @pytest.mark.asyncio
    async def test_anchor_success_present(self):
        """<ANCHOR_SUCCESS> block must be in retry message."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0  # First rejection (will become 1 after +=)

        # Mock the helpers to return FAIL with logical flaw
        fail_feedback = {
            "pass": False,
            "reason": "proxy claim unsupported",
            "action_required": "RETRY_WITH_FEEDBACK",
            "feedback_to_agent": "proxy claim unsupported",
            "accuracy_score": 0,
            "completeness_score": 0,
            "missing_facts": [],
            "extracted_claims": ["CPU is 10%", "proxy detected"],
            "logical_flaw": "The draft introduces a proxy claim not in tool data",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%\nRAM: 50%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "<ANCHOR_SUCCESS>" in retry_content
        assert "</ANCHOR_SUCCESS>" in retry_content
        assert "מדויקים ומצוינים" in retry_content  # Positive Hebrew anchor

    @pytest.mark.asyncio
    async def test_revise_target_for_logical_flaw(self):
        """<REVISE_TARGET> block must contain the logical flaw."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "",
            "feedback_to_agent": "",
            "missing_facts": [],
            "extracted_claims": [],
            "logical_flaw": "proxy claim not grounded in tool data",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "<REVISE_TARGET>" in retry_content
        assert "</REVISE_TARGET>" in retry_content
        assert "proxy claim not grounded" in retry_content

    @pytest.mark.asyncio
    async def test_add_evidence_for_missing_facts(self):
        """<ADD_EVIDENCE> block must contain missing facts."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "",
            "feedback_to_agent": "",
            "missing_facts": ["CPU temperature", "Disk usage"],
            "extracted_claims": ["CPU temperature", "Disk usage"],
            "logical_flaw": "",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "<ADD_EVIDENCE>" in retry_content
        assert "</ADD_EVIDENCE>" in retry_content
        assert "CPU temperature" in retry_content
        assert "Disk usage" in retry_content

    @pytest.mark.asyncio
    async def test_no_negative_tokens_in_feedback(self):
        """Feedback must NOT contain 'נדחתה' or 'פגם לוגי' (negative framing)."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "some reason",
            "feedback_to_agent": "some reason",
            "missing_facts": [],
            "extracted_claims": [],
            "logical_flaw": "proxy hallucination",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        # Negative tokens that cause attention collapse in 4B models
        assert "נדחתה" not in retry_content
        assert "פגם לוגי" not in retry_content
        assert "SYSTEM CRITIC" not in retry_content  # Old header replaced

    @pytest.mark.asyncio
    async def test_positive_header_present(self):
        """Feedback must use 'אופטימיזציית טיוטה' (optimization) not 'ביקורת' (criticism)."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "test",
            "feedback_to_agent": "test",
            "missing_facts": [],
            "extracted_claims": [],
            "logical_flaw": "test flaw",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "אופטימיזציית טיוטה" in retry_content
        assert "SYSTEM COGNITION PATH" in retry_content

    @pytest.mark.asyncio
    async def test_retry_instruction_kca_aligned(self):
        """Retry instruction must contain KCA-aligned steps (Keep/Revise/Add)."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "test",
            "feedback_to_agent": "test",
            "missing_facts": ["fact1"],
            "extracted_claims": ["fact1"],
            "logical_flaw": "flaw1",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "INSTRUCTION" in retry_content
        assert "<ANCHOR_SUCCESS>" in retry_content
        assert "<REVISE_TARGET>" in retry_content
        assert "<ADD_EVIDENCE>" in retry_content
        # KCA instruction steps
        assert "Keep all successful" in retry_content
        assert "optimizing only" in retry_content

    @pytest.mark.asyncio
    async def test_generic_fallback_no_flaw_no_missing(self):
        """When no specific flaw/missing but FAIL, generic REVISE_TARGET from fb_text."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = 0

        fail_feedback = {
            "pass": False,
            "reason": "Answer too brief",
            "feedback_to_agent": "Answer too brief",
            "missing_facts": [],
            "extracted_claims": [],
            "logical_flaw": "",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            await critic_mod._node_critic(ctx)

        retry_content = ctx.messages[-1]["content"]
        assert "<REVISE_TARGET>" in retry_content
        assert "Answer too brief" in retry_content
        # Should NOT have ADD_EVIDENCE block (no missing facts)
        # Note: the INSTRUCTION line mentions <ADD_EVIDENCE> as a tag name,
        # so we check for the actual block with content, not just the tag.
        assert "<ADD_EVIDENCE>\n" not in retry_content

    @pytest.mark.asyncio
    async def test_circuit_breaker_still_works(self):
        """Circuit breaker activates after max retries and returns FINALIZE."""
        from services.agent._nodes import _critic as critic_mod

        ctx = self._make_ctx()
        ctx.critic_rejections = _CRITIC_MAX_RETRIES  # At limit

        fail_feedback = {
            "pass": False,
            "reason": "still wrong",
            "feedback_to_agent": "still wrong",
            "missing_facts": [],
            "extracted_claims": [],
            "logical_flaw": "persistent flaw",
        }

        with (
            patch("services.agent._nodes._critic._has_tool_outputs_in_history", return_value=True),
            patch("services.agent._nodes._critic._extract_tool_history", return_value="CPU: 10%\nRAM: 50%"),
            patch(
                "services.agent._nodes._critic._run_critic_evaluation", AsyncMock(return_value=(False, fail_feedback))
            ),
            patch(
                "services.agent._nodes._critic._run_tool_selection_review",
                AsyncMock(return_value={"tool_selection_score": 80}),
            ),
        ):
            state, answer = await critic_mod._node_critic(ctx)

        assert state == AgentState.FINALIZE
        assert "SYSTEM WARNING" in answer  # User-facing fallback
        assert "CPU: 10%" in answer  # Raw tool data included
