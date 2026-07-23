# tests/test_critic_context_compression.py
"""Tests for _compress_context_for_retry — context compression for critic retry.

Validates that:
1. System message (messages[0] with role=="system") is preserved
2. Non-system messages are dropped
3. Rebuilt context contains single user message with tool_data + feedback + instruction
4. Handles missing system message gracefully
5. Character count is reduced (compression effective)
6. Previous draft is included for repair (not synthesis from scratch)
7. Tail-anchored output format (Few-Shot) is present
"""

from unittest.mock import MagicMock

from services.agent._context import _AgentContext
from services.agent._nodes._critic import _compress_context_for_retry


def _make_ctx(messages: list[dict]) -> _AgentContext:
    """Build a minimal _AgentContext with the given message history."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "Scan my system for threats"
    ctx.messages = messages
    ctx._tool_outputs_buffer = []
    ctx._draft_v1 = ""
    ctx.draft_answer = ""
    return ctx


def test_preserves_system_message():
    """System message (role=='system') should be preserved after compression."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "You are a security analyst."},
            {"role": "user", "content": "check cpu"},
            {"role": "assistant", "content": "<tool_output>CPU: 15%</tool_output>"},
            {"role": "user", "content": "analyze"},
        ]
    )
    _compress_context_for_retry(ctx, "feedback text", "instruction text")
    assert len(ctx.messages) == 2
    assert ctx.messages[0]["role"] == "system"
    assert ctx.messages[0]["content"] == "You are a security analyst."


def test_drops_non_system_messages():
    """All non-system messages should be replaced by a single user message."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "x" * 500},
            {"role": "assistant", "content": "y" * 500},
            {"role": "user", "content": "z" * 500},
        ]
    )
    _compress_context_for_retry(ctx, "fb", "instr")
    # Should be: [system_msg, single_user_msg]
    assert len(ctx.messages) == 2
    assert ctx.messages[1]["role"] == "user"


def test_user_message_contains_tool_data():
    """Rebuilt user message should contain [RAW TOOL DATA] block."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "<tool_output>CPU: 15%</tool_output>"},
        ]
    )
    _compress_context_for_retry(ctx, "my feedback", "my instruction")
    content = ctx.messages[1]["content"]
    assert "[RAW TOOL DATA]" in content
    assert "CPU: 15%" in content


def test_user_message_contains_feedback_and_instruction():
    """Rebuilt user message should contain feedback and instruction."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
        ]
    )
    _compress_context_for_retry(ctx, "SPECIAL_FEEDBACK_MARKER", "SPECIAL_INSTRUCTION_MARKER")
    content = ctx.messages[1]["content"]
    assert "SPECIAL_FEEDBACK_MARKER" in content
    assert "SPECIAL_INSTRUCTION_MARKER" in content


def test_user_message_contains_previous_draft():
    """Rebuilt user message should contain [YOUR PREVIOUS DRAFT] block."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
        ]
    )
    ctx.draft_answer = "## DRAFT REPORT V1\nCPU is fine."
    _compress_context_for_retry(ctx, "fb", "instr")
    content = ctx.messages[1]["content"]
    assert "[YOUR PREVIOUS DRAFT]" in content
    assert "DRAFT REPORT V1" in content


def test_draft_v1_saved_on_first_compression():
    """_draft_v1 should be saved from draft_answer on first compression."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
        ]
    )
    ctx.draft_answer = "ORIGINAL DRAFT TEXT"
    _compress_context_for_retry(ctx, "fb", "instr")
    assert ctx._draft_v1 == "ORIGINAL DRAFT TEXT"


def test_draft_v1_not_overwritten_on_second_compression():
    """_draft_v1 should NOT be overwritten on subsequent compressions."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
        ]
    )
    ctx._draft_v1 = "FIRST DRAFT"
    ctx.draft_answer = "SECOND DRAFT"
    _compress_context_for_retry(ctx, "fb", "instr")
    assert ctx._draft_v1 == "FIRST DRAFT"


def test_tail_anchored_output_format_present():
    """Output format (Few-Shot) should be tail-anchored at end of message."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
        ]
    )
    _compress_context_for_retry(ctx, "fb", "instr")
    content = ctx.messages[1]["content"]
    assert "Action: final_answer" in content
    assert 'Action Input: {"text"' in content
    assert "Do NOT just write a thought" in content


def test_no_system_message_handled():
    """When messages[0] is not system, no system message is preserved."""
    ctx = _make_ctx(
        [
            {"role": "user", "content": "check cpu"},
            {"role": "assistant", "content": "ok"},
        ]
    )
    _compress_context_for_retry(ctx, "fb", "instr")
    # Should be: [single_user_msg] (no system message)
    assert len(ctx.messages) == 1
    assert ctx.messages[0]["role"] == "user"


def test_empty_messages_handled():
    """Empty messages list should not crash."""
    ctx = _make_ctx([])
    _compress_context_for_retry(ctx, "fb", "instr")
    assert len(ctx.messages) == 1
    assert ctx.messages[0]["role"] == "user"


def test_compression_reduces_char_count():
    """Post-compression char count should be less than pre-compression for large histories."""
    ctx = _make_ctx(
        [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "A" * 2000},
            {"role": "assistant", "content": "B" * 2000},
            {"role": "user", "content": "C" * 2000},
        ]
    )
    pre_chars = sum(len(m.get("content", "")) for m in ctx.messages)
    _compress_context_for_retry(ctx, "short fb", "short instr")
    post_chars = sum(len(m.get("content", "")) for m in ctx.messages)
    assert post_chars < pre_chars


def test_tool_data_truncated_when_over_budget():
    """Large tool_data should be truncated to fit the data budget."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "test"
    ctx.messages = [{"role": "system", "content": "sys"}]
    ctx._tool_outputs_buffer = [{"name": "scan", "result": "X" * 2000}]
    ctx._draft_v1 = ""
    ctx.draft_answer = ""
    _compress_context_for_retry(ctx, "fb", "instr")
    content = ctx.messages[1]["content"]
    assert "[...truncated]" in content


def test_draft_truncated_when_over_budget():
    """Large previous draft should be truncated to fit the draft budget."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "test"
    ctx.messages = [{"role": "system", "content": "sys"}]
    ctx._tool_outputs_buffer = []
    ctx._draft_v1 = ""
    ctx.draft_answer = "Y" * 2000
    _compress_context_for_retry(ctx, "fb", "instr")
    # tool_data is empty here, so the only truncation marker comes from the draft
    assert "[...truncated]" in ctx.messages[1]["content"]


def test_tool_outputs_buffer_merged():
    """_tool_outputs_buffer entries should appear in tool_data."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.user_question = "test"
    ctx.messages = [{"role": "system", "content": "sys"}]
    ctx._tool_outputs_buffer = [{"name": "scan_lan", "result": "192.168.1.1 open"}]
    ctx._draft_v1 = ""
    ctx.draft_answer = ""
    _compress_context_for_retry(ctx, "fb", "instr")
    content = ctx.messages[1]["content"]
    assert "scan_lan" in content
    assert "192.168.1.1 open" in content
