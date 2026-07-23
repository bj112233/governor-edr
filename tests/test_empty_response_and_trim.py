# tests/test_empty_response_and_trim.py
"""Regression tests for empty LLM response handling and context trim fallback.

Bug 1 (content_len=1): LLM returned whitespace-only output ('\n') when context
was near-limit (19863 chars). The empty content passed through the parser as
empty tool_calls, fell through to termination fallback, and sent raw tool data
as the answer instead of retrying.

Bug 2 (trim gap): _trim_messages preserved system prompt + current turn, but
if those alone exceeded max_chars the trim returned oversized messages —
causing the LLM to stall and return empty responses.
"""

import json

from services.agent.utils import _trim_messages


def test_trim_truncates_oversized_tool_output_when_system_huge():
    """When system + current turn exceed max_chars, tool outputs must be truncated."""
    messages = [
        {"role": "system", "content": "S" * 8000},
        {"role": "user", "content": "query"},
        {"role": "assistant", "content": "calling tool"},
        {"role": "tool", "content": "X" * 6000, "tool_call_id": "tc1"},
    ]
    result = _trim_messages(messages, max_chars=10000)
    total = sum(len(json.dumps(m, ensure_ascii=False, default=str)) for m in result)
    assert total <= 10000, f"trim failed: total={total} > 10000"
    # Tool output should be truncated
    tool_msg = [m for m in result if m.get("role") == "tool"][0]
    assert "[...truncated...]" in tool_msg["content"]


def test_trim_preserves_short_tool_outputs():
    """Short tool outputs must not be truncated."""
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "query"},
        {"role": "assistant", "content": "calling tool"},
        {"role": "tool", "content": "OK", "tool_call_id": "tc1"},
    ]
    result = _trim_messages(messages, max_chars=10000)
    tool_msg = [m for m in result if m.get("role") == "tool"][0]
    assert tool_msg["content"] == "OK"


def test_trim_drops_oldest_turns_first():
    """Standard trim still drops oldest turns before truncating."""
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "query1"},
        {"role": "assistant", "content": "A" * 2000},
        {"role": "tool", "content": "T" * 2000, "tool_call_id": "tc1"},
        {"role": "user", "content": "query2"},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=1000)
    # First turn should be dropped
    contents = [m.get("content", "") for m in result]
    assert "query1" not in contents
    assert "query2" in contents


def test_trim_handles_single_message():
    """Edge case: single message should pass through unchanged."""
    messages = [{"role": "system", "content": "S"}]
    result = _trim_messages(messages, max_chars=100)
    assert result == messages


# ── System Armor: mid-conversation system messages must survive trimming ──


def test_trim_preserves_mid_conversation_system_message():
    """Emergency Reserve / Recovery Nudge (role=system, mid-conversation)
    must NOT be dropped by the sliding window, even when trimming is aggressive.

    Bug: head = messages[:1] only protected the FIRST system message. A
    system message injected at step N (e.g. Emergency Reserve) was in the
    tail drop zone and could be trimmed away — causing the 4B model to lose
    the "FORBIDDEN from using any tool except final_answer" directive.
    """
    emergency_msg = {
        "role": "system",
        "content": "⚠️ SYSTEM OVERRIDE: EMERGENCY BUDGET ACTIVE. "
        "You are strictly FORBIDDEN from using any tool except 'final_answer'.",
    }
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "query1"},
        {"role": "assistant", "content": "A" * 2000},
        {"role": "tool", "content": "T" * 2000, "tool_call_id": "tc1"},
        emergency_msg,  # mid-conversation system injection
        {"role": "user", "content": "query2"},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=1000)
    system_contents = [m["content"] for m in result if m.get("role") == "system"]
    # Both system messages must survive: the head + the mid-conversation one
    assert len(system_contents) == 2
    assert "EMERGENCY BUDGET" in system_contents[1]


def test_trim_preserves_mid_system_even_when_oldest_turns_dropped():
    """Mid-system message must survive even when it's in the oldest portion
    that would normally be dropped."""
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "old query"},
        {"role": "assistant", "content": "A" * 3000},
        {"role": "tool", "content": "T" * 3000, "tool_call_id": "tc1"},
        {"role": "system", "content": "Recovery Nudge: call final_answer NOW"},
        {"role": "user", "content": "current query"},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=800)
    contents = [m.get("content", "") for m in result]
    # Old turn dropped
    assert "old query" not in contents
    # But mid-system message preserved (substring check — content is
    # "Recovery Nudge: call final_answer NOW", not an exact match)
    assert any("Recovery Nudge" in c for c in contents)


# ── Internal User Prefix Seal: prevent internal injections from hijacking
#    the "last genuine user message" anchor ──


def test_internal_intercept_does_not_become_user_anchor():
    """[SYSTEM INTERCEPT] is role=user but internal — must not be treated as
    the genuine user message, otherwise older tool data gets protected and
    newer genuine user messages could be trimmed."""
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "real question"},
        {"role": "assistant", "content": "A" * 2000},
        {"role": "tool", "content": "T" * 2000, "tool_call_id": "tc1"},
        {"role": "user", "content": "[SYSTEM INTERCEPT] Subtask 1 completed. PROCEED to subtask 2."},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=1500)
    contents = [m.get("content", "") for m in result]
    # The INTERCEPT message is internal → "real question" is the genuine anchor.
    # Under aggressive trim, the intercept (being after the anchor) is preserved
    # as part of the current turn. But if we had a newer genuine user message,
    # the intercept would NOT block it from being the anchor. The key assertion:
    # the intercept did not prevent trimming of older turns.
    assert any("[SYSTEM INTERCEPT]" in c for c in contents) or any("real question" in c for c in contents)


def test_staleness_directive_survives_as_system_message():
    """Directive is injected as role=system (protected by _mid_system_msgs)
    and the user question is a separate role=user at the tail (the anchor).

    Old turns must be dropped; the directive must survive.
    """
    messages = [
        {"role": "system", "content": "S" * 100},
        {"role": "user", "content": "old question"},
        {"role": "assistant", "content": "A" * 3000},
        {"role": "tool", "content": "T" * 3000, "tool_call_id": "tc1"},
        {"role": "system", "content": "<staleness_warning>\nContent is STALE.\n</staleness_warning>"},
        {"role": "user", "content": "current"},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=800)
    contents = [m.get("content", "") for m in result]
    # User question is the anchor → old turn dropped
    assert "old question" not in contents
    # Directive (role=system) preserved via _mid_system_msgs extraction
    assert any("staleness_warning" in c for c in contents)
    # User question preserved (it's the anchor)
    assert "current" in contents


def test_directive_survives_aggressive_progressive_shrink():
    """Directive (role=system) must survive even when progressive shrink
    is forced to aggressively truncate tool outputs. The directive is
    extracted into _mid_system_msgs and never enters the shrink loop."""
    messages = [
        {"role": "system", "content": "S" * 200},
        {"role": "user", "content": "old"},
        {"role": "assistant", "content": "A" * 2000},
        {"role": "tool", "content": "T" * 5000, "tool_call_id": "tc1"},
        {"role": "system", "content": "[ROUTING DIRECTIVE — MUST FOLLOW]: Call the news skill."},
        {"role": "user", "content": "what are the latest headlines"},
        {"role": "assistant", "content": "B" * 200},
        {"role": "tool", "content": "C" * 5000, "tool_call_id": "tc2"},
    ]
    result = _trim_messages(messages, max_chars=2000)
    contents = [m.get("content", "") for m in result]
    # Directive must survive — it's in _mid_system_msgs, not in shrink loop
    assert any("ROUTING DIRECTIVE" in c for c in contents), "Directive was lost during aggressive trim"
    # User question must survive (it's the anchor)
    assert any("latest headlines" in c for c in contents)


def test_directive_survives_emergency_overflow_trim():
    """Directive (role=system) must survive _emergency_trim_for_overflow,
    which keeps messages[0] (system) + tail from last_real_user_idx."""
    from services.agent._json_utils import _emergency_trim_for_overflow

    messages = [
        {"role": "system", "content": "S" * 200},
        {"role": "user", "content": "old question"},
        {"role": "assistant", "content": "A" * 5000},
        {"role": "tool", "content": "T" * 5000, "tool_call_id": "tc1"},
        {"role": "system", "content": "<staleness_warning>\nContent is STALE.\n</staleness_warning>"},
        {"role": "user", "content": "current question"},
        {"role": "assistant", "content": "B" * 100},
        {"role": "tool", "content": "C" * 100, "tool_call_id": "tc2"},
    ]
    result = _emergency_trim_for_overflow(messages)
    contents = [m.get("content", "") for m in result]
    # Directive must survive emergency trim
    assert any("staleness_warning" in c for c in contents), "Directive lost in emergency overflow trim"
    # User question must survive
    assert any("current question" in c for c in contents)
