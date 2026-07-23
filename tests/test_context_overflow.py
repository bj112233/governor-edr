"""
Regression tests for context_length_exceeded handling.

1. Bridge raises ContextOverflowError (not APIConnectionError) for 400s that
   contain context-overflow markers.
2. Bridge does NOT trip the circuit breaker on ContextOverflowError.
3. Core._emergency_trim_for_overflow preserves system prompt and last real
   user message, dropping middle history.
4. Core._emergency_trim_for_overflow handles messages ending in tool_output.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import openai
import pytest

# ---------------------------------------------------------------------------
# 1. Bridge: ContextOverflowError detection
# ---------------------------------------------------------------------------


def _make_br(msg: str) -> openai.BadRequestError:
    """Create a BadRequestError with required keyword args (v1.x SDK)."""
    return openai.BadRequestError(
        message=msg,
        response=MagicMock(),
        body=None,
    )


def test_is_context_overflow_match():
    from services.llm_bridge.models import _is_context_overflow

    assert _is_context_overflow(_make_br("context_length exceeded"))
    assert _is_context_overflow(_make_br("maximum context"))
    assert _is_context_overflow(_make_br("context window"))
    assert _is_context_overflow(_make_br("too many tokens"))
    assert _is_context_overflow(_make_br("tokens exceed 2048"))
    assert _is_context_overflow(_make_br("exceeds the max"))
    assert _is_context_overflow(_make_br("n_ctx"))


def test_is_context_overflow_no_match():
    from services.llm_bridge.models import _is_context_overflow

    assert not _is_context_overflow(_make_br("schema mismatch"))
    assert not _is_context_overflow(_make_br("invalid JSON"))


@pytest.mark.asyncio
async def test_agent_step_raises_context_overflow_on_400():
    from services.llm_bridge import ContextOverflowError, LLMBridge

    bridge = LLMBridge.get_instance()
    # Reset state to closed so should_accept_traffic returns True
    bridge.cb.state = "closed"
    bridge.cb.consecutive_failures = 0

    err = _make_br("context_length_exceeded")
    bridge._client = MagicMock()
    bridge._client.chat.completions.create = AsyncMock(side_effect=err)

    with pytest.raises(ContextOverflowError):
        await bridge.agent_step(messages=[{"role": "user", "content": "test"}])

    # Circuit breaker must NOT have been incremented for a payload-level error.
    assert bridge.cb.consecutive_failures == 0


@pytest.mark.asyncio
async def test_complete_raises_context_overflow_on_400():
    from services.llm_bridge import ContextOverflowError, LLMBridge

    bridge = LLMBridge.get_instance()
    bridge.cb.state = "closed"
    bridge.cb.consecutive_failures = 0

    err = _make_br("context_length_exceeded")
    client = MagicMock()
    client.chat.completions.create = AsyncMock(side_effect=err)
    bridge._client = client

    with pytest.raises(ContextOverflowError):
        await bridge.complete(system_prompt="You are Sentinel.", user_input="hello")

    assert bridge.cb.consecutive_failures == 0


# ---------------------------------------------------------------------------
# 2. Core: emergency trim preserves invariants
# ---------------------------------------------------------------------------


def test_emergency_trim_preserves_system_and_last_user():
    from services.agent.core import _emergency_trim_for_overflow

    system = {"role": "system", "content": "You are Sentinel."}
    middle_history = [
        {"role": "user", "content": "old question 1"},
        {"role": "assistant", "content": "old answer 1"},
        {"role": "user", "content": "old question 2"},
        {"role": "assistant", "content": "old answer 2"},
    ]
    last_user = {"role": "user", "content": "current question?"}
    messages = [system] + middle_history + [last_user]

    result = _emergency_trim_for_overflow(messages)

    assert result[0] is system, "system prompt was touched"
    assert result[-1] is last_user, "last user message was lost"
    assert len(result) == 2, f"expected 2 messages, got {len(result)}"


def test_emergency_trim_handles_tool_output_tail():
    from services.agent.core import _emergency_trim_for_overflow

    system = {"role": "system", "content": "You are Sentinel."}
    history = [
        {"role": "user", "content": "what is the weather?"},
        {"role": "assistant", "content": '{"thought":"...","tool_calls":[...]}'},
        {
            "role": "user",
            "content": "<tool_output>\nsunny 25C\n</tool_output>",
        },
    ]
    messages = [system] + history

    result = _emergency_trim_for_overflow(messages)

    assert result[0] is system
    # Must keep the user question AND the tool_output that follows it
    assert result[1] is history[0], "user question dropped"
    assert result[2] is history[1], "assistant response dropped"
    assert result[3] is history[2], "tool_output dropped"


def test_emergency_trim_shrinks_long_tool_output():
    from services.agent.core import _emergency_trim_for_overflow

    system = {"role": "system", "content": "You are Sentinel."}
    user_msg = {"role": "user", "content": "what is the weather?"}
    tool_out = {
        "role": "user",
        "content": "<tool_output>\n" + "A" * 2000 + "\n</tool_output>",
    }
    messages = [system, user_msg, tool_out]
    original_len = len(tool_out["content"])

    result = _emergency_trim_for_overflow(messages)

    assert result[0] is system
    assert result[1] is user_msg
    assert result[2] is tool_out
    # Current behavior: most-recent tool_output is preserved as head(1200)+tail(500)
    # with a "[trimmed for overflow]" marker. Must be smaller than the original
    # and carry the marker. (Function mutates in place — capture len first.)
    assert len(result[2]["content"]) < original_len, "tool_output was not shrunk"
    assert "[trimmed" in result[2]["content"]


def test_emergency_trim_minimal_payload():
    from services.agent.core import _emergency_trim_for_overflow

    system = {"role": "system", "content": "You are Sentinel."}
    user_msg = {"role": "user", "content": "A" * 5000}
    messages = [system, user_msg]

    result = _emergency_trim_for_overflow(messages)
    assert result[0] is system
    assert len(result) == 2
    assert "[truncated]" in result[1]["content"]


if __name__ == "__main__":
    asyncio.run(test_agent_step_raises_context_overflow_on_400())
    asyncio.run(test_complete_raises_context_overflow_on_400())
    test_emergency_trim_preserves_system_and_last_user()
    test_emergency_trim_handles_tool_output_tail()
    test_emergency_trim_shrinks_long_tool_output()
    test_emergency_trim_minimal_payload()
    print("OK")
