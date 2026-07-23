"""
Regression: capability questions ("what can you do?") must NOT leak raw
ReAct JSON ({"thought":..., "tool_calls":[]}) to the user.

Root cause (fixed): the capability-intent branch zeroed _active_tools but
still built the ReAct system_prompt via generate_system_prompt_with_tools([]),
instructing the LLM to emit JSON. The Fast Path then returned that JSON
verbatim to Telegram.

Sprint 4 refactor: the capability fast-path lives in _select_tools
(_initializer_helpers.py). We test it directly — when _CAPABILITY_PATTERNS
match, it returns ([], _CONVERSATIONAL_SYSTEM) without touching the LLM.
"""

from __future__ import annotations

import asyncio

import pytest


@pytest.mark.asyncio
async def test_capability_question_uses_conversational_prompt():
    from services.agent._nodes._initializer_helpers import _select_tools
    from services.agent.prompts import _CONVERSATIONAL_SYSTEM

    # A capability question ("מה היכולות שלך?") contains a capability pattern.
    # _select_tools checks _CAPABILITY_PATTERNS after the conversational check.
    active_tools, system_prompt = await _select_tools("מה היכולות שלך?", [])

    # 1. No tools must be selected for a capability question.
    assert active_tools == [], f"Capability intent must zero tools, got {len(active_tools)}"

    # 2. The system prompt must be the conversational one.
    assert system_prompt == _CONVERSATIONAL_SYSTEM, (
        "Capability intent must use _CONVERSATIONAL_SYSTEM, not the ReAct prompt."
    )

    # 3. The conversational prompt must not mention tool_calls schema.
    assert "tool_calls" not in system_prompt, "Conversational prompt must not mention tool_calls schema."

    # 4. The ReAct JSON marker must be absent.
    assert '"thought"' not in system_prompt


@pytest.mark.asyncio
async def test_non_capability_question_gets_react_prompt():
    """Sanity: a normal actionable question must NOT get the conversational
    prompt — it should get the full ReAct system prompt with tools."""
    # Patch _is_conversational to return False (not a casual chat query)
    # and _filter_relevant_tools to return empty (no semantic match).
    from unittest.mock import AsyncMock, patch

    from services.agent import routing as rt
    from services.agent._nodes._initializer_helpers import _select_tools
    from services.agent.prompts import _CONVERSATIONAL_SYSTEM

    with (
        patch.object(rt, "_is_conversational", AsyncMock(return_value=False)),
        patch.object(rt, "_filter_relevant_tools", AsyncMock(return_value=[])),
        patch.object(rt, "_filter_relevant_skills", AsyncMock(return_value=[])),
    ):
        active_tools, system_prompt = await _select_tools("scan my network for threats", [])

    # Non-capability, non-conversational → ReAct prompt (NOT conversational).
    assert system_prompt != _CONVERSATIONAL_SYSTEM


if __name__ == "__main__":
    asyncio.run(test_capability_question_uses_conversational_prompt())
    asyncio.run(test_non_capability_question_gets_react_prompt())
    print("OK")
