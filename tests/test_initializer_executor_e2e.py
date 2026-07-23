# tests/test_initializer_executor_e2e.py
"""Comprehensive tests for agent initialization and executor phases.

Covers:
- _initializer_helpers: _select_tools, _inject_memory, _load_recent_history,
  _enforce_token_ceiling, _build_history_messages, _inject_directive
- _initializer: _run_pre_compute, _apply_tool_visibility, _build_agent_context,
  _node_initialize
- _executor: _compute_max_tokens
- _executor_phases: llm_call, _process_single_tool_call, partition_tool_calls,
  apply_resource_guard

Run:  .venv\\Scripts\\python.exe -m pytest tests/test_initializer_executor_e2e.py -v --tb=short -p no:warnings
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import AgentState, _AgentContext
from services.agent._nodes._executor import _compute_max_tokens
from services.agent._nodes._executor_phases import (
    _process_single_tool_call,
    apply_resource_guard,
    llm_call,
    partition_tool_calls,
)
from services.agent._nodes._initializer import (
    _apply_tool_visibility,
    _build_agent_context,
    _node_initialize,
    _run_pre_compute,
)
from services.agent._nodes._initializer_helpers import (
    _build_history_messages,
    _enforce_token_ceiling,
    _inject_directive,
    _inject_memory,
    _load_recent_history,
    _select_tools,
)
from services.agent.prompts import _CONVERSATIONAL_SYSTEM

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


class _FakeMsg:
    """Minimal stand-in for an LLM response message."""

    def __init__(self, content: str):
        self.content = content


def _tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name}}


def _ctx(**kw) -> _AgentContext:
    defaults = {"user_question": "test query", "max_steps": 10}
    defaults.update(kw)
    return _AgentContext(**defaults)


# ──────────────────────────────────────────────────────────────────────────────
# _select_tools
# ──────────────────────────────────────────────────────────────────────────────


async def test_select_tools_conversational_path_returns_empty():
    """Conversational query → empty tools + _CONVERSATIONAL_SYSTEM."""
    # _is_conversational is imported INSIDE _select_tools via `from ..routing import`,
    # so we must patch the source module, not _initializer_helpers.
    with patch(
        "services.agent.routing._is_conversational",
        new=AsyncMock(return_value=True),
    ):
        tools, prompt = await _select_tools("hi there", [])

    assert tools == []
    assert prompt == _CONVERSATIONAL_SYSTEM


async def test_select_tools_capability_intent_bypass():
    """Capability-intent question (after conversational=False) → bypass all tools."""
    from services.agent import routing as rt

    with (
        patch.object(rt, "_is_conversational", AsyncMock(return_value=False)),
        patch(
            "services.agent._nodes._initializer_helpers._filter_relevant_tools",
            new=AsyncMock(return_value=[]),
        ),
    ):
        tools, prompt = await _select_tools("מה היכולות שלך?", [])

    assert tools == []
    assert prompt == _CONVERSATIONAL_SYSTEM


async def test_select_tools_no_semantic_match_falls_back_to_basic():
    """No semantic match for system tools → _TOOLS_BASIC fallback + ReAct prompt."""
    from services.agent import routing as rt

    with (
        patch.object(rt, "_is_conversational", AsyncMock(return_value=False)),
        patch(
            "services.agent._nodes._initializer_helpers._filter_relevant_tools",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._filter_relevant_skills",
            new=AsyncMock(return_value=[]),
        ),
        # _rank_tools_by_history is imported INSIDE _select_tools from .._tool_ranker
        patch(
            "services.agent._tool_ranker._rank_tools_by_history",
            AsyncMock(side_effect=lambda tools, q, **kw: tools),
        ),
    ):
        tools, prompt = await _select_tools("scan my network for threats", [])

    assert prompt != _CONVERSATIONAL_SYSTEM
    # final_answer is always appended
    names = [t.get("function", {}).get("name") for t in tools]
    assert "final_answer" in names


async def test_select_tools_adaptive_ranking_called():
    """Adaptive tool ranking (_rank_tools_by_history) is invoked on selected tools."""
    from services.agent import routing as rt

    _ranked_seen: list = []

    async def _fake_rank(tools, q, **kw):
        _ranked_seen.append(list(tools))
        return tools

    with (
        patch.object(rt, "_is_conversational", AsyncMock(return_value=False)),
        patch(
            "services.agent._nodes._initializer_helpers._filter_relevant_tools",
            new=AsyncMock(return_value=[_tool("get_system_snapshot"), _tool("get_process_list")]),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._filter_relevant_skills",
            new=AsyncMock(return_value=[]),
        ),
        # _rank_tools_by_history is imported INSIDE _select_tools from .._tool_ranker
        patch(
            "services.agent._tool_ranker._rank_tools_by_history",
            side_effect=_fake_rank,
        ),
    ):
        tools, _ = await _select_tools("check system status", [])

    assert len(_ranked_seen) == 1
    assert len(_ranked_seen[0]) >= 2


# ──────────────────────────────────────────────────────────────────────────────
# _inject_memory
# ──────────────────────────────────────────────────────────────────────────────


async def test_inject_memory_recall_context_failure_continues():
    """recall_context raises → system_prompt unchanged for that block, no crash."""
    with (
        patch(
            "services.agent._nodes._initializer_helpers.recall_context",
            AsyncMock(side_effect=RuntimeError("db down")),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._get_lessons_for_prompt",
            AsyncMock(return_value=[]),
        ),
        patch(
            "services.memory_summarizer.get_latest_user_profile",
            AsyncMock(return_value=None),
        ),
    ):
        result = await _inject_memory("base prompt", "question")

    assert result == "base prompt"


async def test_inject_memory_lessons_failure_continues():
    """Lessons fetch raises → no lessons block, prompt still returned."""
    with (
        patch(
            "services.agent._nodes._initializer_helpers.recall_context",
            AsyncMock(return_value=None),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._get_lessons_for_prompt",
            AsyncMock(side_effect=RuntimeError("lessons db down")),
        ),
        patch(
            "services.memory_summarizer.get_latest_user_profile",
            AsyncMock(return_value=None),
        ),
    ):
        result = await _inject_memory("base", "q")

    assert result == "base"


async def test_inject_memory_profile_failure_continues():
    """Profile fetch raises → no profile block, prompt still returned."""
    with (
        patch(
            "services.agent._nodes._initializer_helpers.recall_context",
            AsyncMock(return_value=None),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._get_lessons_for_prompt",
            AsyncMock(return_value=[]),
        ),
        patch(
            "services.memory_summarizer.get_latest_user_profile",
            AsyncMock(side_effect=RuntimeError("profile err")),
        ),
    ):
        result = await _inject_memory("base", "q")

    assert result == "base"


async def test_inject_memory_all_success_appends_blocks():
    """All three sources succeed → all blocks appended."""
    with (
        patch(
            "services.agent._nodes._initializer_helpers.recall_context",
            AsyncMock(return_value="recall data"),
        ),
        patch(
            "services.agent._nodes._initializer_helpers._get_lessons_for_prompt",
            AsyncMock(return_value=[{"tool": "x", "resolution": "fix"}]),
        ),
        patch(
            "services.memory_summarizer.get_latest_user_profile",
            AsyncMock(return_value='{"name":"bob"}'),
        ),
        patch(
            "services.agent._nodes._initializer_helpers.format_lessons_for_prompt",
            return_value="LESSON: fix",
        ),
    ):
        result = await _inject_memory("base", "q")

    assert "[Relevant context from memory]:recall data" in result
    assert "[Operational lessons from past errors]" in result
    assert "[User profile]" in result


# ──────────────────────────────────────────────────────────────────────────────
# _load_recent_history
# ──────────────────────────────────────────────────────────────────────────────


async def test_load_recent_history_memory_service_failure_returns_empty():
    """get_memory_service raises → empty messages, no crash."""
    with patch(
        "services.agent._nodes._initializer_helpers.get_memory_service",
        side_effect=RuntimeError("svc unavailable"),
    ):
        msgs, count = await _load_recent_history("question")

    assert msgs == []
    assert count == 0


async def test_load_recent_history_short_response_skipped():
    """Response shorter than 10 chars or non-alphanumeric → skipped."""
    from services.bot_memory.models import MemoryEntry

    entries = [
        MemoryEntry(query="prev q", response="ab"),  # too short
        MemoryEntry(query="prev q2", response="!!!"),  # no alphanumeric
    ]
    svc = MagicMock()
    svc.get_recent = AsyncMock(return_value=entries)
    with patch(
        "services.agent._nodes._initializer_helpers.get_memory_service",
        return_value=svc,
    ):
        msgs, count = await _load_recent_history("current question")

    # Both responses skipped; only user messages for matching queries added
    # (entries are reversed, query != user_question so user msg appended)
    assert count >= 0
    assistant_msgs = [m for m in msgs if m["role"] == "assistant"]
    assert assistant_msgs == []


async def test_load_recent_history_response_truncation():
    """Response > 1200 chars → truncated to last 1200."""
    from services.bot_memory.models import MemoryEntry

    long_resp = "A" * 2000
    entries = [MemoryEntry(query="other q", response=long_resp)]
    svc = MagicMock()
    svc.get_recent = AsyncMock(return_value=entries)
    with patch(
        "services.agent._nodes._initializer_helpers.get_memory_service",
        return_value=svc,
    ):
        msgs, _ = await _load_recent_history("current question")

    assistant_msgs = [m for m in msgs if m["role"] == "assistant"]
    assert len(assistant_msgs) == 1
    # Content wrapped + truncated to last 1200 chars
    content = assistant_msgs[0]["content"]
    assert len(content) <= 1200 + len("<previous_turn>\n\n</previous_turn>")


# ──────────────────────────────────────────────────────────────────────────────
# _enforce_token_ceiling
# ──────────────────────────────────────────────────────────────────────────────


async def test_enforce_token_ceiling_more_than_six_messages_trimmed():
    """>6 messages → sliding window keeps last 6."""
    msgs = [{"role": "user", "content": f"msg{i}"} for i in range(10)]
    with patch(
        "services.agent._nodes._initializer_helpers._count_tokens",
        AsyncMock(return_value=10),
    ):
        result = await _enforce_token_ceiling(msgs)

    assert len(result) == 6
    assert result[0]["content"] == "msg4"


async def test_enforce_token_ceiling_trims_to_last_user():
    """Token ceiling exceeded → trims to last user message onwards."""
    msgs = [
        {"role": "user", "content": "old"},
        {"role": "assistant", "content": "resp"},
        {"role": "user", "content": "new question"},
        {"role": "assistant", "content": "resp2"},
    ]
    # First call over limit, second (after trim) under limit
    call_count = [0]

    async def _fake_count(m):
        call_count[0] += 1
        if call_count[0] == 1:
            return 999999  # over limit
        return 10  # under limit after trim

    with patch(
        "services.agent._nodes._initializer_helpers._count_tokens",
        side_effect=_fake_count,
    ):
        result = await _enforce_token_ceiling(msgs)

    # Trimmed to last user message (index 2)
    assert result[0]["content"] == "new question"


async def test_enforce_token_ceiling_no_user_message_breaks_loop():
    """No user message in messages → loop breaks, returns as-is (after window)."""
    msgs = [
        {"role": "assistant", "content": "r1"},
        {"role": "assistant", "content": "r2"},
        {"role": "assistant", "content": "r3"},
    ]
    with patch(
        "services.agent._nodes._initializer_helpers._count_tokens",
        AsyncMock(return_value=999999),
    ):
        result = await _enforce_token_ceiling(msgs)

    # No user message → break immediately; all 3 kept (≤6)
    assert len(result) == 3


# ──────────────────────────────────────────────────────────────────────────────
# _build_history_messages
# ──────────────────────────────────────────────────────────────────────────────


async def test_build_history_messages_integration():
    """_build_history_messages calls load + ceiling enforcement."""
    from services.bot_memory.models import MemoryEntry

    entries = [MemoryEntry(query="other", response="a valid response here")]
    svc = MagicMock()
    svc.get_recent = AsyncMock(return_value=entries)
    with (
        patch(
            "services.agent._nodes._initializer_helpers.get_memory_service",
            return_value=svc,
        ),
        patch(
            "services.agent._nodes._initializer_helpers._count_tokens",
            AsyncMock(return_value=10),
        ),
    ):
        msgs, count = await _build_history_messages("current question")

    assert isinstance(msgs, list)
    assert count >= 1  # at least the user message for "other"


# ──────────────────────────────────────────────────────────────────────────────
# _inject_directive
# ──────────────────────────────────────────────────────────────────────────────


def test_inject_directive_match_injects_system_message():
    """Directive match → system message injected + user question appended."""
    messages = [{"role": "system", "content": "sys"}]
    fake_registry = MagicMock()
    fake_registry.match = MagicMock(return_value=("my_directive", "DIRECTIVE_TEXT"))

    with patch(
        "services.agent.directives.directive_registry",
        fake_registry,
    ):
        result = _inject_directive(messages, "question", [_tool("scan")], 0)

    # system directive injected, then user question
    assert any(m["role"] == "system" and m["content"] == "DIRECTIVE_TEXT" for m in result)
    assert result[-1] == {"role": "user", "content": "question"}


def test_inject_directive_no_match_appends_user_question():
    """No directive match → only user question appended."""
    messages = [{"role": "system", "content": "sys"}]
    fake_registry = MagicMock()
    fake_registry.match = MagicMock(return_value=None)

    with patch(
        "services.agent.directives.directive_registry",
        fake_registry,
    ):
        result = _inject_directive(messages, "question", [], 0)

    assert result[-1] == {"role": "user", "content": "question"}
    assert len(result) == 2  # original system + user


# ──────────────────────────────────────────────────────────────────────────────
# _run_pre_compute
# ──────────────────────────────────────────────────────────────────────────────


async def test_run_pre_compute_exception_returns_prompt_unchanged():
    """pre_compute raises → (system_prompt, None, "") returned, no crash."""
    with patch(
        "services.pre_compute_router.pre_compute",
        AsyncMock(side_effect=RuntimeError("pre-compute fail")),
    ):
        prompt, intent, hard_facts = await _run_pre_compute("question", "sys prompt")

    assert prompt == "sys prompt"
    assert intent is None
    assert hard_facts == ""


async def test_run_pre_compute_success_injects_facts():
    """pre_compute succeeds → hard facts injected, intent returned."""
    fake_report = MagicMock()
    fake_report.intent = {"intent": "threat_hunt"}
    fake_report.enriched = []

    with (
        patch(
            "services.pre_compute_router.pre_compute",
            AsyncMock(return_value=fake_report),
        ),
        patch(
            "services.pre_compute_router.format_pre_compute_facts",
            return_value="HARD_FACTS",
        ),
    ):
        prompt, intent, hard_facts = await _run_pre_compute("question", "sys")

    assert "HARD_FACTS" in prompt
    assert intent == "threat_hunt"
    assert hard_facts == "HARD_FACTS"


# ──────────────────────────────────────────────────────────────────────────────
# _apply_tool_visibility
# ──────────────────────────────────────────────────────────────────────────────


def test_apply_tool_visibility_exception_returns_active_tools():
    """filter_tools_by_intent raises → active_tools returned unchanged."""
    tools = [_tool("a"), _tool("b")]
    with patch(
        "services.tools.tool_visibility.filter_tools_by_intent",
        side_effect=RuntimeError("visibility fail"),
    ):
        result = _apply_tool_visibility(tools, "some_intent")

    assert result == tools


def test_apply_tool_visibility_success_filters():
    """filter_tools_by_intent succeeds → filtered list returned."""
    tools = [_tool("a"), _tool("b"), _tool("c")]
    with patch(
        "services.tools.tool_visibility.filter_tools_by_intent",
        return_value=[_tool("a")],
    ):
        result = _apply_tool_visibility(tools, "intent_x")

    assert len(result) == 1
    assert result[0]["function"]["name"] == "a"


# ──────────────────────────────────────────────────────────────────────────────
# _build_agent_context
# ──────────────────────────────────────────────────────────────────────────────


async def test_build_agent_context_bypass_response():
    """Bypass handler returns response → context with bypass_response, empty tools."""

    async def _bypass_handler(q):
        return "bypass answer"

    with (
        patch("services.agent._nodes._initializer._BYPASS_HANDLERS", [_bypass_handler]),
        patch("services.agent._nodes._initializer._store_message", new=AsyncMock()),
        patch("services.agent._nodes._initializer._fire_and_forget"),
    ):
        ctx = await _build_agent_context("bypass question")

    assert ctx.bypass_response == "bypass answer"
    assert ctx.active_tools == []
    assert ctx.messages == []


async def test_build_agent_context_llm_not_ready():
    """is_llm_ready False → context with is_llm_ready=False, empty tools."""
    with (
        patch("services.agent._nodes._initializer._BYPASS_HANDLERS", []),
        patch("services.agent._nodes._initializer.is_llm_ready", return_value=False),
    ):
        ctx = await _build_agent_context("question")

    assert ctx.is_llm_ready is False
    assert ctx.active_tools == []


async def test_build_agent_context_no_skills_no_tools_conversational():
    """No skills + conversational query → empty tools, conversational prompt."""
    fake_skills_engine = MagicMock()
    fake_skills_engine.get_tools = MagicMock(return_value=[])

    with (
        patch("services.agent._nodes._initializer._BYPASS_HANDLERS", []),
        patch("services.agent._nodes._initializer.is_llm_ready", return_value=True),
        patch("services.agent._nodes._initializer.get_skills_engine", return_value=fake_skills_engine),
        # _search_lessons is imported INSIDE _build_agent_context from services.error_memory
        patch(
            "services.error_memory.search_lessons",
            AsyncMock(return_value=[]),
        ),
        patch(
            "services.agent._nodes._initializer._select_tools",
            AsyncMock(return_value=([], _CONVERSATIONAL_SYSTEM)),
        ),
        patch(
            "services.agent._nodes._initializer._run_pre_compute",
            AsyncMock(return_value=("sys", None, "")),
        ),
        patch(
            "services.agent._nodes._initializer._inject_memory",
            AsyncMock(return_value="sys"),
        ),
        patch(
            "services.agent._nodes._initializer._build_history_messages",
            AsyncMock(return_value=([], 0)),
        ),
        patch(
            "services.agent._nodes._initializer._inject_directive",
            side_effect=lambda m, q, t, h: m + [{"role": "user", "content": q}],
        ),
    ):
        ctx = await _build_agent_context("hi")

    assert ctx.active_tools == []
    assert ctx.step_max_tokens == 1024  # no tools → 1024


# ──────────────────────────────────────────────────────────────────────────────
# _node_initialize
# ──────────────────────────────────────────────────────────────────────────────


async def test_node_initialize_bypass_routes_to_finalize():
    """Bypass response set → FINALIZE with bypass response."""
    ctx = _ctx()
    ctx.bypass_response = "bypass answer"

    with (
        patch("services.agent._nodes._initializer._fire_and_forget"),
        patch(
            "services.agent._nodes._initializer._build_agent_context",
            AsyncMock(return_value=ctx),
        ),
    ):
        state, output = await _node_initialize(ctx)

    assert state == AgentState.FINALIZE
    assert output == "bypass answer"


async def test_node_initialize_llm_not_ready_routes_to_finalize():
    """is_llm_ready False → FINALIZE with loading message."""
    built = _ctx()
    built.is_llm_ready = False
    built.bypass_response = None

    ctx = _ctx()
    with (
        patch("services.agent._nodes._initializer._fire_and_forget"),
        patch(
            "services.agent._nodes._initializer._build_agent_context",
            AsyncMock(return_value=built),
        ),
    ):
        state, output = await _node_initialize(ctx)

    assert state == AgentState.FINALIZE
    assert "מנוע ה-AI" in output


async def test_node_initialize_no_tools_conversational_routes_to_finalize():
    """No active tools → conversational path → FINALIZE with LLM answer."""
    built = _ctx()
    built.active_tools = []
    built.messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    built.step_max_tokens = 1024
    built.is_llm_ready = True
    built.bypass_response = None

    ctx = _ctx()
    fake_engine = MagicMock()
    fake_engine.agent_step = AsyncMock(return_value=_FakeMsg("Hello! How can I help?"))

    with (
        patch("services.agent._nodes._initializer._fire_and_forget"),
        patch(
            "services.agent._nodes._initializer._build_agent_context",
            AsyncMock(return_value=built),
        ),
        patch("services.agent._nodes._initializer.LLMBridge") as mock_bridge,
        patch("services.agent._nodes._initializer.async_store_conversation", new=AsyncMock()),
    ):
        mock_bridge.get_instance.return_value = fake_engine
        state, output = await _node_initialize(ctx)

    assert state == AgentState.FINALIZE
    assert output == "Hello! How can I help?"


# ──────────────────────────────────────────────────────────────────────────────
# _compute_max_tokens
# ──────────────────────────────────────────────────────────────────────────────


def test_compute_max_tokens_subtask_mode_caps_at_768():
    """Subtask mode (current_subtask_idx >= 0) → min(step_max, 768)."""
    ctx = _ctx(step_max_tokens=1500)
    ctx.subtasks = [{"id": 1, "description": "do", "status": "pending"}]
    ctx.current_subtask_idx = 0

    result = _compute_max_tokens(ctx)
    assert result == 768


def test_compute_max_tokens_subtask_mode_lower_step_max_wins():
    """If step_max < 768 in subtask mode → step_max returned."""
    ctx = _ctx(step_max_tokens=500)
    ctx.subtasks = [{"id": 1, "description": "do", "status": "pending"}]
    ctx.current_subtask_idx = 0

    result = _compute_max_tokens(ctx)
    assert result == 500


def test_compute_max_tokens_schema_fatigue_nudge():
    """Tool outputs in history + step>=2 → expanded tokens + nudge injected."""
    ctx = _ctx(step_max_tokens=1500, step_count=2)
    ctx._last_raw_tool_result = "data"
    ctx.messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "q"}]
    ctx._schema_nudge_injected = False

    result = _compute_max_tokens(ctx)

    assert result == 6000
    assert ctx._schema_nudge_injected is True
    # Nudge message appended
    assert any("system_reminder" in m.get("content", "") for m in ctx.messages)


def test_compute_max_tokens_default_returns_step_max():
    """No subtask, no tool outputs → step_max_tokens returned."""
    ctx = _ctx(step_max_tokens=1500, step_count=0)

    result = _compute_max_tokens(ctx)
    assert result == 1500


# ──────────────────────────────────────────────────────────────────────────────
# llm_call
# ──────────────────────────────────────────────────────────────────────────────


async def test_llm_call_context_overflow_first_retry_succeeds():
    """First ContextOverflowError → trim + retry succeeds."""
    from services.llm_bridge.models import ContextOverflowError

    ctx = _ctx()
    ctx.engine = MagicMock()
    ctx.engine.agent_step = AsyncMock(side_effect=[ContextOverflowError("overflow"), _FakeMsg("recovered response")])

    with patch(
        "services.agent._nodes._executor_phases._emergency_trim_for_overflow",
        side_effect=lambda m: m,
    ):
        content, err_state, err_msg = await llm_call(ctx, 1500)

    assert content == "recovered response"
    assert err_state is None
    assert err_msg is None


async def test_llm_call_double_overflow_routes_to_error():
    """Double ContextOverflowError → ERROR state."""
    from services.llm_bridge.models import ContextOverflowError

    ctx = _ctx()
    ctx.engine = MagicMock()
    ctx.engine.agent_step = AsyncMock(side_effect=ContextOverflowError("overflow"))

    with patch(
        "services.agent._nodes._executor_phases._emergency_trim_for_overflow",
        side_effect=lambda m: m,
    ):
        content, err_state, err_msg = await llm_call(ctx, 1500)

    assert content is None
    assert err_state == AgentState.ERROR
    assert "חרג" in err_msg


async def test_llm_call_empty_response_nudge():
    """Empty response at step>0 → nudge message + retry."""
    ctx = _ctx(step_count=1)
    ctx.engine = MagicMock()
    ctx.engine.agent_step = AsyncMock(side_effect=[_FakeMsg("   "), _FakeMsg("real answer")])

    content, err_state, err_msg = await llm_call(ctx, 1500)

    assert content == "real answer"
    assert err_state is None
    # Nudge message was appended
    assert any("CRITICAL" in m.get("content", "") for m in ctx.messages)


async def test_llm_call_empty_response_step0_no_nudge():
    """Empty response at step 0 → no nudge, empty content returned."""
    ctx = _ctx(step_count=0)
    ctx.engine = MagicMock()
    ctx.engine.agent_step = AsyncMock(return_value=_FakeMsg(""))

    content, err_state, err_msg = await llm_call(ctx, 1500)

    assert content == ""
    assert err_state is None
    assert err_msg is None


# ──────────────────────────────────────────────────────────────────────────────
# _process_single_tool_call
# ──────────────────────────────────────────────────────────────────────────────


async def test_process_single_tool_call_late_binding_placeholder():
    """{{TASK_1_OUTPUT}} placeholder resolved via _task_results."""
    ctx = _ctx()
    ctx._task_results = {"1": "resolved data"}
    tool_call = {"name": "some_tool", "arguments": {"input": "{{TASK_1_OUTPUT}}"}}
    allowed = {"some_tool", "final_answer"}

    with (
        patch(
            "services.agent._nodes._executor_phases._resolve_task_placeholders",
            side_effect=lambda args, results: {"input": "resolved data"},
        ),
        patch(
            "services.agent._nodes._executor_phases._check_authorization",
            AsyncMock(return_value=True),
        ),
        patch("services.agent._nodes._executor_phases._handle_error_lesson"),
        patch(
            "services.agent._nodes._executor_phases.build_call_key",
            return_value=(0, "some_tool", "abc123"),
        ),
        patch(
            "services.agent._nodes._executor_phases.handle_loop",
            AsyncMock(return_value=(False, None, None)),
        ),
        patch("services.agent._nodes._executor_phases.is_volatile_tool", return_value=False),
    ):
        result = await _process_single_tool_call(ctx, tool_call, "thought", allowed)

    assert result is not None
    fn_name, fn_args, call_key = result
    assert fn_args == {"input": "resolved data"}


async def test_process_single_tool_call_blocked_tool_returns_none():
    """Tool in _blocked_tools → _handle_blocked_tool called, returns None."""
    ctx = _ctx()
    ctx._blocked_tools = {"bad_tool"}
    tool_call = {"name": "bad_tool", "arguments": {}}
    allowed = {"bad_tool", "final_answer"}

    with patch("services.agent._nodes._executor_phases._handle_blocked_tool") as mock_blocked:
        result = await _process_single_tool_call(ctx, tool_call, "thought", allowed)

    assert result is None
    mock_blocked.assert_called_once_with(ctx, "bad_tool")


async def test_process_single_tool_call_unauthorized_tool_returns_none():
    """Tool not in allowed set → _check_authorization False, returns None."""
    ctx = _ctx()
    tool_call = {"name": "evil_tool", "arguments": {}}
    allowed = {"final_answer"}

    with (
        patch(
            "services.agent._nodes._executor_phases._resolve_tool_name",
            side_effect=lambda fn, tc, _al: fn,
        ),
        patch(
            "services.agent._nodes._executor_phases._check_authorization",
            AsyncMock(return_value=False),
        ),
    ):
        result = await _process_single_tool_call(ctx, tool_call, "thought", allowed)

    assert result is None


async def test_process_single_tool_call_loop_detection_early_exit():
    """Loop detected → returns (fn_name, fn_args, (next_state, output))."""
    ctx = _ctx()
    tool_call = {"name": "get_system_snapshot", "arguments": {}}
    allowed = {"get_system_snapshot", "final_answer"}

    with (
        patch(
            "services.agent._nodes._executor_phases._check_authorization",
            AsyncMock(return_value=True),
        ),
        patch("services.agent._nodes._executor_phases._handle_error_lesson"),
        patch(
            "services.agent._nodes._executor_phases.build_call_key",
            return_value=(0, "get_system_snapshot", "abc"),
        ),
        patch(
            "services.agent._nodes._executor_phases.handle_loop",
            AsyncMock(return_value=(True, AgentState.EXECUTE, None)),
        ),
    ):
        result = await _process_single_tool_call(ctx, tool_call, "thought", allowed)

    assert result is not None
    fn_name, fn_args, call_key = result
    assert fn_name == "get_system_snapshot"
    # call_key is the (next_state, output) tuple from loop detection
    assert call_key == (AgentState.EXECUTE, None)


async def test_process_single_tool_call_cross_subtask_cache_hit():
    """Cross-subtask cache hit → cached result injected, returns None."""
    ctx = _ctx()
    ctx.subtasks = [{"id": 1, "description": "do", "status": "pending"}]
    ctx.current_subtask_idx = 0
    ctx._cross_subtask_cache = {("cached_tool", "args_hash"): "cached result here"}
    tool_call = {"name": "cached_tool", "arguments": {"x": 1}}
    allowed = {"cached_tool", "final_answer"}

    with (
        patch(
            "services.agent._nodes._executor_phases._check_authorization",
            AsyncMock(return_value=True),
        ),
        patch("services.agent._nodes._executor_phases._handle_error_lesson"),
        patch(
            "services.agent._nodes._executor_phases.build_call_key",
            return_value=(0, "cached_tool", "args_hash"),
        ),
        patch(
            "services.agent._nodes._executor_phases.handle_loop",
            AsyncMock(return_value=(False, None, None)),
        ),
        patch("services.agent._nodes._executor_phases.is_volatile_tool", return_value=False),
    ):
        result = await _process_single_tool_call(ctx, tool_call, "thought", allowed)

    assert result is None
    # Cached result injected into messages
    assert any("cached result here" in m.get("content", "") for m in ctx.messages)


# ──────────────────────────────────────────────────────────────────────────────
# partition_tool_calls
# ──────────────────────────────────────────────────────────────────────────────


async def test_partition_tool_calls_loop_exit_early_return():
    """Loop detection early exit → returns (safe, critical, next_state, output)."""
    ctx = _ctx()
    tool_calls = [{"name": "get_system_snapshot", "arguments": {}}]
    allowed = {"get_system_snapshot", "final_answer"}

    with patch(
        "services.agent._nodes._executor_phases._process_single_tool_call",
        AsyncMock(return_value=("get_system_snapshot", {}, (AgentState.EXECUTE, "loop output"))),
    ):
        safe, critical, state, output = await partition_tool_calls(ctx, tool_calls, "thought", allowed)

    assert state == AgentState.EXECUTE
    assert output == "loop output"


async def test_partition_tool_calls_final_answer_is_critical():
    """final_answer → routed to critical_calls."""
    ctx = _ctx()
    tool_calls = [{"name": "final_answer", "arguments": {"text": "answer"}}]
    allowed = {"final_answer"}

    with patch(
        "services.agent._nodes._executor_phases._process_single_tool_call",
        AsyncMock(return_value=("final_answer", {"text": "answer"}, ("", ""))),
    ):
        safe, critical, state, output = await partition_tool_calls(ctx, tool_calls, "thought", allowed)

    assert len(critical) == 1
    assert len(safe) == 0
    assert state is None


async def test_partition_tool_calls_safe_vs_critical_partition():
    """Safe tool → safe_calls; critical tool → critical_calls."""
    ctx = _ctx()
    tool_calls = [
        {"name": "get_system_snapshot", "arguments": {}},
        {"name": "block_ip", "arguments": {"ip": "1.2.3.4"}},
    ]
    allowed = {"get_system_snapshot", "block_ip", "final_answer"}

    with (
        patch(
            "services.agent._nodes._executor_phases._process_single_tool_call",
            AsyncMock(
                side_effect=[
                    ("get_system_snapshot", {}, (0, "get_system_snapshot", "h1")),
                    ("block_ip", {"ip": "1.2.3.4"}, (0, "block_ip", "h2")),
                ]
            ),
        ),
        patch(
            "services.agent._nodes._executor_phases._is_safe_tool",
            side_effect=lambda fn: fn == "get_system_snapshot",
        ),
    ):
        safe, critical, state, output = await partition_tool_calls(ctx, tool_calls, "thought", allowed)

    assert len(safe) == 1
    assert safe[0][0] == "get_system_snapshot"
    assert len(critical) == 1
    assert critical[0][0] == "block_ip"
    assert state is None


# ──────────────────────────────────────────────────────────────────────────────
# apply_resource_guard
# ──────────────────────────────────────────────────────────────────────────────


def test_apply_resource_guard_stress_blocks_heavy():
    """Stress mode (not permitted) → heavy tools filtered from both lists."""
    safe = [("web_search", {}, "k1"), ("get_system_snapshot", {}, "k2")]
    critical = [("block_ip", {}, "k3")]

    fake_rg = MagicMock()
    fake_rg.check.return_value = (False, "CPU=90%")

    with (
        patch(
            "services.agent._nodes._executor_phases.ResourceGuard",
            return_value=fake_rg,
        ),
        patch(
            "services.agent._nodes._executor_phases.is_heavy_tool",
            side_effect=lambda fn: fn == "web_search",
        ),
    ):
        s, c, all_blocked, reason = apply_resource_guard(safe, critical)

    # web_search (heavy) filtered from safe; get_system_snapshot kept
    assert all(fn != "web_search" for fn, _, _ in s)
    assert any(fn == "get_system_snapshot" for fn, _, _ in s)
    # block_ip is NOT heavy → kept in critical
    assert any(fn == "block_ip" for fn, _, _ in c)
    assert all_blocked is False
    assert "CPU" in reason


def test_apply_resource_guard_all_blocked_returns_true():
    """All tools heavy + stress → all_blocked=True."""
    safe = [("web_search", {}, "k1")]
    critical = [("fetch_url", {}, "k3")]

    fake_rg = MagicMock()
    fake_rg.check.return_value = (False, "RAM=95%")

    with (
        patch(
            "services.agent._nodes._executor_phases.ResourceGuard",
            return_value=fake_rg,
        ),
        patch(
            "services.agent._nodes._executor_phases.is_heavy_tool",
            return_value=True,
        ),
    ):
        s, c, all_blocked, reason = apply_resource_guard(safe, critical)

    assert all_blocked is True
    assert s == []
    assert c == []


def test_apply_resource_guard_safe_passes_when_not_stressed():
    """Not stressed → all tools pass through unchanged."""
    safe = [("web_search", {}, "k1"), ("get_system_snapshot", {}, "k2")]
    critical = [("block_ip", {}, "k3")]

    fake_rg = MagicMock()
    fake_rg.check.return_value = (True, "ok")

    with patch(
        "services.agent._nodes._executor_phases.ResourceGuard",
        return_value=fake_rg,
    ):
        s, c, all_blocked, reason = apply_resource_guard(safe, critical)

    assert s == safe
    assert c == critical
    assert all_blocked is False
    assert reason == "ok"


if __name__ == "__main__":
    asyncio.run(test_select_tools_conversational_path_returns_empty())
    print("OK")
