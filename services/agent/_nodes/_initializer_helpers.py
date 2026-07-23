"""Initializer helpers — tool selection, memory injection, history building.

Extracted from _initializer.py to reduce _build_agent_context from F(53).
Each helper handles one phase of context construction.
"""

import asyncio
import logging
from datetime import datetime

from config import LLM_AGENT_MAX_TOKENS, LLM_CONTEXT_WINDOW, MAX_SYSTEM_TOOLS

from ...agent_tools import _TOOLS, _TOOLS_BASIC
from ...bot_memory import get_memory_service, recall_context
from ...error_memory import format_lessons_for_prompt, search_lessons
from ...skills_engine import get_skills_engine
from .._context import _FINAL_ANSWER_TOOL_SPEC, _AgentContext
from .._helpers import _count_tokens
from ..prompts import _CONVERSATIONAL_SYSTEM, generate_system_prompt_with_tools
from ..routing import _CAPABILITY_PATTERNS, _filter_relevant_skills, _filter_relevant_tools
from ..utils import sanitize_agent_history

logger = logging.getLogger(__name__)

_MAX_TOOLS_TOTAL = 7
_MIN_SYSTEM_TOOLS = 2
_MIN_SKILLS = 2
_HISTORY_WINDOW_MSGS = 6


async def _select_tools(
    user_question: str,
    skills_tools: list[dict],
    prefetched_lessons: list[dict] | None = None,
) -> tuple[list[dict], str]:
    """Phase 4: Select tools and build system prompt.

    Args:
        prefetched_lessons: pre-fetched error lessons to avoid double embedding.
            If None, _rank_tools_by_history will fetch them (with embedding cost).

    Returns (active_tools, system_prompt).
    """
    from ..routing import _is_conversational

    if await _is_conversational(user_question):
        return [], _CONVERSATIONAL_SYSTEM

    # Filter permanently hidden tools BEFORE routing so the router selects
    # replacements (e.g. scan_suspicious_procs instead of analyze_cmdline).
    # Without this, the router wastes a slot on a hidden tool, leaving the LLM
    # with no cmdline analysis capability during threat hunts.
    from services.tools.tool_visibility import PERMANENTLY_HIDDEN_TOOLS

    routable_tools = [t for t in _TOOLS if t.get("function", {}).get("name", "") not in PERMANENTLY_HIDDEN_TOOLS]
    filtered_system_tools = await _filter_relevant_tools(user_question, routable_tools, max_tools=MAX_SYSTEM_TOOLS)

    if filtered_system_tools:
        base_tools = filtered_system_tools
        logger.info("[AGENT] Semantic filter matched %d system tools", len(filtered_system_tools))
    else:
        base_tools = _TOOLS_BASIC
        logger.info("[AGENT] No semantic match for system tools; using basic tools only")

    if any(p in user_question.lower() for p in _CAPABILITY_PATTERNS):
        logger.info("[AGENT] Capability intent detected: Bypassing ALL tools (fast path).")
        return [], _CONVERSATIONAL_SYSTEM

    filtered_skills = await _filter_relevant_skills(user_question, skills_tools)
    max_allowed = _MAX_TOOLS_TOTAL - 1

    system_pool = list(base_tools or [])
    skills_pool = list(filtered_skills or [])
    seen_names: set[str] = set()

    def _pick(pool: list[dict], count: int) -> list[dict]:
        picked: list[dict] = []
        for tool in pool:
            name = tool.get("function", {}).get("name")
            if name and name not in seen_names:
                picked.append(tool)
                seen_names.add(name)
            if len(picked) >= count:
                break
        return picked

    reserved_system = _pick(system_pool, _MIN_SYSTEM_TOOLS)
    reserved_skills = _pick(skills_pool, _MIN_SKILLS)
    selected = reserved_system + reserved_skills

    remaining = []
    for tool in system_pool + skills_pool:
        name = tool.get("function", {}).get("name")
        if name and name not in seen_names:
            remaining.append(tool)
            seen_names.add(name)

    for tool in remaining:
        if len(selected) >= max_allowed:
            break
        selected.append(tool)

    # Ensure final_answer is last
    final_answer_tool = next((t for t in selected if t.get("function", {}).get("name") == "final_answer"), None)
    other_tools = [t for t in selected if t.get("function", {}).get("name") != "final_answer"]
    active_tools = other_tools + [final_answer_tool] if final_answer_tool else other_tools + [_FINAL_ANSWER_TOOL_SPEC]

    # ── Adaptive Tool Ranking: demote tools with failure history ──
    # Zero LLM cost — pure SQLite + Python. Exploits SLM primacy bias.
    from .._tool_ranker import _rank_tools_by_history

    active_tools = await _rank_tools_by_history(active_tools, user_question, prefetched_lessons=prefetched_lessons)

    system_prompt = generate_system_prompt_with_tools(active_tools)
    logger.info(
        "[AGENT] Using full agent system prompt with %d tools (%d system, %d/%d skills matched)",
        len(active_tools),
        len(base_tools),
        len(filtered_skills),
        len(skills_tools),
    )
    return active_tools, system_prompt


async def _inject_memory(
    system_prompt: str,
    user_question: str,
    prefetched_lessons: list[dict] | None = None,
) -> str:
    """Phase 5: Inject recall context, error lessons, and user profile into system prompt.

    Args:
        prefetched_lessons: pre-fetched lessons to avoid double embedding cost.
            If None, will fetch them (with embedding cost).
    """
    from services.memory_summarizer import get_latest_user_profile

    results = await asyncio.gather(
        recall_context(user_question, limit=3),
        _get_lessons_for_prompt(user_question, prefetched_lessons),
        get_latest_user_profile(),
        return_exceptions=True,
    )

    context = results[0] if not isinstance(results[0], Exception) else None
    if context:
        system_prompt += f"\n\n[Relevant context from memory]:{context}"

    _lessons = results[1] if not isinstance(results[1], Exception) else []
    _lessons_block = format_lessons_for_prompt(_lessons)
    if _lessons_block:
        system_prompt += f"\n\n[Operational lessons from past errors]:\n{_lessons_block}"
        logger.info("[AGENT] Injected %d error lesson(s).", len(_lessons))

    profile_json = results[2] if not isinstance(results[2], Exception) else None
    if profile_json:
        system_prompt += f"\n\n[User profile]: {profile_json}"

    logger.info(
        "[AGENT-DIAG] system_prompt=%d chars (~%d tok) recall_ctx=%d chars",
        len(system_prompt),
        len(system_prompt) // 4,
        len(context) if context else 0,
    )
    return system_prompt


async def _get_lessons_for_prompt(user_question: str, prefetched: list[dict] | None = None) -> list[dict]:
    """Return lessons for prompt injection, reusing pre-fetched results if available."""
    if prefetched is not None:
        return prefetched[:2]  # _inject_memory only needs top 2
    return await search_lessons(user_question, limit=2)


async def _load_recent_history(user_question: str) -> tuple[list[dict], int]:
    """Phase 6: Load recent conversation history from memory service."""
    messages: list[dict[str, str]] = []
    _history_msgs_added = 0
    try:
        svc = get_memory_service()
        recent = await svc.get_recent(limit=2, memory_type="conversation")
        for entry in reversed(recent):
            if entry.query and entry.query != user_question:
                messages.append({"role": "user", "content": f"<previous_turn>\n{entry.query}\n</previous_turn>"})
                _history_msgs_added += 1
            if entry.response:
                response_text = entry.response.strip()
                if len(response_text) < 10 or not any(c.isalnum() for c in response_text):
                    logger.debug("[AGENT] Skipped broken history entry (len=%d)", len(response_text))
                    continue
                response_text = sanitize_agent_history(response_text)
                if len(response_text) > 1200:
                    response_text = response_text[-1200:]
                messages.append({"role": "assistant", "content": f"<previous_turn>\n{response_text}\n</previous_turn>"})
                _history_msgs_added += 1
    except Exception as e:
        logger.debug("[AGENT] Failed to load conversation history: %s", e)
    return messages, _history_msgs_added


async def _enforce_token_ceiling(messages: list[dict]) -> list[dict]:
    """Phase 7: Sliding window + token ceiling enforcement."""
    if len(messages) > _HISTORY_WINDOW_MSGS:
        messages = messages[-_HISTORY_WINDOW_MSGS:]

    _MAX_PROMPT_TOKENS = LLM_CONTEXT_WINDOW - LLM_AGENT_MAX_TOKENS - 512
    full_check = [{"role": "system", "content": ""}] + messages
    while len(messages) > 2 and await _count_tokens(full_check) > _MAX_PROMPT_TOKENS:
        last_user_idx = -1
        for i in range(len(messages) - 1, -1, -1):
            if messages[i].get("role") == "user":
                last_user_idx = i
                break
        if last_user_idx > 0:
            messages = messages[last_user_idx:]
        else:
            break
        full_check = [{"role": "system", "content": ""}] + messages
    return messages


async def _build_history_messages(user_question: str) -> tuple[list[dict], int]:
    """Phase 6-7: Build message list with conversation history + sliding window.

    Returns (messages_without_system, history_msgs_added).
    """
    messages, _history_msgs_added = await _load_recent_history(user_question)
    messages = await _enforce_token_ceiling(messages)

    _diag_hist_count = len(messages)
    _diag_hist_chars = sum(len(str(m.get("content", "") or "")) for m in messages)
    logger.info("[AGENT-DIAG] history_injected=%d msgs, %d chars", _diag_hist_count, _diag_hist_chars)

    if logger.isEnabledFor(logging.DEBUG):
        for _i, _m in enumerate(messages):
            _c = str(_m.get("content", "") or "")
            logger.debug("[AGENT-DIAG] msg[%d] role=%s len=%d preview=%r", _i, _m.get("role"), len(_c), _c[:80])

    return messages, _history_msgs_added


def _inject_directive(
    messages: list[dict], user_question: str, active_tools: list[dict], history_msgs_added: int
) -> list[dict]:
    """Phase 8: Inject directive (as system) + user question (as user).

    Directives are injected as role="system" so _trim_messages protects them
    via _mid_system_msgs extraction — they survive aggressive trimming,
    progressive shrink, and emergency overflow. The user question is always
    appended as role="user" at the tail so it serves as the current-turn
    anchor for the trimming algorithm.
    """
    from ..directives import directive_registry

    _active_tool_names = {t.get("function", {}).get("name", "") for t in active_tools}
    _directive_ctx = {"active_tool_names": _active_tool_names, "history_msgs": history_msgs_added}
    _matched = directive_registry.match(user_question, _directive_ctx)
    if _matched is not None:
        _name, _rendered = _matched
        messages.append({"role": "system", "content": _rendered})
        logger.info("[AGENT] Directive injected: name=%s history_msgs=%d", _name, history_msgs_added)
    messages.append({"role": "user", "content": user_question})
    return messages
