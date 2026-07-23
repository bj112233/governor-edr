"""Adaptive Tool Ranking — deterministic pre-execution tool scoring.

Ranks tools by historical performance BEFORE the LLM sees them.
Exploits SLM primacy bias: the first tool in the schema is chosen more often.

Scoring formula:
  base = 100 - decayed_failures * 10 - decayed_repeats * 5
  base = clamp(base, _SCORE_FLOOR, _SCORE_CAP)   # cap+floor BEFORE bonus
  score = base + lesson_bonus                     # bonus lifts above cap
  lesson_bonus = +20 if tool_name appears in search_lessons(user_question)

Tie-breaker: when scores are equal, a deterministic hash of the tool name
(float in [0,1)) breaks ties without alphabetical or insertion-order bias.
Without this, all clean tools get score=100 and the sort is a stable no-op.

Time Decay (Half-life):
  Penalties decay exponentially with a 7-day half-life.
  A failure from 7 days ago counts as 0.5, from 14 days as 0.25, etc.
  This prevents Ghost Penalties — tools that were fixed but still demoted
  because old crash lessons never expire.

Zero LLM cost. Pure Python + SQLite. < 1ms execution.
"""

import asyncio
import hashlib
import logging
import math
from datetime import UTC, datetime

from services.error_memory import get_tool_stats, search_lessons

logger = logging.getLogger(__name__)

# Penalties
_FAILURE_PENALTY = 10
_REPEAT_PENALTY = 5
# Bonus for tools that resolved similar past queries
_LESSON_BONUS = 20
# Score bounds — base is clamped to [floor, cap] BEFORE bonus is added
_SCORE_FLOOR = 10
_SCORE_CAP = 100
# Time Decay: half-life in days. Penalty halves every 7 days.
_HALF_LIFE_DAYS = 7.0


def _decay_factor(last_seen: str) -> float:
    """Exponential decay factor based on age of last failure.

    Returns a multiplier in (0, 1] that scales penalties.
    - age=0 days → 1.0 (full penalty)
    - age=7 days → 0.5 (half penalty)
    - age=14 days → 0.25 (quarter penalty)
    - age=30 days → ~0.05 (nearly forgiven)

    This prevents Ghost Penalties: a tool that crashed 30 days ago and was
    since fixed will have its penalty decayed to near-zero, allowing it to
    be ranked fairly again.
    """
    if not last_seen:
        return 1.0  # unknown age — assume recent, full penalty
    try:
        # SQLite timestamps: "YYYY-MM-DD HH:MM:SS" (UTC)
        last_dt = datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
    except (ValueError, TypeError):
        # Try ISO format with timezone
        try:
            last_dt = datetime.fromisoformat(last_seen)
        except (ValueError, TypeError):
            return 1.0  # unparseable — full penalty (safe default)
    now_dt = datetime.now(UTC)
    age_days = (now_dt - last_dt).total_seconds() / 86400.0
    if age_days <= 0:
        return 1.0
    return math.pow(0.5, age_days / _HALF_LIFE_DAYS)


def _extract_lesson_tools(lessons: list[dict] | Exception) -> set[str]:
    """Build set of tool names that appear in lessons (resolved similar queries)."""
    if not isinstance(lessons, list):
        return set()
    return {lesson.get("tool_name", "") for lesson in lessons if lesson.get("tool_name", "")}


def _tie_breaker(name: str) -> float:
    """Deterministic float in [0, 1) from tool name hash.

    Breaks score ties without alphabetical or insertion-order bias.
    Same name → same value (stable across runs, processes, restarts).
    """
    h = hashlib.md5(name.encode("utf-8")).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def _score_tool(name: str, stats: dict, lesson_tools: set[str]) -> tuple[int, float]:
    """Score a single tool by historical data + lesson bonus.

    Returns (score, tie_breaker) for deterministic tuple-key sorting.
    Base is clamped to [_SCORE_FLOOR, _SCORE_CAP] BEFORE the lesson bonus
    is added, so the bonus always lifts above the cap (never absorbed by
    the floor).
    """
    base = _SCORE_CAP
    tool_stats = stats.get(name, {}) if isinstance(stats, dict) else {}
    failures = tool_stats.get("failures", 0)
    repeat_failures = tool_stats.get("repeat_failures", 0)
    last_seen = tool_stats.get("last_seen", "")

    decay = _decay_factor(last_seen)
    base -= int(failures * decay * _FAILURE_PENALTY)
    base -= int(repeat_failures * decay * _REPEAT_PENALTY)

    # Clamp base BEFORE bonus — bonus must lift above cap, not be absorbed by floor
    base = max(min(base, _SCORE_CAP), _SCORE_FLOOR)

    if name in lesson_tools:
        base += _LESSON_BONUS

    return base, _tie_breaker(name)


async def _fetch_stats_and_lessons(user_question: str, prefetched: list[dict] | None) -> tuple[dict, list[dict]]:
    """Fetch tool stats + lessons. Reuses prefetched lessons if available."""
    if prefetched is not None:
        return await get_tool_stats(), prefetched
    stats, lessons = await asyncio.gather(
        get_tool_stats(),
        search_lessons(user_question, limit=5, threshold=0.75),
        return_exceptions=True,
    )
    if isinstance(stats, Exception):
        logger.warning("[ToolRanker] get_tool_stats failed: %s", stats)
        stats = {}
    if isinstance(lessons, Exception):
        logger.warning("[ToolRanker] search_lessons failed: %s", lessons)
        lessons = []
    return stats, lessons


def _log_ranking(scored: list[tuple[int, float, dict]], lesson_tools: set[str]) -> None:
    """Log ranking if any demotion, bonus, or tie-break differentiation occurred."""
    has_diff = any(s != _SCORE_CAP for s, _, _ in scored)
    if not (has_diff or lesson_tools):
        return
    names_with_scores = [f"{t.get('function', {}).get('name', '?')}={s}" for s, _, t in scored]
    logger.info(
        "[ToolRanker] Ranked: %s | lesson_bonus_tools=%s",
        ", ".join(names_with_scores),
        list(lesson_tools) if lesson_tools else "none",
    )


async def _rank_tools_by_history(
    tools: list[dict],
    user_question: str,
    *,
    prefetched_lessons: list[dict] | None = None,
) -> list[dict]:
    """Rank tools by historical success/failure data.

    Args:
        tools: list of OpenAI-format tool dicts ({"type":"function","function":{...}})
        user_question: the user's query, used for lesson matching
        prefetched_lessons: pre-fetched lessons to avoid double embedding cost.
            If None, will fetch them (with embedding cost ~20-100ms).

    Returns:
        Same tools list, sorted best-first. final_answer always last.
    """
    if len(tools) <= 2:
        return tools  # Not enough to rank

    stats, lessons = await _fetch_stats_and_lessons(user_question, prefetched_lessons)
    lesson_tools = _extract_lesson_tools(lessons)

    scored: list[tuple[int, float, dict]] = []
    final_answer_tool: dict | None = None

    for tool in tools:
        name = tool.get("function", {}).get("name", "")
        if name == "final_answer":
            final_answer_tool = tool
            continue
        score, tie = _score_tool(name, stats, lesson_tools)
        scored.append((score, tie, tool))

    # Sort by (score desc, tie_breaker desc) — tie_breaker breaks score ties
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    _log_ranking(scored, lesson_tools)

    ranked = [tool for _, _, tool in scored]
    if final_answer_tool:
        ranked.append(final_answer_tool)
    return ranked
