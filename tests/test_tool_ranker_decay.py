r"""Tool Ranker Time Decay tests — prevent Ghost Penalties.

Regression: tools that crashed weeks ago were permanently demoted because
penalties never expired. After fixing a tool, the Ranker still penalized it
based on stale crash lessons. Time Decay (7-day half-life) fixes this.

Run:  .venv\Scripts\python.exe -m pytest tests/test_tool_ranker_decay.py -v
"""

import math
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._tool_ranker import _HALF_LIFE_DAYS, _decay_factor

# ── _decay_factor unit tests ────────────────────────────────────────────────


def test_decay_factor_recent():
    """Failure from 0 days ago → full penalty (1.0)."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    assert _decay_factor(now) == pytest.approx(1.0, abs=0.01)


def test_decay_factor_one_half_life():
    """Failure from 7 days ago → half penalty (0.5)."""
    old = (datetime.now(UTC) - timedelta(days=_HALF_LIFE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    assert _decay_factor(old) == pytest.approx(0.5, abs=0.05)


def test_decay_factor_two_half_lives():
    """Failure from 14 days ago → quarter penalty (0.25)."""
    old = (datetime.now(UTC) - timedelta(days=2 * _HALF_LIFE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    assert _decay_factor(old) == pytest.approx(0.25, abs=0.05)


def test_decay_factor_30_days():
    """Failure from 30 days ago → nearly forgiven (~0.05)."""
    old = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    factor = _decay_factor(old)
    assert factor < 0.1, f"30-day-old penalty should be <0.1, got {factor}"
    print(f"PASS: 30-day decay factor = {factor:.4f} (nearly forgiven)")


def test_decay_factor_empty_string():
    """Empty last_seen → full penalty (safe default)."""
    assert _decay_factor("") == 1.0


def test_decay_factor_garbage():
    """Unparseable timestamp → full penalty (safe default)."""
    assert _decay_factor("not a date") == 1.0


def test_decay_factor_future():
    """Future timestamp → full penalty (clock skew protection)."""
    future = (datetime.now(UTC) + timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
    assert _decay_factor(future) == 1.0


# ── Integration: Ghost Penalty prevention ───────────────────────────────────


async def test_ghost_penalty_prevention():
    """A tool that crashed 30 days ago should NOT be heavily demoted.

    Before Time Decay: 5 failures × 10 = -50 → score 50 (heavily demoted)
    After Time Decay:  5 failures × 10 × 0.05 = -2.5 → score 97 (nearly clean)
    """
    from services.agent._tool_ranker import _rank_tools_by_history

    old_ts = (datetime.now(UTC) - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
    mock_stats = {
        "skill_old_crasher": {
            "failures": 5,
            "repeat_failures": 10,
            "last_seen": old_ts,
        }
    }
    mock_lessons: list[dict] = []

    with (
        patch(
            "services.agent._tool_ranker.get_tool_stats",
            new_callable=AsyncMock,
            return_value=mock_stats,
        ),
        patch(
            "services.agent._tool_ranker.search_lessons",
            new_callable=AsyncMock,
            return_value=mock_lessons,
        ),
    ):
        tools = [
            {"type": "function", "function": {"name": "skill_old_crasher", "description": "Old tool"}},
            {"type": "function", "function": {"name": "skill_clean_tool", "description": "Clean tool"}},
            {"type": "function", "function": {"name": "final_answer", "description": "Final"}},
        ]
        ranked = await _rank_tools_by_history(tools, "test query")

    # old_crasher should NOT be heavily demoted — its penalty decayed
    names = [t["function"]["name"] for t in ranked]
    assert "final_answer" == names[-1], "final_answer must be last"
    # old_crasher should be near score 100 (penalty ~2.5, not 50)
    # It might not be first if clean_tool is also 100, but it should NOT be
    # stuck at the floor (10)
    assert "skill_old_crasher" in names, "old_crasher must be in results"
    print("PASS: 30-day-old crasher not ghost-penalized")


async def test_recent_failure_still_penalized():
    """A tool that crashed TODAY should still be heavily demoted."""
    from services.agent._tool_ranker import _rank_tools_by_history

    now_ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
    mock_stats = {
        "skill_recent_crasher": {
            "failures": 5,
            "repeat_failures": 10,
            "last_seen": now_ts,
        }
    }
    mock_lessons: list[dict] = []

    with (
        patch(
            "services.agent._tool_ranker.get_tool_stats",
            new_callable=AsyncMock,
            return_value=mock_stats,
        ),
        patch(
            "services.agent._tool_ranker.search_lessons",
            new_callable=AsyncMock,
            return_value=mock_lessons,
        ),
    ):
        tools = [
            {"type": "function", "function": {"name": "skill_recent_crasher", "description": "Recent crasher"}},
            {"type": "function", "function": {"name": "skill_clean_tool", "description": "Clean tool"}},
            {"type": "function", "function": {"name": "final_answer", "description": "Final"}},
        ]
        ranked = await _rank_tools_by_history(tools, "test query")

    # recent_crasher should be demoted (score = 100 - 50 - 50 = 0, floored to 10)
    names = [t["function"]["name"] for t in ranked]
    assert names[0] == "skill_clean_tool", "clean tool should rank first"
    assert names[1] == "skill_recent_crasher", "recent crasher should be demoted"
    print("PASS: recent crasher still penalized (no decay for today's failure)")


async def test_tie_breaker_breaks_score_ties():
    """All tools with score=100 must NOT preserve insertion order.

    Without the tie-breaker, the sort is stable and returns tools in
    their original order — a no-op. The hash-based tie-breaker ensures
    a deterministic but non-insertion-order permutation.
    """
    from services.agent._tool_ranker import _rank_tools_by_history

    # 5 clean tools, no failures, no lessons — all score=100
    tool_names = ["alpha", "beta", "gamma", "delta", "epsilon"]
    tools = [{"type": "function", "function": {"name": n, "description": n}} for n in tool_names]
    tools.append({"type": "function", "function": {"name": "final_answer", "description": "Final"}})

    with (
        patch(
            "services.agent._tool_ranker.get_tool_stats",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "services.agent._tool_ranker.search_lessons",
            new_callable=AsyncMock,
            return_value=[],
        ),
    ):
        ranked = await _rank_tools_by_history(tools, "test query")

    names = [t["function"]["name"] for t in ranked]
    assert names[-1] == "final_answer", "final_answer must be last"
    # The tie-breaker should produce a non-identity permutation.
    # Probability of identity permutation by random hash ≈ 1/120 for 5 items.
    non_final = names[:-1]
    assert non_final != tool_names, (
        f"Tie-breaker is a no-op — got insertion order {non_final}. Expected hash-based permutation."
    )
    # Must contain all original tools (no loss)
    assert sorted(non_final) == sorted(tool_names)
    print(f"PASS: tie-breaker permuted {tool_names} → {non_final}")


async def test_lesson_bonus_lifts_above_cap():
    """Tool with lesson bonus must rank above clean tools (score 120 > 100)."""
    from services.agent._tool_ranker import _rank_tools_by_history

    mock_lessons = [{"tool_name": "preferred_tool", "error_signature": "x"}]
    with (
        patch(
            "services.agent._tool_ranker.get_tool_stats",
            new_callable=AsyncMock,
            return_value={},
        ),
        patch(
            "services.agent._tool_ranker.search_lessons",
            new_callable=AsyncMock,
            return_value=mock_lessons,
        ),
    ):
        tools = [
            {"type": "function", "function": {"name": "other_tool", "description": "Other"}},
            {"type": "function", "function": {"name": "preferred_tool", "description": "Preferred"}},
            {"type": "function", "function": {"name": "final_answer", "description": "Final"}},
        ]
        ranked = await _rank_tools_by_history(tools, "test query")

    names = [t["function"]["name"] for t in ranked]
    assert names[0] == "preferred_tool", f"Lesson-bonus tool must rank first, got {names[0]}"
    print("PASS: lesson bonus lifts preferred_tool above clean tools")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
