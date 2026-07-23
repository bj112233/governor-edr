# tests/test_react_memory.py
"""Tests for ReAct Deep-Dive + Investigation Memory.

Covers: dynamic budget computation, investigation_memory CRUD,
loop prevention, and cross-run memory injection.
"""

import asyncio
import hashlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

# Ensure services are importable
_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Budget computation tests ──


class TestComputeBudget:
    def test_empty_topic_returns_min(self):
        from services.react_budget import compute_budget

        assert compute_budget("") == 3
        assert compute_budget("   ") == 3

    def test_simple_topic_returns_base(self):
        from services.react_budget import compute_budget

        # 2 words, no keywords, no IOCs → base 5
        assert compute_budget("malware analysis") == 5

    def test_multi_word_topic_gets_bonus(self):
        from services.react_budget import compute_budget

        # 4+ words → +1
        budget = compute_budget("investigate recent malware campaign trends")
        assert budget >= 6

    def test_complex_keywords_get_bonus(self):
        from services.react_budget import compute_budget

        budget = compute_budget("APT campaign botnet investigation")
        # "apt" + "campaign" + "botnet" → +2 (capped at +2)
        assert budget >= 7

    def test_ioc_in_topic_gets_bonus(self):
        from services.react_budget import compute_budget

        budget = compute_budget("investigate 1.2.3.4")
        # IP in topic → +1
        assert budget >= 6

    def test_domain_in_topic_gets_bonus(self):
        from services.react_budget import compute_budget

        budget = compute_budget("investigate evil.com")
        assert budget >= 6

    def test_hash_in_topic_gets_bonus(self):
        from services.react_budget import compute_budget

        budget = compute_budget("analyze " + "a" * 64)
        assert budget >= 6

    def test_budget_capped_at_max(self):
        from services.react_budget import compute_budget

        # Everything triggers: multi-word + complex keywords + IOC + hints
        budget = compute_budget(
            "APT campaign botnet ransomware 1.2.3.4 attribution",
            complexity_hints={"has_iocs": True, "is_apt": True},
        )
        assert budget <= 10

    def test_budget_never_below_min(self):
        from services.react_budget import compute_budget

        assert compute_budget("x") >= 3

    def test_complexity_hints_add_budget(self):
        from services.react_budget import compute_budget

        base = compute_budget("test topic")
        with_hints = compute_budget("test topic", complexity_hints={"has_iocs": True, "is_apt": True})
        assert with_hints > base


# ── Investigation memory tests (in-memory DB) ──


class TestInvestigationMemory:
    """Tests use a temporary in-memory SQLite to avoid touching reference.db."""

    @pytest.fixture
    def temp_db(self, tmp_path, monkeypatch):
        """Redirect investigation_memory to a temp DB."""
        import services.investigation_memory as im

        db_path = str(tmp_path / "test_reference.db")
        monkeypatch.setattr(im, "_DB_PATH", db_path)
        monkeypatch.setattr(im, "_pool", None)
        # Reset init flag so _ensure_init runs fresh
        monkeypatch.setattr(im, "_initialized", False)
        # Create a fresh pool for the temp DB
        from services.db_pool import get_pool

        monkeypatch.setattr(im, "_pool", get_pool(db_path, max_connections=2))
        return im

    async def test_save_and_retrieve_step(self, temp_db):
        await temp_db.save_step("test_topic", "search query 1", "search", "Some results")
        visited = await temp_db.get_visited_queries("test_topic")
        assert len(visited) == 1

    async def test_multiple_steps(self, temp_db):
        await temp_db.save_step("topic_a", "query 1", "search", "result 1")
        await temp_db.save_step("topic_a", "query 2", "search", "result 2")
        await temp_db.save_step("topic_b", "query 1", "search", "result 3")
        visited_a = await temp_db.get_visited_queries("topic_a")
        visited_b = await temp_db.get_visited_queries("topic_b")
        assert len(visited_a) == 2
        assert len(visited_b) == 1

    async def test_is_query_visited_true(self, temp_db):
        await temp_db.save_step("topic", "my query", "search", "results")
        assert await temp_db.is_query_visited("topic", "my query") is True

    async def test_is_query_visited_false(self, temp_db):
        assert await temp_db.is_query_visited("topic", "never asked") is False

    async def test_is_query_visited_case_insensitive(self, temp_db):
        await temp_db.save_step("topic", "My Query", "search", "results")
        # Normalized: lowercase + whitespace collapse
        assert await temp_db.is_query_visited("topic", "my  query") is True

    async def test_investigation_summary_empty(self, temp_db):
        summary = await temp_db.get_investigation_summary("nonexistent")
        assert summary == ""

    async def test_investigation_summary_has_content(self, temp_db):
        await temp_db.save_step("topic", "query 1", "search", "Found malware at evil.com")
        summary = await temp_db.get_investigation_summary("topic")
        assert "query 1" in summary
        assert "search" in summary

    async def test_observation_truncated(self, temp_db):
        long_obs = "x" * 1000
        await temp_db.save_step("topic", "query", "search", long_obs)
        summary = await temp_db.get_investigation_summary("topic")
        # Observation in summary is truncated to 100 chars
        assert len(summary) < 500


# ── ReAct loop integration (mocked LLM + memory) ──


class TestReActLoopMemory:
    async def test_loop_prevention_intercepts_repeated_query(self):
        """When a query is already visited, the loop injects ALREADY SEARCHED."""
        from services import osint_react_loop

        # Mock LLM to produce the same query twice
        responses = [
            "Thought: I need to search\nAction: search\nAction Input: malware info",
            "Thought: Let me search again\nAction: search\nAction Input: malware info",
            "Thought: Done\nFinal Answer: Found nothing useful.",
        ]
        call_count = 0

        async def mock_complete(**kwargs):
            nonlocal call_count
            resp = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return resp

        with (
            patch.object(osint_react_loop, "LLMBridge") as mock_bridge_cls,
            patch("services.investigation_memory.is_query_visited", new_callable=AsyncMock) as mock_visited,
            patch("services.investigation_memory.save_step", new_callable=AsyncMock),
            patch("services.investigation_memory.get_investigation_summary", new_callable=AsyncMock, return_value=""),
            patch("services.osint_react_loop._run_tool", new_callable=AsyncMock, return_value="Observation: results"),
        ):
            mock_bridge = mock_bridge_cls.get_instance.return_value
            mock_bridge.complete = mock_complete

            # First call: not visited. Second call: visited.
            mock_visited.side_effect = [False, True]
            result = await osint_react_loop.run_hunt("test topic", max_iterations=3)

        # The second query should have been intercepted
        assert "ALREADY SEARCHED" in result["history"][2] or "Final Answer" in result["history"][-1]

    async def test_memory_injected_into_prompt(self):
        """Prior investigation summary is injected into the first prompt."""
        from services import osint_react_loop

        captured_prompt = []

        async def mock_complete(**kwargs):
            captured_prompt.append(kwargs.get("user_input", ""))
            return "Thought: Done\nFinal Answer: Nothing new."

        with (
            patch.object(osint_react_loop, "LLMBridge") as mock_bridge_cls,
            patch("services.investigation_memory.get_investigation_summary", new_callable=AsyncMock) as mock_summary,
            patch("services.investigation_memory.save_step", new_callable=AsyncMock),
            patch("services.investigation_memory.is_query_visited", new_callable=AsyncMock, return_value=False),
        ):
            mock_bridge = mock_bridge_cls.get_instance.return_value
            mock_bridge.complete = mock_complete
            mock_summary.return_value = "Prior investigation steps:\n  - search 'old query' → old results"

            await osint_react_loop.run_hunt("test topic", max_iterations=1)

        assert "Prior investigation findings" in captured_prompt[0]
        assert "old query" in captured_prompt[0]

    async def test_max_iterations_in_result(self):
        from services import osint_react_loop

        async def mock_complete(**kwargs):
            return "Thought: searching\nAction: search\nAction Input: test"

        with (
            patch.object(osint_react_loop, "LLMBridge") as mock_bridge_cls,
            patch("services.investigation_memory.get_investigation_summary", new_callable=AsyncMock, return_value=""),
            patch("services.investigation_memory.save_step", new_callable=AsyncMock),
            patch("services.investigation_memory.is_query_visited", new_callable=AsyncMock, return_value=False),
            patch("services.osint_react_loop._run_tool", new_callable=AsyncMock, return_value="Observation: data"),
        ):
            mock_bridge = mock_bridge_cls.get_instance.return_value
            mock_bridge.complete = mock_complete

            result = await osint_react_loop.run_hunt("topic", max_iterations=5)

        assert result["max_iterations"] == 5


# ── Hash function test ──


class TestQueryHash:
    def test_hash_consistent(self):
        from services.investigation_memory import _hash_query

        h1 = _hash_query("malware info")
        h2 = _hash_query("malware info")
        assert h1 == h2

    def test_hash_case_insensitive(self):
        from services.investigation_memory import _hash_query

        assert _hash_query("Malware Info") == _hash_query("malware info")

    def test_hash_whitespace_normalized(self):
        from services.investigation_memory import _hash_query

        assert _hash_query("malware   info") == _hash_query("malware info")

    def test_hash_different_queries(self):
        from services.investigation_memory import _hash_query

        assert _hash_query("query a") != _hash_query("query b")
