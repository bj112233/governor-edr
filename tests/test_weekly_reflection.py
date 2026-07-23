# tests/test_weekly_reflection.py
"""Tests for Weekly Auto-Reflection (Critic Node).

Verifies:
- _build_reflection_block produces compact XML-tagged block
- Token bloat prevention: errors are deduplicated (GROUP BY + COUNT)
- run_weekly_reflection calls LLM, saves file, appends to lessons.md, emits event
- Graceful degradation: no data → skip, LLM failure → skip
- Prompt enforces Hebrew output + English tech terms
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.reflection_agent import _REFLECTION_PROMPT, _build_reflection_block, run_weekly_reflection

# ── _build_reflection_block ──


async def test_empty_data_returns_empty_block():
    with (
        patch("services.error_memory.get_errors_last_7d", new_callable=AsyncMock, return_value=[]),
        patch(
            "services.memory_db.get_hunts_last_7d",
            new_callable=AsyncMock,
            return_value={"total": 0, "avg_score": 0.0, "dispatched": 0, "high_risk": 0},
        ),
        patch("services.telemetry.get_telemetry") as mock_tel,
    ):
        mock_tel.return_value.snapshot.return_value = {
            "llm": {"calls": 0, "errors": 0, "p95_ms": 0},
            "tools": {"calls": 0, "errors": 0, "per_tool": {}},
        }
        block = await _build_reflection_block()
    # Telemetry section still appears (0 calls), but no TOOL_FAILURES or HUNT_STATISTICS
    assert "<TOOL_FAILURES>" not in block
    assert "<HUNT_STATISTICS>" not in block


async def test_errors_deduplicated_with_count():
    """400 identical errors → ONE line with occurred 400x (token bloat prevention)."""
    errors = [
        {
            "error_signature": "Failed to parse JSON",
            "tool_name": "analyze_cmdline",
            "occurrences": 400,
            "last_seen": "2026-06-30T10:00",
        },
    ]
    with (
        patch("services.error_memory.get_errors_last_7d", new_callable=AsyncMock, return_value=errors),
        patch(
            "services.memory_db.get_hunts_last_7d",
            new_callable=AsyncMock,
            return_value={"total": 0, "avg_score": 0.0, "dispatched": 0, "high_risk": 0},
        ),
        patch("services.telemetry.get_telemetry") as mock_tel,
    ):
        mock_tel.return_value.snapshot.return_value = {
            "llm": {"calls": 0, "errors": 0, "p95_ms": 0},
            "tools": {"calls": 0, "errors": 0, "per_tool": {}},
        }
        block = await _build_reflection_block()
    assert "<TOOL_FAILURES>" in block
    assert "occurred 400x" in block
    # Should NOT have 400 separate lines
    assert block.count("Failed to parse JSON") == 1


async def test_telemetry_included_as_aggregated_stats():
    with (
        patch("services.error_memory.get_errors_last_7d", new_callable=AsyncMock, return_value=[]),
        patch(
            "services.memory_db.get_hunts_last_7d",
            new_callable=AsyncMock,
            return_value={"total": 0, "avg_score": 0.0, "dispatched": 0, "high_risk": 0},
        ),
        patch("services.telemetry.get_telemetry") as mock_tel,
    ):
        mock_tel.return_value.snapshot.return_value = {
            "llm": {"calls": 42, "errors": 3, "p95_ms": 2400},
            "tools": {
                "calls": 100,
                "errors": 5,
                "per_tool": {"get_system_snapshot": {"n": 18, "p50_ms": 100, "p95_ms": 200}},
            },
        }
        block = await _build_reflection_block()
    assert "<AGENT_TELEMETRY>" in block
    assert "Total LLM Calls: 42" in block
    assert "Tool Errors: 5" in block
    assert "get_system_snapshot" in block


async def test_hunt_stats_metadata_only():
    """Hunt section must contain only metadata, NOT report content."""
    with (
        patch("services.error_memory.get_errors_last_7d", new_callable=AsyncMock, return_value=[]),
        patch(
            "services.memory_db.get_hunts_last_7d",
            new_callable=AsyncMock,
            return_value={"total": 14, "avg_score": 0.15, "dispatched": 2, "high_risk": 0},
        ),
        patch("services.telemetry.get_telemetry") as mock_tel,
    ):
        mock_tel.return_value.snapshot.return_value = {
            "llm": {"calls": 0, "errors": 0, "p95_ms": 0},
            "tools": {"calls": 0, "errors": 0, "per_tool": {}},
        }
        block = await _build_reflection_block()
    assert "<HUNT_STATISTICS>" in block
    assert "Total Hunts Executed: 14" in block
    assert "Average Threat Score: 0.15" in block
    # No summary content should leak
    assert "summary" not in block.lower()


# ── run_weekly_reflection ──


async def test_empty_block_skips_reflection():
    with patch("services.reflection_agent._build_reflection_block", new_callable=AsyncMock, return_value=""):
        result = await run_weekly_reflection()
    assert result == ""


async def test_llm_circuit_open_skips():
    bridge = MagicMock()
    bridge.should_accept_traffic.return_value = False
    with (
        patch(
            "services.reflection_agent._build_reflection_block",
            new_callable=AsyncMock,
            return_value="<TOOL_FAILURES>\n- test\n</TOOL_FAILURES>",
        ),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
    ):
        result = await run_weekly_reflection()
    assert result == ""


async def test_successful_reflection_saves_file_and_emits_event(tmp_path):
    reflection_text = "- שגיאה 1: Tool hallucination\n- כלל 1: Verify tool exists"
    bridge = MagicMock()
    bridge.should_accept_traffic.return_value = True
    bridge.complete = AsyncMock(return_value=reflection_text)

    # Mock Path: redirect ALL paths to tmp_path (isolation from real files)
    mock_file = MagicMock()
    mock_file.write_text = MagicMock()
    mock_file.mkdir = MagicMock(parents=True, exist_ok=True)
    mock_file.__truediv__ = MagicMock(return_value=mock_file)  # Path / "file" → mock_file
    mock_lessons = MagicMock()
    mock_lessons.exists.return_value = True
    mock_lessons.open.return_value.__enter__ = MagicMock()
    mock_lessons.open.return_value.__exit__ = MagicMock(return_value=False)

    with (
        patch(
            "services.reflection_agent._build_reflection_block",
            new_callable=AsyncMock,
            return_value="<TOOL_FAILURES>\n- test\n</TOOL_FAILURES>",
        ),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.sentinel_events.send_weekly_reflection_event", new_callable=AsyncMock) as mock_event,
        patch("services.reflection_agent.Path") as mock_path_cls,
    ):
        # ALL Path() calls return mocks — no real file I/O
        def _path_side_effect(p):
            if "lessons" in str(p):
                return mock_lessons
            return mock_file

        mock_path_cls.side_effect = _path_side_effect
        result = await run_weekly_reflection()

    assert "רפלקציה שבועית" in result
    assert reflection_text in result
    mock_event.assert_called_once()
    mock_file.write_text.assert_called_once()  # .md file saved
    mock_lessons.open.assert_called_once()  # lessons.md appended


async def test_llm_failure_returns_empty():
    with (
        patch(
            "services.reflection_agent._build_reflection_block",
            new_callable=AsyncMock,
            return_value="<TOOL_FAILURES>\n- test\n</TOOL_FAILURES>",
        ),
        patch("services.llm_bridge.LLMBridge.get_instance", side_effect=Exception("LLM down")),
    ):
        result = await run_weekly_reflection()
    assert result == ""


async def test_prompt_enforces_hebrew_with_english_tech_terms():
    """Prompt must contain Hebrew output instruction + English tech term preservation."""
    assert "Hebrew" in _REFLECTION_PROMPT
    assert "English" in _REFLECTION_PROMPT
    assert "Latency" in _REFLECTION_PROMPT
    assert "Hallucination" in _REFLECTION_PROMPT
    assert "JSON" in _REFLECTION_PROMPT
