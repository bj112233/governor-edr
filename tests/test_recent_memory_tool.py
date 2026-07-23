# tests/test_recent_memory_tool.py
"""Tests for recent_memory_tool — Telegram display format + DB stats.

Verifies the tool no longer dumps LLM-context format ([Context from memory:]
with Q:q1... A:r1... placeholders) and instead shows readable entries
with timestamps, full Q/A preview, and DB statistics footer.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.tools.mcp_skill_handlers import recent_memory_tool


def _mock_entry(ts="2026-06-30T11:31:24", query="מה המצב", response="הכל תקין", memory_type="conversation"):
    return MagicMock(ts=ts, query=query, response=response, memory_type=memory_type, context="")


async def test_empty_memory_shows_stats():
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(return_value=[])
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch("services.tools.mcp_skill_handlers._get_memory_stats", new_callable=AsyncMock, return_value="📊 stats"),
    ):
        result = await recent_memory_tool()
    assert "אין זיכרונות פעילים" in result
    assert "📊 stats" in result


async def test_no_llm_context_header():
    """Must NOT contain the old LLM-injection format."""
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(return_value=[_mock_entry()])
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch("services.tools.mcp_skill_handlers._get_memory_stats", new_callable=AsyncMock, return_value="📊 stats"),
    ):
        result = await recent_memory_tool()
    assert "[Context from memory:]" not in result
    assert "Q:q1..." not in result


async def test_shows_timestamp_and_qa():
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(
        return_value=[
            _mock_entry(ts="2026-06-30T11:31:24", query="מה המצב היום", response="הכל תקין במערכת"),
        ]
    )
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch("services.tools.mcp_skill_handlers._get_memory_stats", new_callable=AsyncMock, return_value="📊 stats"),
    ):
        result = await recent_memory_tool()
    assert "2026-06-30 11:31" in result
    assert "מה המצב היום" in result
    assert "הכל תקין במערכת" in result
    assert "❓" in result
    assert "💬" in result


async def test_truncates_long_entries():
    long_q = "x" * 200
    long_a = "y" * 200
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(return_value=[_mock_entry(query=long_q, response=long_a)])
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch("services.tools.mcp_skill_handlers._get_memory_stats", new_callable=AsyncMock, return_value="📊 stats"),
    ):
        result = await recent_memory_tool()
    assert "…" in result
    # Full 200 chars should NOT appear
    assert long_q not in result
    assert long_a not in result


async def test_multiple_entries_numbered():
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(
        return_value=[
            _mock_entry(ts="2026-06-30T11:00:00", query="q1", response="r1"),
            _mock_entry(ts="2026-06-30T10:00:00", query="q2", response="r2"),
            _mock_entry(ts="2026-06-30T09:00:00", query="q3", response="r3"),
        ]
    )
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch("services.tools.mcp_skill_handlers._get_memory_stats", new_callable=AsyncMock, return_value="📊 stats"),
    ):
        result = await recent_memory_tool()
    assert "**#1**" in result
    assert "**#2**" in result
    assert "**#3**" in result


async def test_stats_footer_present():
    svc = MagicMock()
    svc._ensure_init = AsyncMock()
    svc.get_recent = AsyncMock(return_value=[_mock_entry()])
    with (
        patch("services.bot_memory.crud.get_memory_service", return_value=svc),
        patch(
            "services.tools.mcp_skill_handlers._get_memory_stats",
            new_callable=AsyncMock,
            return_value="📊 **סטטיסטיקות זיכרון:**\n  • פעילים: 42",
        ),
    ):
        result = await recent_memory_tool()
    assert "סטטיסטיקות זיכרון" in result
    assert "פעילים: 42" in result
