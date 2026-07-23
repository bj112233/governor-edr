# tests/test_fts5_integrity.py
"""Tests for FTS5 integrity check and rebuild consolidation.

Verifies:
- check_fts5_integrity() detects corruption and triggers rebuild
- _rebuild_fts() (maintenance) delegates to fts_manager._rebuild_fts
- Missing table case is handled (backfill from memories)
- Healthy FTS5 returns True without rebuild
"""

import sqlite3
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.bot_memory.maintenance import _rebuild_fts, check_fts5_integrity


class TestCheckFts5Integrity:
    """FTS5 integrity check tests."""

    @pytest.mark.asyncio
    async def test_healthy_fts5_returns_true(self):
        """When FTS5 integrity-check returns 'ok', return True."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone = AsyncMock(return_value=("ok",))

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        class _Ctx:
            async def __aenter__(self):
                return mock_db

            async def __aexit__(self, *a):
                return None

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _Ctx()

        with patch("services.bot_memory.maintenance.get_memory_pool", return_value=mock_pool):
            result = await check_fts5_integrity()

        assert result is True

    @pytest.mark.asyncio
    async def test_corrupted_fts5_triggers_rebuild(self):
        """When FTS5 integrity-check raises, rebuild and return False."""
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(side_effect=sqlite3.OperationalError("database disk image is malformed"))

        class _Ctx:
            async def __aenter__(self):
                return mock_db

            async def __aexit__(self, *a):
                return None

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _Ctx()

        with (
            patch("services.bot_memory.maintenance.get_memory_pool", return_value=mock_pool),
            patch("services.bot_memory.maintenance._rebuild_fts", new_callable=AsyncMock) as mock_rebuild,
        ):
            result = await check_fts5_integrity()

        assert result is False
        mock_rebuild.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_rebuild_delegates_to_fts_manager(self):
        """_rebuild_fts in maintenance delegates to fts_manager._rebuild_fts."""
        mock_db = AsyncMock()

        class _Ctx:
            async def __aenter__(self):
                return mock_db

            async def __aexit__(self, *a):
                return None

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _Ctx()

        with (
            patch("services.bot_memory.maintenance.get_memory_pool", return_value=mock_pool),
            patch("services.bot_memory.fts_manager._rebuild_fts", new_callable=AsyncMock) as mock_fts,
        ):
            await _rebuild_fts()

        mock_fts.assert_awaited_once_with(mock_db)

    @pytest.mark.asyncio
    async def test_rebuild_handles_missing_table(self):
        """_rebuild_fts handles missing table via fts_manager backfill."""
        mock_cursor = MagicMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)  # No table found

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        class _Ctx:
            async def __aenter__(self):
                return mock_db

            async def __aexit__(self, *a):
                return None

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _Ctx()

        with patch("services.bot_memory.maintenance.get_memory_pool", return_value=mock_pool):
            await _rebuild_fts()

        # Should have checked for table existence and created it
        execute_calls = [str(c) for c in mock_db.execute.call_args_list]
        assert any("sqlite_master" in c for c in execute_calls)
        assert any("CREATE VIRTUAL TABLE" in c for c in execute_calls)
