# tests/test_tier4_m2_migration.py
"""Tests for Tier 4 M2: net_baselines last_seen column + lazy eviction.

M2: Schema migration adds last_seen column (PRAGMA user_version=1).
record_net_baselines uses ON CONFLICT DO UPDATE to refresh last_seen.
is_known_combo uses last_seen for TTL + lazy eviction (DELETE expired).
"""

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_schema_migration_adds_last_seen():
    """M2: _ensure_init migrates net_baselines with last_seen column."""
    import services.metrics_db as mdb
    from services.metrics_db import _ensure_init

    mdb._init_done = False

    mock_cursor = AsyncMock()
    # PRAGMA table_info returns rows as tuples: (cid, name, type, ...)
    mock_cursor.fetchall.side_effect = [
        [(0, "expires_at", "DATETIME")],  # intel_whitelist has expires_at
        [
            (0, "id"),
            (1, "process_name"),
            (2, "remote_ip"),
            (3, "remote_port"),
            (4, "first_seen"),
        ],  # net_baselines no last_seen
    ]
    mock_cursor.fetchone.return_value = (0,)  # user_version = 0

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with patch("services.metrics_db.get_metrics_pool") as mock_pool:
        mock_pool.return_value.acquire.return_value = mock_acquire
        await _ensure_init()

    # Verify ALTER TABLE was called
    alter_calls = [c for c in mock_db.execute.call_args_list if "ALTER TABLE net_baselines" in str(c)]
    assert len(alter_calls) == 1
    # Verify PRAGMA user_version = 1 was set
    version_calls = [c for c in mock_db.execute.call_args_list if "PRAGMA user_version = 1" in str(c)]
    assert len(version_calls) == 1


@pytest.mark.asyncio
async def test_schema_migration_skips_if_already_versioned():
    """M2: If user_version >= 1, migration is skipped."""
    import services.metrics_db as mdb
    from services.metrics_db import _ensure_init

    mdb._init_done = False

    mock_cursor = AsyncMock()
    mock_cursor.fetchall.side_effect = [
        [(0, "expires_at", "DATETIME")],  # intel_whitelist has expires_at
    ]
    mock_cursor.fetchone.return_value = (1,)  # user_version = 1

    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with patch("services.metrics_db.get_metrics_pool") as mock_pool:
        mock_pool.return_value.acquire.return_value = mock_acquire
        await _ensure_init()

    # No ALTER TABLE should be called
    alter_calls = [c for c in mock_db.execute.call_args_list if "ALTER TABLE net_baselines" in str(c)]
    assert len(alter_calls) == 0


@pytest.mark.asyncio
async def test_record_net_baselines_uses_on_conflict_update():
    """M2: record_net_baselines uses ON CONFLICT DO UPDATE last_seen."""
    from services.net_baseline import record_net_baselines

    mock_db = AsyncMock()
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with (
        patch("services.net_baseline.get_metrics_pool") as mock_pool,
        patch("services.net_baseline._ensure_table", new_callable=AsyncMock),
    ):
        mock_pool.return_value.acquire.return_value = mock_acquire
        await record_net_baselines(
            [
                {"proc_name": "chrome.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
            ]
        )

    sql = mock_db.executemany.call_args[0][0]
    assert "ON CONFLICT" in sql
    assert "DO UPDATE SET last_seen" in sql


@pytest.mark.asyncio
async def test_is_known_combo_uses_last_seen():
    """M2: is_known_combo queries last_seen, not first_seen."""
    from services.net_baseline import is_known_combo

    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = (1,)  # found
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with (
        patch("services.net_baseline.get_metrics_pool") as mock_pool,
        patch("services.net_baseline._ensure_table", new_callable=AsyncMock),
    ):
        mock_pool.return_value.acquire.return_value = mock_acquire
        result = await is_known_combo("chrome.exe", "1.2.3.4", 443)

    assert result is True
    select_sql = mock_db.execute.call_args_list[0][0][0]
    assert "last_seen > datetime" in select_sql
    assert "first_seen" not in select_sql


@pytest.mark.asyncio
async def test_is_known_combo_lazy_eviction():
    """M2: Expired entries are deleted (lazy eviction)."""
    from services.net_baseline import is_known_combo

    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = None  # no recent row
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with (
        patch("services.net_baseline.get_metrics_pool") as mock_pool,
        patch("services.net_baseline._ensure_table", new_callable=AsyncMock),
    ):
        mock_pool.return_value.acquire.return_value = mock_acquire
        result = await is_known_combo("chrome.exe", "1.2.3.4", 443)

    assert result is False
    # Second call should be DELETE (lazy eviction)
    delete_sql = mock_db.execute.call_args_list[1][0][0]
    assert "DELETE FROM net_baselines" in delete_sql
    assert "last_seen <= datetime" in delete_sql


@pytest.mark.asyncio
async def test_benign_baseline_ips_uses_last_seen():
    """M2: benign_baseline_ips checks last_seen TTL."""
    from services.net_baseline import benign_baseline_ips

    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = (1,)  # found
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with (
        patch("services.net_baseline.get_metrics_pool") as mock_pool,
        patch("services.net_baseline._ensure_table", new_callable=AsyncMock),
    ):
        mock_pool.return_value.acquire.return_value = mock_acquire
        result = await benign_baseline_ips({"1.2.3.4"})

    assert "1.2.3.4" in result
    sql = mock_db.execute.call_args_list[0][0][0]
    assert "last_seen > datetime" in sql
