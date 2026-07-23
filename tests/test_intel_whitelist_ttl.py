# tests/test_intel_whitelist_ttl.py
"""Tests for intel_whitelist hard TTL — expires_at column + cleanup.

Validates that:
1. record_intel_whitelist sets expires_at ~7 days ahead
2. is_intel_whitelisted respects expiry (fresh → True, expired → False)
3. cleanup_intel_whitelist deletes only expired rows
4. Re-recording an IP refreshes the TTL
"""

import pytest

from services.metrics_db import get_metrics_pool
from services.net_baseline import (
    add_to_baseline,
    benign_baseline_ips,
    cleanup_intel_whitelist,
    is_intel_whitelisted,
    record_intel_whitelist,
)


@pytest.fixture(autouse=True)
def reset_net_baseline_init(monkeypatch):
    """Reset net_baseline._init_done so tables are created in the temp DB."""
    monkeypatch.setattr("services.net_baseline._init_done", False)


@pytest.fixture(autouse=True)
async def ensure_metrics_tables():
    """Ensure intel_whitelist table exists before each test."""
    from services.metrics_db import _ensure_init as _metrics_ensure_init

    await _metrics_ensure_init()


async def test_record_sets_expires_at():
    """record_intel_whitelist should set expires_at ~7 days in the future."""
    await record_intel_whitelist("10.0.0.1")
    pool = get_metrics_pool()
    async with pool.acquire() as db:
        cursor = await db.execute(
            "SELECT julianday(expires_at) - julianday('now') FROM intel_whitelist WHERE remote_ip = ?",
            ("10.0.0.1",),
        )
        row = await cursor.fetchone()
    assert row is not None
    day_diff = row[0]
    assert 6.9 < day_diff < 7.1, f"expires_at diff {day_diff} not ~7 days"


async def test_is_whitelisted_fresh_entry():
    """A freshly recorded IP should be whitelisted."""
    await record_intel_whitelist("192.168.1.100")
    assert await is_intel_whitelisted("192.168.1.100") is True


async def test_is_whitelisted_expired_entry():
    """An expired IP should NOT be whitelisted."""
    pool = get_metrics_pool()
    async with pool.acquire() as db:
        await db.execute(
            "INSERT OR REPLACE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
            "VALUES ('203.0.113.5', datetime('now', '-10 days'), datetime('now', '-3 days'))"
        )
        await db.commit()
    assert await is_intel_whitelisted("203.0.113.5") is False


async def test_is_whitelisted_unknown_ip():
    """An IP not in the table should return False."""
    assert await is_intel_whitelisted("198.51.100.99") is False


async def test_cleanup_deletes_expired():
    """cleanup_intel_whitelist should delete only expired rows."""
    pool = get_metrics_pool()
    async with pool.acquire() as db:
        await db.execute(
            "INSERT OR REPLACE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
            "VALUES ('10.10.10.10', datetime('now', '-30 days'), datetime('now', '-20 days'))"
        )
        await db.execute(
            "INSERT OR REPLACE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
            "VALUES ('10.10.10.11', datetime('now'), datetime('now', '+7 days'))"
        )
        await db.commit()

    deleted = await cleanup_intel_whitelist()
    assert deleted >= 1

    async with pool.acquire() as db:
        cursor = await db.execute("SELECT remote_ip FROM intel_whitelist WHERE remote_ip = '10.10.10.10'")
        assert await cursor.fetchone() is None
        cursor = await db.execute("SELECT remote_ip FROM intel_whitelist WHERE remote_ip = '10.10.10.11'")
        assert await cursor.fetchone() is not None


async def test_rerecord_refreshes_ttl():
    """Re-recording an IP should refresh its expires_at."""
    pool = get_metrics_pool()
    async with pool.acquire() as db:
        await db.execute(
            "INSERT OR REPLACE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
            "VALUES ('172.16.0.1', datetime('now', '-30 days'), datetime('now', '-20 days'))"
        )
        await db.commit()

    assert await is_intel_whitelisted("172.16.0.1") is False

    await record_intel_whitelist("172.16.0.1")
    assert await is_intel_whitelisted("172.16.0.1") is True


async def test_record_empty_ip_skipped():
    """Empty IP should be silently skipped (no DB write, no exception)."""
    await record_intel_whitelist("")
    assert await is_intel_whitelisted("") is False


async def test_benign_baseline_ips_empty_input():
    """Empty candidate set → empty result, no DB access."""
    assert await benign_baseline_ips(set()) == set()


async def test_benign_baseline_ips_matches_learned_combo():
    """An IP learned as a benign combo is returned; an unknown IP is not."""
    await add_to_baseline("claude.exe", "18.97.36.5", 443)
    result = await benign_baseline_ips({"18.97.36.5", "203.0.113.9"})
    assert result == {"18.97.36.5"}


async def test_benign_baseline_ips_matches_intel_whitelist():
    """An IP on the live intel whitelist is returned via the whitelist branch."""
    await record_intel_whitelist("198.51.100.7")
    result = await benign_baseline_ips({"198.51.100.7", "203.0.113.9"})
    assert result == {"198.51.100.7"}
