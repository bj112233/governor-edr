#!/usr/bin/env python3
"""Regression test: pooled connection with an open transaction must be
cleaned up on release so the next acquirer can issue `BEGIN IMMEDIATE`.

Reproduces the original bug:
  sqlite3.OperationalError: cannot start a transaction within a transaction
at services/night_watchman.py:178 (run_memory_compaction).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.db_pool import DBPool


@pytest.fixture
def pool(tmp_path):
    return DBPool(str(tmp_path / "hygiene.db"), max_connections=2)


async def test_open_transaction_cleared_on_release(pool):
    """A caller that leaves a transaction open must not poison the next
    acquirer — the pool rolls back on release."""
    async with pool.acquire() as db:
        await db.execute("CREATE TABLE t (x INTEGER)")
        await db.commit()
        # Start a write transaction and DON'T commit — simulates a caller
        # that forgot to commit (or crashed mid-transaction).
        await db.execute("INSERT INTO t VALUES (1)")
        assert db.in_transaction is True

    # The same connection is returned to _available; next acquire must get a
    # clean connection with no pending transaction.
    async with pool.acquire() as db2:
        assert db2.in_transaction is False, "pool released a dirty connection"
        # The uncommitted INSERT must have been rolled back.
        row = await (await db2.execute("SELECT COUNT(*) FROM t")).fetchone()
        assert row[0] == 0


async def test_begin_immediate_after_dirty_release(pool):
    """Direct repro of the night_watchman crash: after a dirty release, a
    manual `BEGIN IMMEDIATE` must succeed instead of raising
    'cannot start a transaction within a transaction'."""
    async with pool.acquire() as db:
        await db.execute("CREATE TABLE t (x INTEGER)")
        await db.commit()
        await db.execute("INSERT INTO t VALUES (1)")  # open transaction, no commit

    async with pool.acquire() as db2:
        # This is exactly what night_watchman.run_memory_compaction does.
        await db2.execute("BEGIN IMMEDIATE")
        await db2.execute("INSERT INTO t VALUES (2)")
        await db2.commit()

    async with pool.acquire() as db3:
        row = await (await db3.execute("SELECT COUNT(*) FROM t")).fetchone()
        # Only the committed value (2) survives; the dirty (1) was rolled back.
        assert row[0] == 1


async def test_clean_release_stays_clean(pool):
    """A properly committed connection must remain usable and not be
    disturbed by the hygiene rollback (rollback on a non-transaction is a
    no-op)."""
    async with pool.acquire() as db:
        await db.execute("CREATE TABLE t (x INTEGER)")
        await db.execute("INSERT INTO t VALUES (42)")
        await db.commit()
        assert db.in_transaction is False

    async with pool.acquire() as db2:
        row = await (await db2.execute("SELECT COUNT(*) FROM t")).fetchone()
        assert row[0] == 1
