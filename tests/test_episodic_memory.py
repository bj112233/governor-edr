"""Tests for Episodic Memory: event chains, escalation, purge.

Uses an in-memory DB via monkey-patched _pool for hermetic testing.
"""

import asyncio
import json
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

# Ensure services/ is on path
sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from bot_memory.episodic import _ESCALATION_THRESHOLD, EpisodicStore
from bot_memory.models import EventQuery, MemoryEvent


@pytest_asyncio.fixture(loop_scope="function")
async def store(tmp_path):
    """EpisodicStore backed by fresh SQLite per test."""
    import aiosqlite

    db_path = str(tmp_path / "test_episodic.db")

    # Patch _pool on episodic module to use a fresh DB
    from bot_memory import crud, episodic, schema

    class _FakePool:
        def __init__(self, db_path):
            self._db_path = db_path
            self._post = None

        async def set_post_connect(self, fn):
            self._post = fn

        @asynccontextmanager
        async def acquire(self):
            conn = await aiosqlite.connect(self._db_path)
            await conn.execute("PRAGMA foreign_keys = ON")
            await conn.execute("PRAGMA journal_mode = WAL")
            if self._post:
                await self._post(conn)
            try:
                yield conn
            finally:
                await conn.close()

    pool = _FakePool(db_path)

    # Re-create schema in fresh DB
    async with pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity INTEGER DEFAULT 1,
                source TEXT NOT NULL,
                session_id TEXT,
                chain_id TEXT,
                metadata_json TEXT DEFAULT '{}'
            )
            """
        )
        await db.execute("CREATE INDEX idx_events_ts ON events(ts)")
        await db.execute("CREATE INDEX idx_events_escalation ON events(source, event_type, severity, ts)")
        await db.execute("CREATE INDEX idx_events_chain ON events(chain_id)")
        await db.commit()

    # Monkey-patch all modules that use _pool
    original_pool = schema._pool
    schema._pool = pool
    episodic._pool = pool
    crud._episodic_store = None  # force new singleton

    s = EpisodicStore()
    yield s

    # Cleanup
    schema._pool = original_pool
    episodic._pool = original_pool
    crud._episodic_store = None


# ── Tests ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_store_and_retrieve_chain(store):
    chain = "test-chain-1"
    ev1 = MemoryEvent(
        event_type="user_query",
        description="scan the network",
        severity=1,
        source="telegram",
        session_id="sess-1",
        chain_id=chain,
    )
    id1 = await store.store(ev1)
    assert id1 > 0

    ev2 = MemoryEvent(
        event_type="action",
        description="scan_lan executed",
        severity=1,
        source="executor",
        session_id="sess-1",
        chain_id=chain,
    )
    id2 = await store.store(ev2)
    assert id2 > id1

    chain_events = await store.get_chain(chain)
    assert len(chain_events) == 2
    assert chain_events[0].event_type == "user_query"
    assert chain_events[1].event_type == "action"


@pytest.mark.asyncio
async def test_escalation_auto_injected(store):
    chain = "escalation-chain"
    source = "firewall-skill"
    event_type = "alert"

    # Inject threshold-1 events below severity 2 (should NOT escalate)
    for i in range(_ESCALATION_THRESHOLD - 1):
        await store.store(
            MemoryEvent(
                event_type=event_type,
                description=f"low sev alert {i}",
                severity=1,
                source=source,
                chain_id=chain,
            )
        )
    events = await store.get_chain(chain)
    assert len(events) == _ESCALATION_THRESHOLD - 1  # no escalation yet

    # Inject threshold events with severity 2 (should escalate)
    for i in range(_ESCALATION_THRESHOLD):
        await store.store(
            MemoryEvent(
                event_type=event_type,
                description=f"high sev alert {i}",
                severity=2,
                source=source,
                chain_id=chain,
            )
        )

    events = await store.get_chain(chain)
    # threshold low-sev + threshold high-sev + 1 escalation event
    assert len(events) == (_ESCALATION_THRESHOLD - 1) + _ESCALATION_THRESHOLD + 1
    escalation_events = [e for e in events if e.event_type == "escalation"]
    assert len(escalation_events) == 1
    assert escalation_events[0].severity == 3
    assert source in escalation_events[0].description


@pytest.mark.asyncio
async def test_escalation_no_duplicate_for_chain(store):
    chain = "dup-chain"
    source = "system"

    # Trigger escalation
    for i in range(_ESCALATION_THRESHOLD):
        await store.store(
            MemoryEvent(
                event_type="alert",
                description=f"dup alert {i}",
                severity=2,
                source=source,
                chain_id=chain,
            )
        )

    # Add another event in same chain — should NOT create second escalation
    await store.store(
        MemoryEvent(
            event_type="alert",
            description="extra alert",
            severity=2,
            source=source,
            chain_id=chain,
        )
    )

    events = await store.get_chain(chain)
    escalation_events = [e for e in events if e.event_type == "escalation"]
    assert len(escalation_events) == 1, "Only one escalation per chain allowed"


@pytest.mark.asyncio
async def test_escalation_guard_clause_no_recursive_meta(store):
    """Escalation events themselves must NOT trigger further escalation."""
    chain = "meta-chain"

    # Manually inject escalation events (severity 3)
    for i in range(_ESCALATION_THRESHOLD):
        await store.store(
            MemoryEvent(
                event_type="escalation",
                description=f"manual escalation {i}",
                severity=3,
                source="episodic_store",
                chain_id=chain,
            )
        )

    events = await store.get_chain(chain)
    assert len(events) == _ESCALATION_THRESHOLD
    # No additional escalation event should have been auto-created
    assert all(e.event_type == "escalation" for e in events)


@pytest.mark.asyncio
async def test_query_by_filters(store):
    await store.store(MemoryEvent(event_type="action", description="a1", source="executor"))
    await store.store(MemoryEvent(event_type="alert", description="a2", source="monitor"))
    await store.store(MemoryEvent(event_type="action", description="a3", source="executor"))

    results = await store.query(EventQuery(event_type="action", limit=10))
    assert len(results) == 2
    assert all(r.event_type == "action" for r in results)

    results = await store.query(EventQuery(source="monitor", limit=10))
    assert len(results) == 1
    assert results[0].description == "a2"


@pytest.mark.asyncio
async def test_purge_old(store):
    old_ts = (datetime.now() - timedelta(days=10)).isoformat()
    await store.store(
        MemoryEvent(
            event_type="action",
            description="old event",
            source="test",
            ts=old_ts,
        )
    )
    await store.store(
        MemoryEvent(
            event_type="action",
            description="recent event",
            source="test",
        )
    )

    deleted = await store.purge_old(days=7)
    assert deleted == 1

    remaining = await store.query(EventQuery(source="test", limit=10))
    assert len(remaining) == 1
    assert remaining[0].description == "recent event"


@pytest.mark.asyncio
async def test_crud_facade_methods():
    """Test MemoryService facade delegates to EpisodicStore correctly."""
    from bot_memory.crud import get_episodic_store, get_memory_service

    svc = get_memory_service()
    assert hasattr(svc, "store_event")
    assert hasattr(svc, "get_event_chain")
    assert hasattr(svc, "get_recent_events")
    assert hasattr(svc, "purge_old_events")

    store = get_episodic_store()
    assert isinstance(store, EpisodicStore)


@pytest.mark.asyncio
async def test_highlevel_inject_and_recall(store):
    """Test high-level inject_event and recall_episodes API."""
    # Temporarily patch _pool in highlevel's imports
    import bot_memory.highlevel as hl
    from bot_memory import schema
    from bot_memory.highlevel import inject_event, recall_episodes

    old_pool = getattr(hl, "_pool", None)
    # highlevel uses get_episodic_store which uses _pool from episodic/schema
    # This test relies on the store fixture having patched _pool already

    eid = await inject_event(
        event_type="user_query",
        description="test query",
        source="test",
        chain_id="hl-chain",
    )
    assert eid > 0

    text = await recall_episodes(chain_id="hl-chain", limit=5)
    assert "test query" in text
    assert "user_query" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
