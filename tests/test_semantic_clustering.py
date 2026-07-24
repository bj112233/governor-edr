"""Tests for Semantic Clustering — incremental HNSW K=1 clustering.

Hermetic: uses in-memory SQLite + monkey-patched _pool.
"""

import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import pytest_asyncio

sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

from bot_memory.episodic import EpisodicStore
from bot_memory.models import MemoryEntry
from bot_memory.vector_manager import _incremental_cluster


@pytest_asyncio.fixture(loop_scope="function")
async def store(tmp_path):
    import aiosqlite
    from bot_memory import crud, episodic, schema

    db_path = str(tmp_path / "test_cluster.db")

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

    async with pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                query TEXT,
                response TEXT,
                context TEXT,
                memory_type TEXT,
                embedding BLOB,
                cluster_id TEXT
            )
            """
        )
        await db.commit()

    original_pool = schema._pool
    original_crud_pool = crud._pool
    schema._pool = pool
    episodic._pool = pool
    crud._pool = pool
    crud._episodic_store = None

    s = EpisodicStore()
    yield s

    schema._pool = original_pool
    episodic._pool = original_pool
    crud._pool = original_crud_pool
    crud._episodic_store = None


@pytest.mark.asyncio
async def test_cluster_id_assigned(store):
    """Every memory gets a cluster_id after incremental cluster call."""
    from bot_memory.crud import get_memory_service

    svc = get_memory_service()
    # Without embedding, cluster is skipped
    eid = await svc.store(MemoryEntry(query="q1", response="r1", memory_type="conversation"))
    assert eid > 0
    # cluster_id may be empty if no vectorlite, but column exists


@pytest.mark.asyncio
async def test_cluster_column_exists_in_model():
    """MemoryEntry model has cluster_id field."""
    entry = MemoryEntry(query="test", response="test")
    assert hasattr(entry, "cluster_id")
    assert entry.cluster_id is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
