# services/bot_memory/vector_manager.py
"""Vectorlite HNSW vector search + upsert for semantic memory retrieval."""

import asyncio
import logging
import uuid
from typing import Optional

from config import EMBEDDING_DIM

from .models import (
    MemoryEntry,
    MemoryQuery,
)
from .schema import _pool

logger = logging.getLogger(__name__)

_CLUSTER_DISTANCE_THRESHOLD = 0.3  # L2 distance; smaller = more similar

# ── Vectorlite availability (shared with memory_db.py) ──
try:
    import vectorlite

    from services.memory_db import _VECTORLITE_AVAILABLE, _VECTORLITE_INDEX_DIM

    _VECTORLITE_MEM_INIT_DONE: bool = False
except ImportError:
    _VECTORLITE_AVAILABLE = False
    _VECTORLITE_INDEX_DIM = EMBEDDING_DIM  # Single Source of Truth (config.py)
    _VECTORLITE_MEM_INIT_DONE = False

# Lazy-init lock to prevent concurrent vectorlite table creation
_VECTORLITE_INIT_LOCK: asyncio.Lock | None = None


def _get_init_lock() -> asyncio.Lock:
    """Lazy-init lock — must be called inside event loop."""
    global _VECTORLITE_INIT_LOCK
    if _VECTORLITE_INIT_LOCK is None:
        _VECTORLITE_INIT_LOCK = asyncio.Lock()
    return _VECTORLITE_INIT_LOCK


async def _vectorlite_search_memories(mq: MemoryQuery) -> list[MemoryEntry] | None:
    """HNSW vector search via vectorlite on memories table — pure async via pool."""
    global _VECTORLITE_MEM_INIT_DONE
    if not _VECTORLITE_AVAILABLE:
        return None
    try:
        from services.embedding_service import get_embedding_service, serialize_vector

        svc = get_embedding_service()
        query_vec = (await svc.embed(["query: " + mq.query]))[0]
        query_blob = serialize_vector(query_vec)

        async with _pool.acquire() as db:
            # Thread-safe init: lock prevents concurrent CREATE VIRTUAL TABLE
            if not _VECTORLITE_MEM_INIT_DONE:
                async with _get_init_lock():
                    if not _VECTORLITE_MEM_INIT_DONE:
                        await db.execute(
                            f"""
                            CREATE VIRTUAL TABLE IF NOT EXISTS vec_memories
                            USING vectorlite(
                                embedding float[{_VECTORLITE_INDEX_DIM}],
                                hnsw(m=16, ef_construction=200)
                            )
                            """
                        )
                        _VECTORLITE_MEM_INIT_DONE = True
            # Query-time HNSW recall/latency trade-off: 64 ~ 95% recall
            try:
                await db.execute("SELECT vectorlite_config('ef_search', 64)")
            except Exception:
                pass
            _fetch_limit = mq.limit * 4
            cursor = await db.execute(
                """
                SELECT m.id, m.ts, m.query, m.response, m.context, m.memory_type, v.distance
                FROM vec_memories v
                JOIN memories m ON m.id = v.rowid
                WHERE v.embedding MATCH ? AND m.is_archived = 0
                ORDER BY v.distance
                LIMIT ?
                """,
                (query_blob, _fetch_limit),
            )
            rows = await cursor.fetchall()
            if not rows:
                return None
            _VECTORLITE_MEM_INIT_DONE = True
            if mq.memory_type:
                rows = [r for r in rows if r[5] == mq.memory_type]
                if not rows:
                    return None
            return [
                MemoryEntry(
                    id=row[0],
                    ts=row[1],
                    query=row[2],
                    response=row[3],
                    context=row[4],
                    memory_type=row[5],
                    distance=row[6],
                )
                for row in rows
            ]
    except Exception as exc:
        logger.debug("[Memory] _vectorlite_search_memories failed: %s", exc)
        return None


async def _vectorlite_upsert_memory(row_id: int, embedding_blob: bytes, db=None) -> None:
    """Insert/update row in vectorlite virtual table for memories — pure async.

    Args:
        db: Optional existing connection. When provided, the caller manages
            the transaction (no commit here). Used by Night Watchman for
            atomic summary+archive.
    """
    if not _VECTORLITE_AVAILABLE:
        return
    try:
        if db is not None:
            await db.execute(
                f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS vec_memories
                USING vectorlite(
                    embedding float[{_VECTORLITE_INDEX_DIM}],
                    hnsw(m=16, ef_construction=200)
                )
                """
            )
            await db.execute(
                "DELETE FROM vec_memories WHERE rowid = ?",
                (row_id,),
            )
            await db.execute(
                "INSERT INTO vec_memories(rowid, embedding) VALUES (?, ?)",
                (row_id, embedding_blob),
            )
            return
        async with _pool.acquire() as db:
            await db.execute(
                f"""
                CREATE VIRTUAL TABLE IF NOT EXISTS vec_memories
                USING vectorlite(
                    embedding float[{_VECTORLITE_INDEX_DIM}],
                    hnsw(m=16, ef_construction=200)
                )
                """
            )
            await db.execute(
                "DELETE FROM vec_memories WHERE rowid = ?",
                (row_id,),
            )
            await db.execute(
                "INSERT INTO vec_memories(rowid, embedding) VALUES (?, ?)",
                (row_id, embedding_blob),
            )
            await db.commit()
    except Exception as exc:
        logger.debug("[Memory] _vectorlite_upsert_memory failed: %s", exc)


async def _incremental_cluster(row_id: int, embedding_blob: bytes) -> str:
    """Assign cluster_id to a new memory via HNSW K=1 nearest neighbor.

    O(log N) per insertion — no batch processing.
    If nearest neighbor distance < threshold, inherit its cluster_id.
    Otherwise, create a new cluster.
    """
    if not _VECTORLITE_AVAILABLE:
        return ""
    try:
        async with _pool.acquire() as db:
            # K=2 because first hit might be self-match
            cursor = await db.execute(
                """
                SELECT rowid, distance
                FROM vec_memories
                WHERE embedding MATCH ?
                ORDER BY distance
                LIMIT 2
                """,
                (embedding_blob,),
            )
            rows = await cursor.fetchall()
            cluster_id = ""
            for rid, distance in rows:
                if rid == row_id:
                    continue
                if distance < _CLUSTER_DISTANCE_THRESHOLD:
                    # Inherit neighbor's cluster_id
                    c = await db.execute("SELECT cluster_id FROM memories WHERE id = ?", (rid,))
                    r = await c.fetchone()
                    cluster_id = r[0] if r and r[0] else str(uuid.uuid4())[:8]
                    break
            if not cluster_id:
                cluster_id = str(uuid.uuid4())[:8]
            await db.execute(
                "UPDATE memories SET cluster_id = ? WHERE id = ?",
                (cluster_id, row_id),
            )
            await db.commit()
            return cluster_id
    except Exception as exc:
        logger.debug("[Memory] _incremental_cluster failed: %s", exc)
        return ""
