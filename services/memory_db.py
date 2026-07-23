# services/memory_db.py
"""Long-term per-message conversation store (aiosqlite, WAL mode).

Separate from bot_memory.py which stores query/response PAIRS.
This module stores individual role/content rows for semantic search
via the search_past_conversations LLM tool.

Also stores system monitoring baselines (time-series metrics) in
``system_baselines`` for fast AVG()/STDDEV() queries.

Binary layout: each embedding is 1024 × float32 = 4096 bytes (struct.pack).

Facade: search → memory_db_search.py, baselines → memory_db_baselines.py.
"""

import logging
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from config import EMBEDDING_DIM
from services.db_pool import get_pool
from services.embedding_service import get_embedding_service, serialize_vector
from services.memory_store import _ensure_init as _memory_ensure_init
from services.memory_store import get_memory_pool

logger = logging.getLogger(__name__)

_init_done: bool = False

# ── Vectorlite HNSW Index ──
try:
    import vectorlite

    _VECTORLITE_AVAILABLE = True
except ImportError:
    _VECTORLITE_AVAILABLE = False
    logger.warning("[MemoryDB] vectorlite not installed; semantic search falls back to brute-force.")

_VECTORLITE_INIT_DONE: bool = False
_VECTORLITE_INDEX_DIM: int = EMBEDDING_DIM  # Single Source of Truth (config.py)


async def _init_db() -> None:
    """Delegate schema init to memory_store (Sprint 5 Phase 2)."""
    await _memory_ensure_init()


async def _ensure_init() -> None:
    global _init_done
    if not _init_done:
        await _memory_ensure_init()
        _init_done = True


async def _ensure_vectorlite(db: aiosqlite.Connection) -> None:
    """Load vectorlite extension on a pooled connection (idempotent per connection)."""
    if _VECTORLITE_AVAILABLE:
        await db.enable_load_extension(True)
        await db.load_extension(vectorlite.vectorlite_path())


async def _init_vectorlite(db: aiosqlite.Connection) -> None:
    """Safely load vectorlite extension and create HNSW virtual table."""
    global _VECTORLITE_INIT_DONE
    if _VECTORLITE_INIT_DONE:
        return
    try:
        await _ensure_vectorlite(db)
        await db.execute(
            f"""
            CREATE VIRTUAL TABLE IF NOT EXISTS vec_conversations
            USING vectorlite(
                embedding float[{_VECTORLITE_INDEX_DIM}],
                hnsw(m=16, ef_construction=200)
            )
            """
        )
        await db.commit()
        _VECTORLITE_INIT_DONE = True
        logger.info("[MemoryDB] vectorlite HNSW index ready (dim=%d)", _VECTORLITE_INDEX_DIM)
    except Exception as exc:
        logger.warning("[MemoryDB] vectorlite init failed (fallback to brute-force): %s", exc)
        _VECTORLITE_INIT_DONE = False


async def store_message(role: str, content: str) -> None:
    """Persist a single message with its embedding.

    Called via asyncio.create_task() — never blocks the response path.
    Embedding failures are silently logged; the row is still inserted without BLOB.
    """
    await _ensure_init()

    embedding_blob: bytes | None = None
    try:
        svc = get_embedding_service()
        vectors = await svc.embed(["passage: " + content])
        embedding_blob = serialize_vector(vectors[0])
    except Exception as exc:
        logger.debug("[MemoryDB] store_message embed failed (stored without vector): %s", exc)

    try:
        async with get_memory_pool().acquire() as db:
            cursor = await db.execute(
                "INSERT INTO conversations (role, content, embedding) VALUES (?, ?, ?)",
                (role, content, embedding_blob),
            )
            await db.commit()
            row_id = cursor.lastrowid
        logger.debug("[MemoryDB] stored role=%s len=%d", role, len(content))
        if embedding_blob and row_id:
            await _vectorlite_upsert(row_id, embedding_blob)
    except Exception as exc:
        logger.warning("[MemoryDB] store_message DB write failed: %s", exc)


async def _vectorlite_upsert(row_id: int, embedding_blob: bytes) -> None:
    """Insert/update row in vectorlite virtual table after main table insert."""
    if not _VECTORLITE_AVAILABLE or not _VECTORLITE_INIT_DONE:
        return
    try:
        async with get_memory_pool().acquire() as db:
            await _ensure_vectorlite(db)
            await db.execute("DELETE FROM vec_conversations WHERE rowid = ?", (row_id,))
            await db.execute(
                "INSERT INTO vec_conversations(rowid, embedding) VALUES (?, ?)",
                (row_id, embedding_blob),
            )
            await db.commit()
    except Exception as exc:
        logger.debug("[MemoryDB] vectorlite upsert failed: %s", exc)


async def cleanup_old_conversations(days: int = 30) -> int:
    """Purge conversation rows older than ``days`` days. Returns deleted count."""
    async with get_memory_pool().acquire() as db:
        cur = await db.execute(
            "DELETE FROM conversations WHERE timestamp < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cur.rowcount


# ── Threat Hunt History ──
async def store_threat_hunt(prompt_hash: str, score: float, summary: str, dispatched: bool) -> None:
    """Persist a hunt record (dedup + audit trail)."""
    await _ensure_init()
    async with get_memory_pool().acquire() as db:
        await db.execute(
            "INSERT INTO threat_hunts (prompt_hash, threat_score, summary, dispatched) VALUES (?, ?, ?, ?)",
            (prompt_hash, score, summary[:4000], int(dispatched)),
        )
        await db.commit()


async def get_last_hunt() -> dict[str, Any] | None:
    """Return the most recent hunt record, or None if no hunts yet."""
    await _ensure_init()
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "SELECT prompt_hash, threat_score, summary, dispatched, timestamp "
            "FROM threat_hunts ORDER BY id DESC LIMIT 1"
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return {
            "prompt_hash": row[0],
            "threat_score": row[1],
            "summary": row[2],
            "dispatched": bool(row[3]),
            "timestamp": row[4],
        }


async def get_hunts_last_24h() -> list[dict[str, Any]]:
    """Return hunts from the last 24 hours (for daily report)."""
    await _ensure_init()
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "SELECT timestamp, threat_score, summary, dispatched "
            "FROM threat_hunts WHERE timestamp >= datetime('now', '-24 hours') "
            "ORDER BY id DESC"
        )
        rows = await cursor.fetchall()
        return [
            {
                "timestamp": r[0],
                "threat_score": r[1],
                "summary": r[2],
                "dispatched": bool(r[3]),
            }
            for r in rows
        ]


async def get_hunts_last_7d() -> dict[str, Any]:
    """Aggregate hunt statistics from last 7 days (for weekly reflection).

    Returns metadata only (count, avg score, dispatches) — NOT report content.
    Keeps the LLM input compact (<100 tokens for this section).
    """
    await _ensure_init()
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "SELECT COUNT(*) as total, "
            "COALESCE(AVG(threat_score), 0) as avg_score, "
            "COALESCE(SUM(CASE WHEN dispatched = 1 THEN 1 ELSE 0 END), 0) as dispatched, "
            "COALESCE(SUM(CASE WHEN threat_score > 0.8 THEN 1 ELSE 0 END), 0) as high_risk "
            "FROM threat_hunts WHERE timestamp >= datetime('now', '-7 days')"
        )
        row = await cursor.fetchone()
        if not row:
            return {"total": 0, "avg_score": 0.0, "dispatched": 0, "high_risk": 0}
        return {
            "total": row[0] or 0,
            "avg_score": round(row[1] or 0.0, 2),
            "dispatched": row[2] or 0,
            "high_risk": row[3] or 0,
        }


def _fmt_ts(ts: str) -> str:
    """Trim ISO timestamp to 'YYYY-MM-DD HH:MM'."""
    return ts[:16] if ts else "?"


# ── Re-exports for backward compatibility ──
from services.memory_db_baselines import (  # noqa: E402
    cleanup_old_baselines,
    get_baseline_raw_values,
    get_baseline_stats,
    store_baseline_metrics,
)
from services.memory_db_search import search_conversations  # noqa: E402

__all__ = [
    "_VECTORLITE_AVAILABLE",
    "_VECTORLITE_INDEX_DIM",
    "_ensure_init",
    "_fmt_ts",
    "cleanup_old_baselines",
    "cleanup_old_conversations",
    "get_baseline_raw_values",
    "get_baseline_stats",
    "get_last_hunt",
    "search_conversations",
    "store_baseline_metrics",
    "store_message",
    "store_threat_hunt",
]
