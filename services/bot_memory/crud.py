# services/bot_memory/crud.py
"""MemoryService CRUD — store, search, retrieve."""

import json
import logging
import re as _re
import sqlite3
from typing import Optional

from .crud_search import async_search as _async_search_impl
from .crud_search import search as _search_impl
from .crud_search import search_with_decay as _search_with_decay_impl
from .episodic import EpisodicStore
from .fts_manager import _rebuild_fts
from .models import (
    _FTS5_MAX_TOKENS,
    EventQuery,
    MemoryEntry,
    MemoryEvent,
    MemoryQuery,
    _auto_tag_topic,
)
from .schema import _pool

logger = logging.getLogger(__name__)


class MemoryService:
    """מינימליסטי: זיכרון על גבי SQLite קיים."""

    def __init__(self) -> None:
        self._initialized: bool = False

    async def _ensure_init(self) -> None:
        """Lazy async initialization — safe to call from any coroutine."""
        if self._initialized:
            return
        from .schema import _ensure_init as _schema_ensure_init

        await _schema_ensure_init()
        self._initialized = True

    async def store(self, entry: MemoryEntry, db=None) -> int:
        """שמור זיכרון חדש. מחזיר ID. מוסיף auto-tag topic ל-context.

        Args:
            db: Optional existing connection. When provided, the caller manages
                the transaction (no commit/rollback here). Used by Night Watchman
                for atomic summary+archive.
        """
        try:
            text_for_topic = f"{entry.query} {entry.response}"[:500]
            topic = _auto_tag_topic(text_for_topic)
            ctx = json.loads(entry.context) if entry.context else {}
            ctx["topic"] = topic
            entry.context = json.dumps(ctx, ensure_ascii=False)
        except Exception:
            pass
        await self._ensure_init()

        async def _do_insert(conn) -> int:
            try:
                cursor = await conn.execute(
                    """
                    INSERT INTO memories (ts, query, response, context, memory_type, embedding)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry.ts,
                        entry.query,
                        entry.response,
                        entry.context,
                        entry.memory_type,
                        entry.embedding,
                    ),
                )
                last_id = cursor.lastrowid
                return last_id or 0
            except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
                error_msg = str(e).lower()
                if "fts5" in error_msg or "malformed" in error_msg or "trigger" in error_msg:
                    logger.warning(
                        "[BotMemory] INSERT failed due to FTS5 corruption (%s). Rebuilding...",
                        e,
                    )
                    await _rebuild_fts(conn)
                    cursor = await conn.execute(
                        """
                        INSERT INTO memories (ts, query, response, context, memory_type, embedding)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            entry.ts,
                            entry.query,
                            entry.response,
                            entry.context,
                            entry.memory_type,
                            entry.embedding,
                        ),
                    )
                    last_id = cursor.lastrowid
                    return last_id or 0
                raise

        if db is not None:
            return await _do_insert(db)
        async with _pool.acquire() as db:
            last_id = await _do_insert(db)
            await db.commit()
            return last_id

    async def search(self, mq: MemoryQuery) -> list[MemoryEntry]:
        """חיפוש FTS5 semantic-like — מוגן מפני תווי-syntax שגויים."""
        return await _search_impl(self, mq)

    async def async_search(self, mq: MemoryQuery) -> list[MemoryEntry]:
        """Pure-Python cosine similarity search over BLOB embeddings."""
        return await _async_search_impl(self, mq)

    async def search_with_decay(self, mq: MemoryQuery, decay_lambda: float = 0.001) -> list[MemoryEntry]:
        """Over-fetch & Re-rank: HNSW exact distance × temporal decay."""
        return await _search_with_decay_impl(self, mq, decay_lambda)

    async def get_recent(self, limit: int = 10, memory_type: str | None = None) -> list[MemoryEntry]:
        """האחרונים לפי זמן (active only)."""
        await self._ensure_init()
        async with _pool.acquire() as db:
            if memory_type:
                cursor = await db.execute(
                    """
                    SELECT id, ts, query, response, context, memory_type
                    FROM memories WHERE memory_type = ? AND is_archived = 0
                    ORDER BY id DESC LIMIT ?
                    """,
                    (memory_type, limit),
                )
            else:
                cursor = await db.execute(
                    """
                    SELECT id, ts, query, response, context, memory_type
                    FROM memories WHERE is_archived = 0
                    ORDER BY id DESC LIMIT ?
                    """,
                    (limit,),
                )
            rows = await cursor.fetchall()
            return [
                MemoryEntry(
                    id=row[0],
                    ts=row[1],
                    query=row[2],
                    response=row[3],
                    context=row[4],
                    memory_type=row[5],
                )
                for row in rows
            ]

    def format_for_context(self, entries: list[MemoryEntry], max_total: int = 2000) -> str:
        """פורמט להזרקה ל-system prompt - מוגבל ל-2000 chars."""
        if not entries:
            return ""
        lines = ["\n[Context from memory:]"]
        for i, e in enumerate(entries, 1):
            lines.append(f"{i}. [{e.memory_type}]: Q:{e.query[:100]}... A:{e.response[:100]}...")
        result = "\n".join(lines)
        if len(result) > max_total:
            result = result[: max_total - 3] + "..."
        return result

    # ── Episodic memory facade ────────────────────────────────────
    async def store_event(self, event: MemoryEvent) -> int:
        return await get_episodic_store().store(event)

    async def get_event_chain(self, chain_id: str, limit: int = 50) -> list[MemoryEvent]:
        return await get_episodic_store().get_chain(chain_id, limit)

    async def get_recent_events(self, limit: int = 20, event_type: str | None = None) -> list[MemoryEvent]:
        eq = EventQuery(limit=limit, event_type=event_type)
        return await get_episodic_store().query(eq)

    async def purge_old_events(self, days: int = 7) -> int:
        return await get_episodic_store().purge_old(days)


# ── Singletons ─────────────────────────────────────────────────────
_episodic_store: EpisodicStore | None = None


def get_episodic_store() -> EpisodicStore:
    global _episodic_store
    if _episodic_store is None:
        _episodic_store = EpisodicStore()
    return _episodic_store


_memory_service: MemoryService | None = None


def get_memory_service() -> MemoryService:
    """Get singleton MemoryService."""
    global _memory_service
    if _memory_service is None:
        _memory_service = MemoryService()
    return _memory_service
