# services/bot_memory/archive.py
"""Memory lifecycle — archive, restore, vacuum, cleanup, compaction."""

import json
import logging
from datetime import datetime, timedelta

from .models import MemoryEntry
from .schema import _pool
from .vector_manager import _VECTORLITE_AVAILABLE

logger = logging.getLogger(__name__)


async def fetch_old_memories_for_compaction(
    days_old: int = 30,
    max_chunk_chars: int = 4000,
) -> list[list[MemoryEntry]]:
    """Fetch raw conversation memories older than N days, grouped by topic into char-limited chunks."""
    cutoff = (datetime.now() - timedelta(days=days_old)).isoformat()
    async with _pool.acquire() as db:
        cursor = await db.execute(
            """
            SELECT id, ts, query, response, context, memory_type
            FROM memories
            WHERE ts < ? AND memory_type = 'conversation'
            ORDER BY ts ASC
            """,
            (cutoff,),
        )
        rows = await cursor.fetchall()

    entries = [MemoryEntry(id=r[0], ts=r[1], query=r[2], response=r[3], context=r[4], memory_type=r[5]) for r in rows]

    topic_buckets: dict[str, list[MemoryEntry]] = {}
    for e in entries:
        topic = "general"
        try:
            ctx = json.loads(e.context or "{}")
            topic = ctx.get("topic", "general")
        except Exception:
            pass
        topic_buckets.setdefault(topic, []).append(e)

    chunks: list[list[MemoryEntry]] = []
    for topic, bucket in topic_buckets.items():
        current: list[MemoryEntry] = []
        current_chars = 0
        for entry in bucket:
            entry_chars = len(entry.query) + len(entry.response)
            if current and current_chars + entry_chars > max_chunk_chars:
                chunks.append(current)
                current = [entry]
                current_chars = entry_chars
            else:
                current.append(entry)
                current_chars += entry_chars
        if current:
            chunks.append(current)

    if chunks:
        logger.info("[Memory] Compaction: %d entries -> %d chunks", len(entries), len(chunks))
    return chunks


async def archive_memories_by_ids(ids: list[int], db=None) -> int:
    """Soft-delete (archive) specific memory rows. Returns count.

    Args:
        db: Optional existing connection. When provided, the caller manages
            the transaction (no commit here). Used by Night Watchman for
            atomic summary+archive.
    """
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    if db is not None:
        cursor = await db.execute(
            f"UPDATE memories SET is_archived = 1 WHERE id IN ({placeholders})",
            ids,
        )
        return cursor.rowcount
    async with _pool.acquire() as db:
        cursor = await db.execute(
            f"UPDATE memories SET is_archived = 1 WHERE id IN ({placeholders})",
            ids,
        )
        await db.commit()
        return cursor.rowcount


async def restore_archived_memories(ids: list[int]) -> int:
    """Restore soft-archived memories back to active state."""
    if not ids:
        return 0
    placeholders = ",".join("?" * len(ids))
    async with _pool.acquire() as db:
        cursor = await db.execute(
            f"UPDATE memories SET is_archived = 0 WHERE id IN ({placeholders})",
            ids,
        )
        await db.commit()
        return cursor.rowcount


async def vacuum_archived_memories(days: int = 7) -> int:
    """Hard-delete archived memories older than N days (garbage collection)."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    async with _pool.acquire() as db:
        cursor = await db.execute(
            "SELECT id FROM memories WHERE is_archived = 1 AND ts < ?",
            (cutoff,),
        )
        rows = await cursor.fetchall()
        ids = [r[0] for r in rows]
        if not ids:
            return 0

        placeholders = ",".join("?" * len(ids))
        if _VECTORLITE_AVAILABLE:
            try:
                await db.execute(
                    f"DELETE FROM vec_memories WHERE rowid IN ({placeholders})",
                    ids,
                )
            except Exception as exc:
                logger.warning("[Memory] vec_memories vacuum cleanup failed: %s", exc)

        cursor = await db.execute(
            f"DELETE FROM memories WHERE id IN ({placeholders})",
            ids,
        )
        await db.commit()
        return cursor.rowcount


async def clear_conversation_memory() -> int:
    """Archive all conversation memories — called on /start to reset context."""
    async with _pool.acquire() as db:
        cursor = await db.execute(
            "UPDATE memories SET is_archived = 1 WHERE memory_type = ?",
            ("conversation",),
        )
        archived = cursor.rowcount
        await db.commit()
        return archived


async def cleanup_old_memories(days: int = 7) -> int:
    """Archive memory entries older than specified days."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    async with _pool.acquire() as db:
        cursor = await db.execute(
            "UPDATE memories SET is_archived = 1 WHERE ts < ? AND is_archived = 0",
            (cutoff,),
        )
        archived = cursor.rowcount
        await db.commit()
        logger.info("Archived %d memories older than %d days", archived, days)
        return archived
