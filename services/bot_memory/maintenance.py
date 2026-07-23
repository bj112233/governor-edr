"""Daily memory maintenance: FTS5 integrity check + embedding backfill."""

import logging

from services.memory_store import get_memory_pool

logger = logging.getLogger(__name__)


async def check_fts5_integrity() -> bool:
    """Run FTS5 integrity check. Rebuild index if corrupted.

    Returns True if FTS5 is healthy, False if rebuilt.
    Uses fts_manager._rebuild_fts (robust version that handles missing table).
    """
    try:
        async with get_memory_pool().acquire() as db:
            cursor = await db.execute("INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')")
            result = await cursor.fetchone()
            if result and result[0] == "ok":
                logger.debug("[MemoryMaintenance] FTS5 integrity: OK")
                return True
    except Exception as e:
        logger.warning("[MemoryMaintenance] FTS5 integrity check failed: %s — rebuilding", e)
        await _rebuild_fts()
        return False
    # If we get here without exception, it's OK
    return True


async def _rebuild_fts() -> None:
    """Rebuild FTS5 index — delegates to fts_manager for robust handling.

    Handles both corruption AND missing table cases (backfill from memories).
    """
    from .fts_manager import _rebuild_fts as _fts_rebuild

    try:
        async with get_memory_pool().acquire() as db:
            await _fts_rebuild(db)
    except Exception as e:
        logger.error("[MemoryMaintenance] FTS5 rebuild failed: %s", e)


async def backfill_missing_embeddings() -> int:
    """Backfill embeddings for memories with NULL embedding column.

    Returns count of embeddings backfilled.
    """
    try:
        from services.embedding_service import get_embedding_service, serialize_vector
    except ImportError:
        logger.debug("[MemoryMaintenance] Embedding service unavailable — skip backfill")
        return 0

    try:
        svc = get_embedding_service()
    except Exception:
        logger.debug("[MemoryMaintenance] Embedding service not initialized — skip backfill")
        return 0

    count = 0
    try:
        async with get_memory_pool().acquire() as db:
            cursor = await db.execute(
                "SELECT id, query, response FROM memories WHERE embedding IS NULL AND is_archived = 0 LIMIT 50"
            )
            rows = await cursor.fetchall()
            if not rows:
                return 0

            for row_id, query, response in rows:
                try:
                    text = f"query: {query}\nresponse: {response[:500]}"
                    vec = await svc.embed([text])
                    blob = serialize_vector(vec[0])
                    await db.execute(
                        "UPDATE memories SET embedding = ? WHERE id = ?",
                        (blob, row_id),
                    )
                    count += 1
                except Exception as e:
                    logger.debug("[MemoryMaintenance] Embed failed for memory %d: %s", row_id, e)
                    break  # Embedding service down — stop

            await db.commit()
    except Exception as e:
        logger.error("[MemoryMaintenance] Embedding backfill error: %s", e)

    if count > 0:
        logger.info("[MemoryMaintenance] Backfilled %d missing embeddings", count)
    return count


async def run_memory_maintenance() -> None:
    """Daily maintenance: FTS5 integrity + embedding backfill + WAL checkpoint."""
    await check_fts5_integrity()
    await backfill_missing_embeddings()
    await wal_checkpoint()


async def wal_checkpoint() -> None:
    """Checkpoint WAL to prevent unbounded growth.

    Uses PASSIVE mode (not TRUNCATE) because the memory pool keeps up to 4
    persistent connections. TRUNCATE requires exclusive access — no other
    connection may hold a WAL read snapshot — which is impossible to guarantee
    in a pooled environment and causes "database table is locked". PASSIVE
    checkpoints as many frames as possible without waiting for readers, never
    fails, and still bounds WAL size (frames move to the main DB; SQLite reuses
    freed WAL frames + default autocheckpoint at 1000 pages).
    """
    try:
        async with get_memory_pool().acquire() as db:
            await db.execute("PRAGMA wal_checkpoint(PASSIVE)")
            await db.commit()
            logger.debug("[MemoryMaintenance] WAL checkpoint: PASSIVE done")
    except Exception as e:
        logger.warning("[MemoryMaintenance] WAL checkpoint failed: %s", e)
