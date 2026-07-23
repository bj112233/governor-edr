# services/bot_memory/schema.py
"""SQLite schema initialization — tables, indexes, FTS5, triggers, migrations."""

import logging
import sqlite3
from pathlib import Path

import aiosqlite

from services.db_pool import get_pool
from services.memory_store import _ensure_init as _memory_ensure_init
from services.memory_store import get_memory_pool

from .fts_manager import _rebuild_fts

logger = logging.getLogger(__name__)

_pool = get_pool(db_type="memory", max_connections=4)


async def _load_vectorlite_extension(conn):
    """Post-connect hook: load vectorlite C extension for HNSW vector search."""
    try:
        import vectorlite

        await conn.enable_load_extension(True)
        await conn.load_extension(vectorlite.vectorlite_path())
    except ImportError:
        pass  # vectorlite not installed


async def _ensure_init() -> None:
    """Lazy async initialization — delegates schema to memory_store.

    Sprint 5 Phase 2: schema moved to services/memory_store.py.
    Keeps FTS5 integrity check here (bot_memory-specific concern).
    """
    await _pool.set_post_connect(_load_vectorlite_extension)
    await _memory_ensure_init()

    # FTS5 integrity check (bot_memory-specific)
    async with _pool.acquire() as db:
        try:
            await db.execute("INSERT INTO memories_fts(memories_fts) VALUES('integrity-check')")
            await db.commit()
        except sqlite3.OperationalError:
            logger.warning("[BotMemory] FTS5 integrity check failed at startup. Rebuilding.")
            await _rebuild_fts(db)

        # Embedding integrity lock — detect semantic desync
        total_row = await (await db.execute("SELECT COUNT(*) FROM memories")).fetchone()
        total = total_row[0] if total_row else 0
        with_emb_row = await (await db.execute("SELECT COUNT(*) FROM memories WHERE embedding IS NOT NULL")).fetchone()
        with_emb = with_emb_row[0] if with_emb_row else 0
        gap = total - with_emb
        if total > 0 and gap > 5:
            logger.warning(
                "[BotMemory] Embedding gap detected: %d/%d memories missing embeddings. "
                "Run: python scripts/memory_backfill.py",
                gap,
                total,
            )
        elif gap > 0:
            logger.info("[BotMemory] Embedding gap: %d (within tolerance)", gap)
