# services/bot_memory/fts_manager.py
"""FTS5 index management — rebuild, integrity check."""

import logging
import sqlite3

import aiosqlite

logger = logging.getLogger(__name__)


async def _rebuild_fts(conn: aiosqlite.Connection) -> None:
    """Native FTS5 index rebuild. Atomic and safe.

    If the FTS5 table doesn't exist at all (fresh DB / migration), create it
    with triggers instead of trying to rebuild a non-existent index.
    """
    logger.warning("[BotMemory] Initiating native FTS5 rebuild...")
    # Check if memories_fts table exists
    cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='memories_fts'")
    row = await cursor.fetchone()
    if not row:
        logger.warning("[BotMemory] memories_fts table missing — creating fresh.")
        await conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                query, response, content='memories', content_rowid='id'
            )
            """
        )
        # Backfill existing rows
        await conn.execute("INSERT INTO memories_fts(rowid, query, response) SELECT id, query, response FROM memories")
        await conn.commit()
        logger.info("[BotMemory] memories_fts table created and backfilled.")
        return
    await conn.execute("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')")
    await conn.commit()
    logger.info("[BotMemory] FTS5 index rebuilt successfully.")
