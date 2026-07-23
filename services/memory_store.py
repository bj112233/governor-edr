"""Memory database — cognitive store for the agent FSM.

Sprint 5 Phase 2: Separates agent memory from SOC alerts (alert_history.db).
Tables:
  - conversations: per-message store for context window management
  - vec_conversations: vectorlite HNSW index for semantic search
  - memories + memories_fts: Q/A pairs with FTS5 full-text search
  - events: episodic event chains
  - user_profiles: LLM-generated user profile summaries

All connections go through db_pool.get_pool(db_type="memory").
"""

import logging
import sqlite3
from pathlib import Path

import aiosqlite

from services.db_pool import DB_DIR, get_db_path, get_pool

logger = logging.getLogger(__name__)

_MEMORY_DB_PATH = get_db_path("memory")

_init_done: bool = False


def get_memory_pool():
    """Return the DBPool instance for memory.db."""
    return get_pool(db_type="memory", max_connections=4)


async def _ensure_init() -> None:
    """Create all memory tables if not exists. Idempotent."""
    global _init_done
    if _init_done:
        return
    async with get_memory_pool().acquire() as db:
        # conversations
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS conversations (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                role      TEXT NOT NULL,
                content   TEXT NOT NULL,
                embedding BLOB
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_conv_ts ON conversations(timestamp)")

        # memories
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS memories (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                query       TEXT    NOT NULL,
                response    TEXT    NOT NULL,
                context     TEXT    DEFAULT '',
                memory_type TEXT    DEFAULT 'conversation',
                embedding   BLOB
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_memories_ts ON memories(ts)")
        for col, default in [("is_archived", 0), ("cluster_id", None)]:
            try:
                await db.execute(
                    f"ALTER TABLE memories ADD COLUMN {col} {'INTEGER DEFAULT 0' if col == 'is_archived' else 'TEXT'}"
                )
            except sqlite3.OperationalError as e:
                if "duplicate column name" not in str(e).lower():
                    raise
        await db.execute("CREATE INDEX IF NOT EXISTS idx_memories_cluster ON memories(cluster_id, ts)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_memories_archived ON memories(is_archived, ts)")

        # memories_fts (FTS5 external content table)
        await db.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                query, response, content='memories', content_rowid='id'
            )
            """
        )
        await db.execute(
            """
            CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memories_fts(rowid, query, response)
                VALUES (new.id, new.query, new.response);
            END
            """
        )
        await db.execute(
            """
            CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, query, response)
                VALUES ('delete', old.id, old.query, old.response);
            END
            """
        )
        await db.execute(
            """
            CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memories_fts(memories_fts, rowid, query, response)
                VALUES ('delete', old.id, old.query, old.response);
                INSERT INTO memories_fts(rowid, query, response)
                VALUES (new.id, new.query, new.response);
            END
            """
        )

        # events (episodic memory)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts            DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type    TEXT    NOT NULL,
                description   TEXT    NOT NULL,
                severity      INTEGER DEFAULT 1,
                source        TEXT    NOT NULL,
                session_id    TEXT,
                chain_id      TEXT,
                metadata_json TEXT    DEFAULT '{}'
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_escalation ON events(source, event_type, severity, ts)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_events_chain ON events(chain_id)")

        # user_profiles
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS user_profiles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          DATETIME DEFAULT CURRENT_TIMESTAMP,
                profile_json TEXT NOT NULL
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_user_profiles_ts ON user_profiles(ts)")

        # threat_hunts (proactive hunting history — dedup + audit trail)
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS threat_hunts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP,
                prompt_hash   TEXT    NOT NULL,
                threat_score  REAL    NOT NULL,
                summary       TEXT    NOT NULL,
                dispatched    INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_threat_hunts_ts ON threat_hunts(timestamp)")

        # schema_meta — schema version tracking for future migrations
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        # Initialize version if not set
        await db.execute("INSERT OR IGNORE INTO schema_meta (key, value) VALUES ('version', '1')")

        await db.commit()
    _init_done = True
    logger.info(
        "[MemoryStore] conversations + memories + events + user_profiles + threat_hunts + schema_meta ready (WAL)"
    )


async def migrate_from_alert_history(source_path: str | None = None) -> int:
    """One-time migration: copy memory tables from alert_history.db to memory.db.

    Uses ATTACH DATABASE for atomic cross-DB copy. Safe to run multiple times
    (INSERT OR IGNORE). Returns total rows migrated.
    """
    if source_path is None:
        source_path = str(DB_DIR / "alerts.db")

    # ── Path sanitization (SQL injection defense) ──
    # SQLite ATTACH DATABASE does not support parameterized queries for the
    # file path — it requires string interpolation. We sanitize by:
    # 1. Resolving to absolute path (no traversal, no relative tricks)
    # 2. Verifying the file exists (no phantom paths)
    # 3. Asserting the resolved path is inside DB_DIR (no escape)
    # 4. Escaping single quotes in the filename (defensive — filenames with
    #    quotes are rare but legal on Windows)
    resolved = Path(source_path).resolve()
    if not resolved.exists():
        logger.info("[MemoryStore] No source DB found, skipping migration")
        return 0
    if not str(resolved).startswith(str(DB_DIR.resolve())):
        logger.error(
            "[MemoryStore] Migration source path %s is outside DB_DIR %s — refusing (security)",
            resolved,
            DB_DIR.resolve(),
        )
        return 0
    safe_path = str(resolved).replace("'", "''")

    await _ensure_init()
    total = 0
    async with get_memory_pool().acquire() as db:
        await db.execute(f"ATTACH DATABASE '{safe_path}' AS source")

        # Check which source tables exist
        cursor = await db.execute(
            "SELECT name FROM source.sqlite_master WHERE type='table' "
            "AND name IN ('conversations','memories','events','user_profiles')"
        )
        existing = {row[0] for row in await cursor.fetchall()}
        if not existing:
            await db.execute("DETACH DATABASE source")
            logger.info("[MemoryStore] No memory tables in source, already migrated")
            return 0

        if "conversations" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO conversations (timestamp, role, content, embedding) "
                "SELECT timestamp, role, content, embedding FROM source.conversations"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        if "memories" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO memories (ts, query, response, context, memory_type, embedding, is_archived, cluster_id) "
                "SELECT ts, query, response, context, memory_type, embedding, is_archived, cluster_id FROM source.memories"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        if "events" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO events (ts, event_type, description, severity, source, session_id, chain_id, metadata_json) "
                "SELECT ts, event_type, description, severity, source, session_id, chain_id, metadata_json FROM source.events"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        if "user_profiles" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO user_profiles (ts, profile_json) "
                "SELECT ts, profile_json FROM source.user_profiles"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        await db.commit()
        await db.execute("DETACH DATABASE source")

    if total > 0:
        logger.info("[MemoryStore] Migrated %d rows from %s", total, source_path)

        # Drop old tables from source + vacuum (offloaded to thread — VACUUM blocks)
        try:
            import asyncio

            def _cleanup_source():
                conn = sqlite3.connect(source_path, timeout=30.0)
                conn.execute("PRAGMA busy_timeout=10000")
                for table in ("conversations", "memories", "memories_fts", "events", "user_profiles"):
                    conn.execute(f"DROP TABLE IF EXISTS {table}")
                conn.execute("VACUUM")
                conn.close()

            await asyncio.to_thread(_cleanup_source)
            logger.info("[MemoryStore] Dropped old memory tables + vacuumed source")
        except Exception as exc:
            logger.warning("[MemoryStore] Source cleanup failed: %s", exc)

    return total
