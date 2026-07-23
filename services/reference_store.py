# services/reference_store.py
"""Reference DB — cold storage for static / rarely-changing tables.

Tables:
  - osint_intel: OSINT findings with E5 embeddings (written per-scan, read by recall)
  - skill_state: skill execution state (key-value JSON, read+write per skill run)
  - pairing_codes: Telegram pairing codes (legacy, near-static)

Sprint 5 Phase 3: Extracted from alert_history.db to isolate static data
from alert write traffic. Uses memory-mapped I/O for read-heavy access.
"""

import json
import logging
from typing import Any

import aiosqlite

from services.db_pool import DB_DIR, get_pool
from services.embedding_service import (
    cosine_similarity,
    deserialize_vector,
    embed_texts,
    serialize_vector,
)

logger = logging.getLogger(__name__)

_DB_PATH = str(DB_DIR / "reference.db")
_pool = get_pool(_DB_PATH, max_connections=2)
_SIMILARITY_THRESHOLD = 0.65

_initialized = False


async def _ensure_init() -> None:
    """Create tables + indexes if not exist. Called once at startup."""
    global _initialized
    if _initialized:
        return
    async with _pool.acquire() as db:
        await db.execute("PRAGMA mmap_size=268435456")  # 256MB memory-mapped
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS osint_intel (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                topic           TEXT NOT NULL,
                raw_data        TEXT NOT NULL,
                extracted_iocs_json TEXT NOT NULL,
                embedding_blob  BLOB NOT NULL,
                timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_osint_topic ON osint_intel(topic)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS skill_state (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS pairing_codes (
                code       TEXT PRIMARY KEY,
                user_id    TEXT    NOT NULL,
                user_name  TEXT    NOT NULL,
                created_at TEXT    NOT NULL,
                approved   INTEGER NOT NULL DEFAULT 0,
                expiry_min INTEGER NOT NULL DEFAULT 60
            )
            """
        )
        await db.commit()
    _initialized = True
    logger.info("[ReferenceDB] osint_intel + skill_state + pairing_codes ready (reference.db)")


# ── OSINT Intel ──────────────────────────────────────────────────


async def store_intel(topic: str, raw_data: str, iocs_dict: dict[str, list[str]]) -> None:
    """Embed raw_data and persist to SQLite with extracted IOCs."""
    await _ensure_init()
    vectors = await embed_texts([raw_data])
    embedding_blob = serialize_vector(vectors[0])
    async with _pool.acquire() as db:
        await db.execute(
            """
            INSERT INTO osint_intel (topic, raw_data, extracted_iocs_json, embedding_blob)
            VALUES (?, ?, ?, ?)
            """,
            (topic, raw_data, json.dumps(iocs_dict, ensure_ascii=False), embedding_blob),
        )
        await db.commit()
    logger.info("[ReferenceDB] Stored intel for topic='%s'", topic)


async def search_intel(query: str, limit: int = 3) -> list[dict[str, Any]]:
    """Embed query and return top-k similar findings by cosine similarity."""
    await _ensure_init()
    query_vectors = await embed_texts([query])
    query_vec = query_vectors[0]
    scored: list[tuple[float, dict[str, Any]]] = []
    async with _pool.acquire() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT id, topic, raw_data, extracted_iocs_json, embedding_blob, timestamp "
            "FROM osint_intel ORDER BY timestamp DESC LIMIT 500"
        ) as cursor:
            async for row in cursor:
                vec = deserialize_vector(row["embedding_blob"])
                sim = cosine_similarity(query_vec, vec)
                if sim >= _SIMILARITY_THRESHOLD:
                    scored.append(
                        (
                            sim,
                            {
                                "id": row["id"],
                                "topic": row["topic"],
                                "raw_data": row["raw_data"],
                                "extracted_iocs": json.loads(row["extracted_iocs_json"]),
                                "similarity": round(sim, 4),
                                "timestamp": row["timestamp"],
                            },
                        )
                    )
    scored.sort(key=lambda x: x[0], reverse=True)
    top = scored[:limit]
    logger.info(
        "[ReferenceDB] Query='%s...' top sim=%.3f | returned %d/%d above threshold",
        query[:40],
        top[0][0] if top else 0.0,
        len(top),
        len(scored),
    )
    return [item[1] for item in top]


# ── Skill State ──────────────────────────────────────────────────


async def get_skill_state(key: str) -> dict[str, Any]:
    """Return parsed JSON state for a skill key, or empty dict."""
    await _ensure_init()
    async with _pool.acquire() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT value FROM skill_state WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return {}
    try:
        return json.loads(row["value"])
    except json.JSONDecodeError:
        return {}


async def save_skill_state(key: str, data: dict[str, Any]) -> None:
    """Upsert skill state as JSON."""
    await _ensure_init()
    async with _pool.acquire() as db:
        await db.execute(
            "INSERT OR REPLACE INTO skill_state (key, value) VALUES (?, ?)",
            (key, json.dumps(data, ensure_ascii=False)),
        )
        await db.commit()


# ── Migration ────────────────────────────────────────────────────


async def migrate_from_alert_history(source_path: str | None = None) -> int:
    """One-time migration: copy static tables from alert_history.db to reference.db.

    Uses ATTACH DATABASE for atomic cross-DB copy.
    Returns total rows migrated.
    """
    await _ensure_init()
    source = source_path or str(DB_DIR / "alert_history.db")
    import os

    if not os.path.exists(source):
        logger.info("[ReferenceDB] No source DB to migrate from, skipping.")
        return 0

    total = 0
    async with _pool.acquire() as db:
        await db.execute(f"ATTACH DATABASE '{source}' AS source")

        # Check which tables exist in source
        async with db.execute("SELECT name FROM source.sqlite_master WHERE type='table'") as cursor:
            tables = [r[0] async for r in cursor]

        for table in ("osint_intel", "skill_state", "pairing_codes"):
            if table not in tables:
                continue
            async with db.execute(f"SELECT COUNT(*) FROM source.{table}") as cursor:
                row = await cursor.fetchone()
            n = row[0] if row else 0
            if n == 0:
                continue
            await db.execute(f"INSERT OR IGNORE INTO {table} SELECT * FROM source.{table}")
            await db.commit()
            total += n
            logger.info("[ReferenceDB] Migrated %d rows from source.%s", n, table)

        await db.execute("DETACH DATABASE source")
        await db.commit()

    if total > 0:
        logger.info("[ReferenceDB] Migration complete: %d total rows", total)
    return total
