# services/error_memory.py
"""Operational error-lesson memory — isolated SQLite store with E5 embeddings.

"Muscle memory" of past errors and their resolutions. STRICTLY separated from
conversation memory (bot_memory.py / recall_context):
  - Lives in its OWN database file (error_lessons.db), not alert_history.db.
  - Retrieved under a distinct prompt namespace so it never mixes with
    user-facing conversation recall.

No external vector engine. Pure-Python cosine over SQLite BLOBs (the same
embedding_service used everywhere). At the expected scale (tens–hundreds of
critical lessons) brute-force is sub-millisecond on CPU and dependency-free.
If this ever grows to thousands of rows, migrate to sqlite-vec — never
vectorlite.
"""

import logging
from typing import Optional

import aiosqlite

from services.db_pool import DB_DIR, get_pool
from services.embedding_service import (
    cosine_similarity,
    deserialize_vector,
    embed_texts,
    serialize_vector,
)

logger = logging.getLogger(__name__)

# Dedicated DB file — full isolation from conversation memory.
_DB_PATH = str(DB_DIR / "error_lessons.db")

# Connection pool — WAL mode + busy_timeout managed centrally by db_pool.
# Without WAL, concurrent access from the agent loop causes "database is locked".
_pool = get_pool(db_path=_DB_PATH, max_connections=2)

# Near-duplicate lessons collapse into a hit_count bump instead of new rows.
_DEDUP_THRESHOLD = 0.90
# Retrieval bar — calibrated for E5, whose cosine baseline sits high (~0.71-0.76
# for unrelated text, ~0.89 for genuinely related). 0.82 cleanly separates them
# and protects the KV cache from low-signal injections.
_SEARCH_THRESHOLD = 0.82
# Brute-force scan ceiling (lessons are few; this is a safety bound).
_SCAN_LIMIT = 500


async def _ensure_table() -> None:
    async with _pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS error_lessons (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                error_signature TEXT NOT NULL,
                trigger_context TEXT NOT NULL,
                resolution      TEXT NOT NULL,
                tool_name       TEXT NOT NULL DEFAULT '',
                embedding_blob  BLOB NOT NULL,
                hit_count       INTEGER NOT NULL DEFAULT 0,
                timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_error_lessons_ts ON error_lessons(timestamp)")
        await db.commit()


def _embed_text(error_signature: str, trigger_context: str) -> str:
    """Combined text used for both storage embedding and dedup/search."""
    return f"{error_signature}\n{trigger_context}".strip()


async def store_lesson(
    error_signature: str,
    trigger_context: str,
    resolution: str,
    tool_name: str = "",
) -> None:
    """Persist a (error -> resolution) lesson, or bump hit_count on a near-duplicate.

    Non-blocking by design at the call site (fire-and-forget). Failures are
    swallowed with a debug log so the agent path is never affected.
    """
    error_signature = (error_signature or "").strip()
    resolution = (resolution or "").strip()
    if not error_signature or not resolution:
        return
    try:
        await _ensure_table()
        text = _embed_text(error_signature, trigger_context)
        new_vec = (await embed_texts(["passage: " + text]))[0]

        async with _pool.acquire() as db:
            db.row_factory = aiosqlite.Row
            # Dedup: compare against existing lessons by cosine similarity.
            async with db.execute(
                "SELECT id, embedding_blob FROM error_lessons ORDER BY timestamp DESC LIMIT ?",
                (_SCAN_LIMIT,),
            ) as cursor:
                best_id: int | None = None
                best_sim = 0.0
                async for row in cursor:
                    sim = cosine_similarity(new_vec, deserialize_vector(row["embedding_blob"]))
                    if sim > best_sim:
                        best_sim = sim
                        best_id = row["id"]

            if best_id is not None and best_sim >= _DEDUP_THRESHOLD:
                await db.execute(
                    "UPDATE error_lessons SET hit_count = hit_count + 1 WHERE id = ?",
                    (best_id,),
                )
                await db.commit()
                logger.info(
                    "[ErrorMemory] Dedup hit (sim=%.3f) — bumped lesson id=%d",
                    best_sim,
                    best_id,
                )
                return

            await db.execute(
                """
                INSERT INTO error_lessons
                    (error_signature, trigger_context, resolution, tool_name, embedding_blob)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    error_signature,
                    trigger_context,
                    resolution,
                    tool_name,
                    serialize_vector(new_vec),
                ),
            )
            await db.commit()
        logger.info("[ErrorMemory] Stored new lesson (tool=%s).", tool_name or "?")
    except Exception as exc:
        logger.debug("[ErrorMemory] store_lesson failed: %s", exc)


async def search_lessons(query: str, limit: int = 2, threshold: float = _SEARCH_THRESHOLD) -> list[dict]:
    """Return top-k lessons whose stored vector exceeds the similarity threshold."""
    query = (query or "").strip()
    if not query:
        return []
    try:
        await _ensure_table()
        query_vec = (await embed_texts(["query: " + query]))[0]
        scored: list[tuple[float, dict]] = []
        async with _pool.acquire() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT error_signature, resolution, tool_name, hit_count, "
                "embedding_blob FROM error_lessons "
                "ORDER BY timestamp DESC LIMIT ?",
                (_SCAN_LIMIT,),
            ) as cursor:
                async for row in cursor:
                    sim = cosine_similarity(query_vec, deserialize_vector(row["embedding_blob"]))
                    if sim >= threshold:
                        scored.append(
                            (
                                sim,
                                {
                                    "error_signature": row["error_signature"],
                                    "resolution": row["resolution"],
                                    "tool_name": row["tool_name"],
                                    "hit_count": row["hit_count"],
                                    "similarity": round(sim, 4),
                                },
                            )
                        )
        scored.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored[:limit]]
    except Exception as exc:
        logger.debug("[ErrorMemory] search_lessons failed: %s", exc)
        return []


def format_lessons_for_prompt(lessons: list[dict], max_resolution_chars: int = 200) -> str:
    """Render lessons into a compact prompt block (KV-cache friendly)."""
    if not lessons:
        return ""
    lines = []
    for ls in lessons:
        res = ls["resolution"]
        if len(res) > max_resolution_chars:
            res = res[:max_resolution_chars] + "…"
        lines.append(f"- When: {ls['error_signature'][:120]} → Resolution: {res}")
    return "\n".join(lines)


async def get_tool_stats() -> dict[str, dict]:
    """Aggregate failure statistics per tool_name from error_lessons.

    Returns {tool_name: {failures: int, repeat_failures: int, last_seen: str}}.
    Used by Adaptive Tool Ranking to demote tools with poor track records.
    Zero LLM cost — pure SQLite aggregate query.
    """
    try:
        await _ensure_table()
        stats: dict[str, dict] = {}
        async with _pool.acquire() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT tool_name, COUNT(*) as failures, "
                "COALESCE(SUM(hit_count), 0) as repeat_failures, "
                "MAX(timestamp) as last_seen "
                "FROM error_lessons WHERE tool_name != '' "
                "GROUP BY tool_name ORDER BY failures DESC"
            ) as cursor:
                async for row in cursor:
                    name = row["tool_name"]
                    if name:
                        stats[name] = {
                            "failures": row["failures"],
                            "repeat_failures": row["repeat_failures"],
                            "last_seen": row["last_seen"] or "",
                        }
        return stats
    except Exception as exc:
        logger.debug("[ErrorMemory] get_tool_stats failed: %s", exc)
        return {}


async def get_errors_last_7d(limit: int = 15) -> list[dict]:
    """Return deduplicated error lessons from last 7 days (for weekly reflection).

    Groups by error_signature + tool_name to avoid token bloat — if a tool
    crashed 400 times with the same signature, returns ONE row with count=400.
    Returns up to `limit` unique error patterns, sorted by frequency.
    """
    try:
        await _ensure_table()
        async with _pool.acquire() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT error_signature, tool_name, "
                "COUNT(*) as occurrences, "
                "MAX(trigger_context) as sample_context, "
                "MAX(resolution) as sample_resolution, "
                "MAX(timestamp) as last_seen "
                "FROM error_lessons WHERE timestamp >= datetime('now', '-7 days') "
                "GROUP BY error_signature, tool_name "
                "ORDER BY occurrences DESC LIMIT ?",
                (limit,),
            )
            rows = await cursor.fetchall()
            return [
                {
                    "error_signature": row["error_signature"],
                    "tool_name": row["tool_name"] or "",
                    "occurrences": row["occurrences"],
                    "sample_context": row["sample_context"] or "",
                    "sample_resolution": row["sample_resolution"] or "",
                    "last_seen": row["last_seen"] or "",
                }
                for row in rows
            ]
    except Exception as exc:
        logger.debug("[ErrorMemory] get_errors_last_7d failed: %s", exc)
        return []
