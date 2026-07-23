"""Semantic search over conversations — vectorlite HNSW + brute-force fallback.

Extracted from memory_db.py (SRP). Provides search_conversations() used
by the LLM tool ``search_past_conversations``.
"""

import logging
from typing import Optional

from services.db_pool import get_pool
from services.embedding_service import (
    cosine_similarity,
    deserialize_vector,
    get_embedding_service,
    serialize_vector,
)
from services.memory_db import (
    _VECTORLITE_AVAILABLE,
    _VECTORLITE_INIT_DONE,
    _ensure_init,
    _ensure_vectorlite,
    _fmt_ts,
)
from services.memory_store import get_memory_pool

logger = logging.getLogger(__name__)


async def _vectorlite_search(query: str, limit: int) -> str | None:
    """HNSW vector search via vectorlite. Returns formatted string or None."""
    if not _VECTORLITE_AVAILABLE or not _VECTORLITE_INIT_DONE:
        return None
    try:
        svc = get_embedding_service()
        query_vec = (await svc.embed(["query: " + query]))[0]
        query_blob = serialize_vector(query_vec)

        async with get_memory_pool().acquire() as db:
            await _ensure_vectorlite(db)
            try:
                await db.execute("SELECT vectorlite_config('ef_search', 64)")
            except Exception:
                pass
            cursor = await db.execute(
                """
                SELECT c.id, c.timestamp, c.role, c.content, v.distance
                FROM vec_conversations v
                JOIN conversations c ON c.id = v.rowid
                WHERE v.embedding MATCH ?
                ORDER BY v.distance
                LIMIT ?
                """,
                (query_blob, limit),
            )
            rows = await cursor.fetchall()

        if not rows:
            return None

        lines = [f"**🔍 תוצאות ({len(rows)}):**"]
        for row_id, ts, role, content, dist in rows:
            lines.append(f"[{_fmt_ts(ts)}] {role}: {content[:300]}")
        return "\n".join(lines)
    except Exception as exc:
        logger.debug("[MemoryDB] vectorlite search failed: %s", exc)
        return None


def _format_results(entries: list[tuple]) -> str:
    """Format (ts, role, content) entries as search result string."""
    entries.sort(key=lambda x: x[0])
    return "\n".join(f"[{_fmt_ts(ts)}] {role}: {content[:300]}" for ts, role, content in entries)


def _rank_by_embedding(query_vec, rows: list, limit: int) -> str | None:
    """Brute-force cosine similarity ranking. Returns formatted string or None."""
    scored: list[tuple] = []
    unembedded: list[tuple] = []

    for row_id, ts, role, content, blob in rows:
        if blob:
            try:
                mem_vec = deserialize_vector(blob)
                sim = cosine_similarity(query_vec, mem_vec)
                scored.append((sim, ts, role, content))
            except Exception:
                unembedded.append((ts, role, content))
        else:
            unembedded.append((ts, role, content))

    if scored:
        scored.sort(key=lambda x: x[0], reverse=True)
        top = [(ts, role, content) for _, ts, role, content in scored[:limit]]
        return _format_results(top)

    return None  # no scored results — caller falls back to timestamp order


def _timestamp_fallback(rows: list, limit: int) -> str:
    """Timestamp-order fallback when no embeddings available."""
    fallback = [(r[1], r[2], r[3]) for r in rows[:limit]]
    return _format_results(fallback)


async def search_conversations(query: str, days_back: int = 7, limit: int = 5) -> str:
    """Semantic search over the conversations table.

    1. Try vectorlite HNSW index first (O(log n)).
    2. Fallback to brute-force cosine similarity over recent rows.
    3. Final fallback to timestamp order if no embeddings available.

    Returns formatted string: [YYYY-MM-DD HH:MM] role: content
    """
    await _ensure_init()

    if _VECTORLITE_AVAILABLE:
        try:
            vec_result = await _vectorlite_search(query, limit)
            if vec_result:
                return vec_result
        except Exception:
            pass

    try:
        async with get_memory_pool().acquire() as db:
            async with db.execute(
                """
                SELECT id, timestamp, role, content, embedding
                FROM conversations
                WHERE timestamp >= datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (f"-{days_back}", limit * 4),
            ) as cursor:
                rows = await cursor.fetchall()
    except Exception as exc:
        logger.warning("[MemoryDB] search_conversations DB read failed: %s", exc)
        return "❌ שגיאה בגישה לזיכרון."

    if not rows:
        return f"אין שיחות שמורות מהיום האחרון עד {days_back} ימים."

    try:
        svc = get_embedding_service()
        query_vectors = await svc.embed(["query: " + query])
        query_vec = query_vectors[0]
        result = _rank_by_embedding(query_vec, rows, limit)
        return result if result is not None else _timestamp_fallback(rows, limit)
    except Exception as exc:
        logger.debug("[MemoryDB] semantic ranking failed, using timestamp order: %s", exc)
        return _timestamp_fallback(rows, limit)
