"""MemoryService search methods — FTS5 + decay-based re-ranking.

Extracted from crud.py (SRP). Search and search_with_decay are the most
complex methods, with FTS5 query escaping, LIKE fallback, and temporal
decay re-ranking logic.
"""

import logging
import re as _re
import sqlite3
from typing import Optional

from .models import _FTS5_MAX_TOKENS, MemoryEntry, MemoryQuery
from .schema import _pool

logger = logging.getLogger(__name__)


def _escape_fts5(q: str) -> str:
    """Escape query for FTS5 MATCH syntax."""
    tokens = _re.findall(r"[\w\u0590-\u05ff]+", q, flags=_re.UNICODE)
    if not tokens:
        return '"__no_match_token__"'
    tokens = tokens[-_FTS5_MAX_TOKENS:]
    return " OR ".join(f'"{t}"' for t in tokens)


async def _fallback_like_search(db, query: str, limit: int, memory_type: str | None = None) -> list:
    """LIKE-based fallback when FTS5 fails — per-token OR search."""
    tokens = _re.findall(r"[\w\u0590-\u05ff]+", query, flags=_re.UNICODE)
    if not tokens:
        return []
    # Build OR chain of LIKE conditions for each token
    token_patterns = [f"%{t}%" for t in tokens[:_FTS5_MAX_TOKENS]]
    like_clause = " OR ".join(["query LIKE ? OR response LIKE ?" for _ in token_patterns])
    params: list[str | int] = []
    for tp in token_patterns:
        params.extend([tp, tp])
    if memory_type:
        where = f"({like_clause}) AND memory_type = ? AND is_archived = 0"
        params.append(memory_type)
    else:
        where = f"({like_clause}) AND is_archived = 0"
    params.append(limit)
    cursor = await db.execute(
        f"""
        SELECT m.id, m.ts, m.query, m.response, m.context, m.memory_type
        FROM memories m
        WHERE {where}
        ORDER BY ts DESC
        LIMIT ?
        """,
        params,
    )
    return await cursor.fetchall()


def _rows_to_entries(rows) -> list[MemoryEntry]:
    """Convert DB rows to MemoryEntry objects."""
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


async def search(self, mq: MemoryQuery) -> list[MemoryEntry]:
    """חיפוש FTS5 semantic-like — מוגן מפני תווי-syntax שגויים."""
    await self._ensure_init()
    async with _pool.acquire() as db:
        try:
            fts_query = _escape_fts5(mq.query)
            _fetch_limit = mq.limit * 4
            try:
                if mq.memory_type:
                    cursor = await db.execute(
                        """
                        SELECT m.id, m.ts, m.query, m.response, m.context, m.memory_type
                        FROM memories m
                        JOIN memories_fts f ON m.id = f.rowid
                        WHERE memories_fts MATCH ? AND m.memory_type = ? AND m.is_archived = 0
                        ORDER BY rank
                        LIMIT ?
                        """,
                        (fts_query, mq.memory_type, _fetch_limit),
                    )
                else:
                    cursor = await db.execute(
                        """
                        SELECT m.id, m.ts, m.query, m.response, m.context, m.memory_type
                        FROM memories m
                        JOIN memories_fts f ON m.id = f.rowid
                        WHERE memories_fts MATCH ? AND m.is_archived = 0
                        ORDER BY rank
                        LIMIT ?
                        """,
                        (fts_query, _fetch_limit),
                    )
                rows = await cursor.fetchall()
                if rows:
                    return _rows_to_entries(rows)
            except sqlite3.OperationalError as e:
                logger.warning("FTS5 search failed, trying fallback: %s", e)

            logger.info("Using LIKE fallback search for: %s", mq.query)
            rows = await _fallback_like_search(db, mq.query, mq.limit, mq.memory_type)
            return _rows_to_entries(rows)
        except Exception as e:
            logger.exception("Memory search unexpected error: %s", e)
            return []


async def async_search(self, mq: MemoryQuery) -> list[MemoryEntry]:
    """Numpy in-memory cosine similarity search (replaces brute-force Python).

    Uses NumpyVectorCache: BLAS-accelerated matrix-vector multiply over
    up to 10,000 vectors. 0.69ms per query (benchmarked).
    Falls back to DB scan if cache unavailable.
    """
    from services.embedding_service import embed_texts

    from .numpy_cache import get_numpy_cache

    query = (mq.query or "").strip()
    if not query:
        return []
    try:
        query_vec = (await embed_texts(["query: " + query]))[0]
    except Exception as exc:
        logger.debug("[Memory] async_search embed failed: %s", exc)
        return []

    await self._ensure_init()
    cache = await get_numpy_cache()
    return await cache.search(
        query_vec=query_vec,
        limit=mq.limit,
        memory_type=mq.memory_type,
        decay_lambda=0.0,  # No decay for async_search (preserve original semantics)
    )


async def search_with_decay(self, mq: MemoryQuery, decay_lambda: float = 0.001) -> list[MemoryEntry]:
    """Numpy batch cosine × temporal decay — the production search path.

    Physics:
    - Numpy matrix-vector multiply (BLAS) computes cosine for all vectors
      in one shot. 0.69ms for 10,000 vectors.
    - final_score = semantic_score * decay_factor (both in [0,1]).
    - decay_lambda=0.001 → half-life ≈ ln(2)/0.001 = 693h ≈ 29 days.
      A 1-week-old memory loses ~15%, a 1-month-old loses ~50%.
      Deep semantic matches from months ago survive; only true Ghost
      Penalties (very old + weak match) are suppressed.
    """
    from services.embedding_service import embed_texts

    from .numpy_cache import get_numpy_cache

    query = (mq.query or "").strip()
    if not query:
        return []
    try:
        query_vec = (await embed_texts(["query: " + query]))[0]
    except Exception as exc:
        logger.debug("[Memory] search_with_decay embed failed: %s", exc)
        return []

    await self._ensure_init()
    cache = await get_numpy_cache()
    # Over-fetch 10x to avoid false negatives (same strategy as HNSW over-fetch)
    if mq.limit <= 0:
        return []
    results = await cache.search(
        query_vec=query_vec,
        limit=mq.limit * 10,
        memory_type=mq.memory_type,
        decay_lambda=decay_lambda,
    )
    return results[: mq.limit]
