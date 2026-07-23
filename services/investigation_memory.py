# services/investigation_memory.py
"""Investigation Memory — persists ReAct loop steps to reference.db.

Tables:
  - investigation_history: per-step log of queries, actions, observations

Enables:
  1. Loop prevention: detect repeated queries within a single hunt
  2. Cross-run memory: inject prior findings into new investigations
  3. Investigation summary: condensed history for LLM context injection
"""

import hashlib
import json
import logging
from typing import Any

import aiosqlite

from services.db_pool import DB_DIR, get_pool
from services.embedding_service import cosine_similarity, deserialize_vector, embed_texts, serialize_vector

logger = logging.getLogger(__name__)

_DB_PATH = str(DB_DIR / "reference.db")
_pool = get_pool(_DB_PATH, max_connections=2)
_SIMILARITY_THRESHOLD = 0.60
_initialized = False


async def _ensure_init() -> None:
    """Create investigation_history table if not exist. Idempotent."""
    global _initialized
    if _initialized:
        return
    async with _pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_history (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                topic        TEXT NOT NULL,
                query_hash   TEXT NOT NULL,
                query_text   TEXT NOT NULL,
                action       TEXT NOT NULL,
                observation  TEXT,
                iocs_found   TEXT,
                timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_inv_topic ON investigation_history(topic)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_inv_hash ON investigation_history(query_hash)")
        await db.commit()
    _initialized = True
    logger.info("[InvestigationMemory] investigation_history table ready")


def _hash_query(query: str) -> str:
    """SHA256 hash of a normalized query string for dedup."""
    normalized = " ".join(query.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


async def save_step(
    topic: str,
    query: str,
    action: str,
    observation: str,
    iocs_found: list[str] | None = None,
) -> None:
    """Persist a single ReAct step to investigation_history."""
    await _ensure_init()
    qhash = _hash_query(query)
    obs_truncated = observation[:500] if observation else ""
    iocs_json = json.dumps(iocs_found or [], ensure_ascii=False)
    async with _pool.acquire() as db:
        await db.execute(
            """
            INSERT INTO investigation_history (topic, query_hash, query_text, action, observation, iocs_found)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (topic, qhash, query, action, obs_truncated, iocs_json),
        )
        await db.commit()


async def get_visited_queries(topic: str) -> set[str]:
    """Return set of query hashes already executed for this topic."""
    await _ensure_init()
    visited: set[str] = set()
    async with _pool.acquire() as db:
        async with db.execute(
            "SELECT DISTINCT query_hash FROM investigation_history WHERE topic = ?",
            (topic,),
        ) as cursor:
            async for row in cursor:
                visited.add(row[0])
    return visited


async def is_query_visited(topic: str, query: str) -> bool:
    """Check if a specific query has already been executed for this topic."""
    qhash = _hash_query(query)
    visited = await get_visited_queries(topic)
    return qhash in visited


async def get_investigation_summary(topic: str, limit: int = 5) -> str:
    """Return condensed summary of prior investigation steps for this topic.

    Format: "Step N: {action} '{query}' → {observation[:100]}"
    Returns empty string if no prior steps.
    """
    await _ensure_init()
    steps: list[str] = []
    async with _pool.acquire() as db:
        async with db.execute(
            "SELECT action, query_text, observation FROM investigation_history "
            "WHERE topic = ? ORDER BY timestamp DESC LIMIT ?",
            (topic, limit),
        ) as cursor:
            async for row in cursor:
                action, query_text, observation = row
                obs_short = (observation or "")[:100]
                steps.append(f"  - {action} '{query_text}' → {obs_short}")
    if not steps:
        return ""
    return "Prior investigation steps for this topic:\n" + "\n".join(steps)


async def get_similar_investigations(topic: str, limit: int = 3) -> list[dict[str, Any]]:
    """Find similar past investigations by cosine similarity on topic.

    Returns list of {topic, similarity, step_count, last_observation}.
    """
    await _ensure_init()
    query_vec = await embed_texts([topic])
    if not query_vec:
        return []

    # Get distinct topics with their latest embedding (reuse first step's topic)
    scored: list[tuple[float, dict[str, Any]]] = []
    async with _pool.acquire() as db:
        async with db.execute(
            "SELECT DISTINCT topic FROM investigation_history ORDER BY timestamp DESC LIMIT 200"
        ) as cursor:
            topics = [r[0] async for r in cursor]

    if not topics:
        return []

    # Embed all distinct topics and compare
    topic_vecs = await embed_texts(topics)
    if not topic_vecs:
        return []

    for t, vec in zip(topics, topic_vecs):
        if t == topic:
            continue
        sim = cosine_similarity(query_vec[0], vec)
        if sim >= _SIMILARITY_THRESHOLD:
            # Get step count + last observation for this topic
            async with _pool.acquire() as db:
                async with db.execute(
                    "SELECT COUNT(*), MAX(observation) FROM investigation_history WHERE topic = ?",
                    (t,),
                ) as cursor:
                    row = await cursor.fetchone()
            step_count = row[0] if row else 0
            last_obs = (row[1] if row and row[1] else "")[:200]
            scored.append(
                (
                    sim,
                    {
                        "topic": t,
                        "similarity": round(sim, 4),
                        "step_count": step_count,
                        "last_observation": last_obs,
                    },
                )
            )

    scored.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in scored[:limit]]
