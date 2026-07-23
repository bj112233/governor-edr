# services/bot_memory/highlevel.py
"""High-level public API — store_conversation, recall_context, inject_audit_event."""

import json
import logging
from typing import Optional

from .crud import get_episodic_store, get_memory_service
from .models import (
    EventQuery,
    MemoryEntry,
    MemoryQuery,
    _is_nonpersistable_response,
)
from .vector_manager import (
    _VECTORLITE_AVAILABLE,
    _incremental_cluster,
    _vectorlite_upsert_memory,
)

logger = logging.getLogger(__name__)


async def store_conversation(query: str, response: str, metadata: dict | None = None) -> int:
    """High-level: שמור שיחה."""
    from services.thinking_parser import strip_thinking_content

    svc = get_memory_service()
    clean_response = strip_thinking_content(response)
    if _is_nonpersistable_response(clean_response):
        logger.debug("[Memory] Skipped non-persistable response (error/empty).")
        return -1
    entry = MemoryEntry(
        query=query,
        response=clean_response,
        context=json.dumps(metadata) if metadata else "",
        memory_type="conversation",
    )
    return await svc.store(entry)


async def async_store_conversation(query: str, response: str, metadata: dict | None = None) -> int:
    """High-level async: שמור שיחה עם embedding לחיפוש סמנטי עתידי."""
    from services.embedding_service import get_embedding_service, serialize_vector
    from services.thinking_parser import strip_thinking_content

    svc = get_memory_service()
    clean_response = strip_thinking_content(response)
    if _is_nonpersistable_response(clean_response):
        logger.debug("[Memory] Skipped non-persistable response (error/empty).")
        return -1

    text_for_embedding = f"{query}\n{clean_response}"
    embedding_blob: bytes | None = None
    try:
        emb_svc = get_embedding_service()
        vectors = await emb_svc.embed(["passage: " + text_for_embedding])
        embedding_blob = serialize_vector(vectors[0])
    except Exception as exc:
        logger.debug("[Memory] Embedding store skipped: %s", exc)

    entry = MemoryEntry(
        query=query,
        response=clean_response,
        context=json.dumps(metadata) if metadata else "",
        memory_type="conversation",
        embedding=embedding_blob,
    )
    row_id = await svc.store(entry)

    # Write-through to Numpy in-memory cache (replaces vectorlite upsert)
    if embedding_blob and row_id:
        try:
            from .numpy_cache import get_numpy_cache

            cache = await get_numpy_cache()
            await cache.add_vector(
                row_id=row_id,
                ts=entry.ts,
                query=entry.query,
                response=entry.response,
                context=entry.context or "",
                memory_type=entry.memory_type,
                embedding_blob=embedding_blob,
            )
        except Exception as exc:
            logger.debug("[Memory] Numpy cache write-through failed: %s", exc)

    # Legacy: vectorlite upsert if available (kept for backward compat)
    if embedding_blob and row_id and _VECTORLITE_AVAILABLE:
        try:
            await _vectorlite_upsert_memory(row_id, embedding_blob)
            await _incremental_cluster(row_id, embedding_blob)
        except Exception as exc:
            logger.debug("[Memory] vectorlite upsert/cluster failed: %s", exc)

    return row_id


async def inject_audit_event(user_id: int, event_text: str) -> None:
    """Inject deterministic FSM outcome into agent memory so ReAct can recall it."""
    svc = get_memory_service()
    entry = MemoryEntry(
        query=f"[FSM AUDIT] user_id={user_id}",
        response=event_text,
        memory_type="audit",
        context='{"source": "fsm"}',
    )
    await svc.store(entry)
    logger.info("[MEMORY] FSM audit injected for user %s", user_id)


async def recall_context(query: str, limit: int = 3) -> str:
    """High-level async: שלוף הקשר רלוונטי (semantic search when available).

    Production path: Numpy in-memory vector search × temporal decay (half-life ≈ 29 days).
    Fail-safe fallback chain:
      1. search_with_decay  (Numpy BLAS cosine + exp(-λ·age) re-rank)
      2. async_search        (Numpy cosine, no decay)
      3. search              (FTS5 keyword, no decay)
    Each tier activates only if the previous returned [] or raised.
    """
    svc = get_memory_service()
    mq = MemoryQuery(query=query, limit=limit, memory_type="conversation")

    # Tier 1: Vector search + Time Decay (the canonical production path)
    try:
        entries = await svc.search_with_decay(mq)
        if entries:
            return svc.format_for_context(entries)
        logger.debug("[Memory] search_with_decay returned empty, falling back to async_search")
    except Exception as exc:
        logger.warning("[Memory] search_with_decay failed, falling back: %s", exc)

    # Tier 2: Pure-Python cosine (vectorlite unavailable / HNSW init failed)
    try:
        entries = await svc.async_search(mq)
        if entries:
            return svc.format_for_context(entries)
        logger.debug("[Memory] async_search returned empty, falling back to FTS5 search")
    except Exception as exc:
        logger.debug("[Memory] async_search failed, falling back to search: %s", exc)

    # Tier 3: FTS5 keyword fallback (last resort, no semantic awareness)
    entries = await svc.search(mq)
    return svc.format_for_context(entries)


async def inject_event(
    event_type: str,
    description: str,
    *,
    severity: int = 1,
    source: str = "highlevel",
    session_id: str = "",
    chain_id: str = "",
    metadata: dict | None = None,
) -> int:
    """Store an episodic event. High-level API for skills, monitors, executor."""
    from .models import MemoryEvent

    svc = get_memory_service()
    event = MemoryEvent(
        event_type=event_type,
        description=description,
        severity=severity,
        source=source,
        session_id=session_id,
        chain_id=chain_id,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    return await svc.store_event(event)


async def recall_episodes(
    chain_id: str | None = None,
    event_type: str | None = None,
    source: str | None = None,
    limit: int = 20,
    since_hours: int | None = None,
) -> str:
    """Retrieve episodic events formatted for injection into system prompt."""
    store = get_episodic_store()
    eq = EventQuery(
        chain_id=chain_id,
        event_type=event_type,
        source=source,
        limit=limit,
        since_hours=since_hours,
    )
    events = await store.query(eq)
    if not events:
        return ""
    lines = ["\n[Episodic context — recent events:]"]
    for ev in events:
        lines.append(f"- [{ev.ts}] {ev.event_type} ({ev.source}, sev={ev.severity}): {ev.description[:120]}")
    return "\n".join(lines)


async def purge_old_episodes(days: int = 7) -> int:
    """Purge old episodic events. Call from daily maintenance job."""
    return await get_episodic_store().purge_old(days)
