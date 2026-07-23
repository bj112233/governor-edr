# services/night_watchman.py
"""Memory compaction (Night Watchman): compress old raw conversations into bullet-point summaries.

Runs as APScheduler cron job (04:30 daily) when system is idle.
Uses memory_type='summary' for compacted records (no schema migration).
Uses char-based chunking to prevent LLM context overflow.
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from services.bot_memory import (
    MemoryEntry,
    archive_memories_by_ids,
    fetch_old_memories_for_compaction,
)
from services.llm_bridge import LLMBridge

logger = logging.getLogger(__name__)

_MAX_CHUNK_CHARS = 4000
_SUMMARY_SYSTEM = (
    "You are a memory compression engine. "
    "Summarize the following conversations into 3-5 bullet points in Hebrew. "
    "Preserve all key facts, numbers, names, and decisions. "
    "Output ONLY bullet points, no introduction, no markdown, no JSON."
)


async def _summarize_chunk(chunk: list[MemoryEntry], engine) -> str:
    """Call LLM to compress a chunk into bullet points."""
    combined_text = "\n---\n".join(f"Q: {e.query}\nA: {e.response}" for e in chunk)

    try:
        summary = await engine.complete(
            system_prompt=_SUMMARY_SYSTEM,
            user_input=combined_text,
            temperature=0.1,
            max_tokens=512,
        )
        return summary.strip()
    except Exception as exc:
        logger.warning("[NightWatchman] Summarization failed: %s", exc)
        # Fallback: first 200 chars of each response
        return "\n".join(f"- {e.response[:200]}" for e in chunk)


async def _persist_summary(
    summary_text: str,
    original_ids: list[int],
    topic: str,
    engine,
    db=None,
) -> int:
    """Store a summary as memory_type='summary' with metadata in context.

    Args:
        db: Optional existing connection for atomic transaction. When provided,
            no commit is issued here — the caller manages the transaction.
    """
    from services.bot_memory import MemoryEntry, get_memory_service
    from services.embedding_service import get_embedding_service, serialize_vector

    ctx = {
        "source": "night_watchman",
        "original_count": len(original_ids),
        "summarized_ids": original_ids,
        "topic": topic,
        "created_at": datetime.now().isoformat(),
    }

    # Compute embedding for the summary
    embedding_blob: bytes | None = None
    try:
        svc = get_embedding_service()
        vectors = await svc.embed(["passage: " + summary_text])
        embedding_blob = serialize_vector(vectors[0])
    except Exception as exc:
        logger.debug("[NightWatchman] Embedding skipped: %s", exc)

    entry = MemoryEntry(
        query=f"[Summary] {topic}",
        response=summary_text,
        context=json.dumps(ctx, ensure_ascii=False),
        memory_type="summary",
        embedding=embedding_blob,
    )
    mem_svc = get_memory_service()
    row_id = await mem_svc.store(entry, db=db)

    # Sync to vectorlite
    if embedding_blob and row_id:
        from services.bot_memory import vector_manager

        try:
            await vector_manager._vectorlite_upsert_memory(row_id, embedding_blob, db=db)
        except Exception as exc:
            logger.debug("[NightWatchman] vectorlite upsert failed: %s", exc)

    return row_id


async def run_memory_compaction(
    days_old: int = 30,
    max_chunk_chars: int = 4000,
    dry_run: bool = False,
) -> dict:
    """Night Watchman main entry: fetch old memories, chunk, summarize, persist, archive.

    Args:
        days_old: Only compact memories older than this many days.
        max_chunk_chars: Char limit per chunk (prevents LLM context overflow).
        dry_run: If True, only log what WOULD be done without modifying DB.

    Returns:
        {"chunks_processed": int, "summaries_created": int, "rows_archived": int}
    """
    try:
        bridge = LLMBridge.get_instance()
        if not bridge.should_accept_traffic():
            logger.warning("[NightWatchman] LLM circuit open, skipping compaction.")
            return {"chunks_processed": 0, "summaries_created": 0, "rows_archived": 0}
    except Exception:
        logger.warning("[NightWatchman] Could not check LLM readiness, skipping.")
        return {"chunks_processed": 0, "summaries_created": 0, "rows_archived": 0}

    # Step 1: Fetch old raw conversations (grouped by topic, chunked by chars)
    chunks = await fetch_old_memories_for_compaction(days_old, max_chunk_chars)
    if not chunks:
        logger.info("[NightWatchman] No old memories to compact.")
        return {"chunks_processed": 0, "summaries_created": 0, "rows_archived": 0}

    engine = LLMBridge.get_instance()
    summaries_created = 0
    rows_archived = 0

    for i, chunk in enumerate(chunks, 1):
        logger.info(
            "[NightWatchman] Processing chunk %d/%d (%d entries)",
            i,
            len(chunks),
            len(chunk),
        )

        # Step 2: Summarize
        summary_text = await _summarize_chunk(chunk, engine)

        # Step 3: Extract topic from first entry
        topic = "general"
        if chunk:
            try:
                ctx = json.loads(chunk[0].context or "{}")
                topic = ctx.get("topic", "general")
            except Exception:
                pass

        original_ids = [e.id for e in chunk if e.id is not None]

        if dry_run:
            logger.info(
                "[NightWatchman] DRY RUN: Would create summary for IDs %s",
                original_ids,
            )
            continue

        # Step 4+5: Atomic persist summary + archive originals.
        # Wrapped in BEGIN IMMEDIATE to prevent partial states:
        #   - summary saved but originals not archived → duplicate compaction
        #   - originals archived but no summary → silent data loss
        from services.bot_memory.schema import _pool as _mem_pool

        async with _mem_pool.acquire() as db:
            try:
                await db.execute("BEGIN IMMEDIATE")
                summary_id = await _persist_summary(summary_text, original_ids, topic, engine, db=db)
                if summary_id:
                    summaries_created += 1
                archived = await archive_memories_by_ids(original_ids, db=db)
                rows_archived += archived
                await db.commit()
                logger.info(
                    "[NightWatchman] Archived %d old rows, summary_id=%d",
                    archived,
                    summary_id,
                )
            except Exception:
                await db.rollback()
                logger.error(
                    "[NightWatchman] Atomic persist+archive failed for IDs %s — rolled back, originals preserved.",
                    original_ids,
                )
                raise

    logger.info(
        "[NightWatchman] Compaction complete: %d chunks -> %d summaries, %d rows archived.",
        len(chunks),
        summaries_created,
        rows_archived,
    )
    return {
        "chunks_processed": len(chunks),
        "summaries_created": summaries_created,
        "rows_archived": rows_archived,
    }


# Convenience alias for scheduler / manual invocation
compact_conversations = run_memory_compaction
