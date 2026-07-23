#!/usr/bin/env python3
"""Backfill embeddings for memories that were stored without them.

Sprint 5: 52/119 memories (id 84-119) were stored via store_conversation()
which doesn't generate embeddings. This script backfills them using
async_store_conversation's E5 embedding pipeline.

Usage:
    .venv\\Scripts\\python.exe scripts\\memory_backfill.py [--dry-run]
"""

import asyncio
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DB = ROOT / "data" / "memory.db"
BATCH_SIZE = 8  # GPU-friendly batch size


async def backfill(dry_run: bool = False) -> None:
    from services.embedding_service import embed_texts, serialize_vector

    # Find orphan memories (no embedding)
    conn = sqlite3.connect(str(DB))
    orphans = conn.execute("SELECT id, query, response FROM memories WHERE embedding IS NULL ORDER BY id").fetchall()
    conn.close()

    print(f"[Backfill] {len(orphans)} memories without embedding")
    if not orphans:
        print("[Backfill] Nothing to do.")
        return

    if dry_run:
        for mid, q, r in orphans[:10]:
            print(f"  DRY id={mid} q='{q[:50]}'")
        print(f"  ... ({len(orphans)} total)")
        return

    # Embed in batches
    texts = [f"passage: {q}\n{r}" for mid, q, r in orphans]
    total_upserted = 0

    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i : i + BATCH_SIZE]
        batch_ids = [orphans[j][0] for j in range(i, min(i + BATCH_SIZE, len(orphans)))]

        vectors = await embed_texts(batch)

        conn = sqlite3.connect(str(DB))
        conn.execute("PRAGMA busy_timeout=5000")
        for mid, vec in zip(batch_ids, vectors, strict=False):
            blob = serialize_vector(vec)
            conn.execute(
                "UPDATE memories SET embedding = ? WHERE id = ?",
                (blob, mid),
            )
        conn.commit()
        conn.close()
        total_upserted += len(batch_ids)
        print(f"  [{total_upserted}/{len(orphans)}] embedded batch {i // BATCH_SIZE + 1}")

    # Verify
    conn = sqlite3.connect(str(DB))
    with_emb = conn.execute("SELECT COUNT(*) FROM memories WHERE embedding IS NOT NULL").fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
    conn.close()

    print(f"\n[Backfill] Done: {with_emb}/{total} memories now have embeddings")
    gap = total - with_emb
    if gap > 0:
        print(f"[Backfill] WARNING: {gap} still missing embeddings")
    else:
        print("[Backfill] All memories embedded — semantic gap closed")


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    asyncio.run(backfill(dry_run=dry))
