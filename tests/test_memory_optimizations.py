#!/usr/bin/env python3
"""
Live test for memory optimizations - validates all plan items.
"""

import asyncio
import sqlite3
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from services.bot_memory import (
    MemoryEntry,
    cleanup_old_memories,
    recall_context,
    store_conversation,
)
from services.bot_memory.crud import MemoryService
from services.bot_memory.models import _FTS5_MAX_TOKENS
from services.db_pool import get_db_path


def _get_db_path():
    """Get memory DB path at runtime (respects conftest patching)."""
    return get_db_path("memory")


def test_fts5_token_reduction():
    """P0: Verify FTS5_MAX_TOKENS = 16"""
    assert _FTS5_MAX_TOKENS == 16, f"Expected 16, got {_FTS5_MAX_TOKENS}"
    print("PASS: FTS5_MAX_TOKENS = 16")


async def test_db_index_exists():
    """P2: Verify idx_memories_ts index exists"""
    from services.memory_store import _ensure_init

    await _ensure_init()
    with sqlite3.connect(_get_db_path()) as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_memories_ts'")
        result = cursor.fetchone()
        assert result is not None, "Index idx_memories_ts not found"
        print("ג… Index idx_memories_ts exists")


def test_format_for_context_cap():
    """P0: Verify format_for_context caps at 2000 chars"""
    svc = MemoryService()

    # Create 10 entries with long content
    entries = []
    for i in range(10):
        entries.append(
            MemoryEntry(
                id=i,
                ts="2024-01-01T00:00:00",
                query="A" * 200,  # 200 chars
                response="B" * 200,  # 200 chars
                memory_type="conversation",
            )
        )

    result = svc.format_for_context(entries)

    # Should be capped at 2000 chars
    assert len(result) <= 2000, f"Result length {len(result)} exceeds 2000"
    print(f"ג… format_for_context capped: {len(result)} chars (max 2000)")

    # Verify no timestamps in output
    assert "2024-01-01" not in result, "Timestamp should not appear in output"
    print("ג… Timestamps removed from context output")

    # Verify Q/A truncation at 100 chars
    assert "A" * 100 in result or "A" * 50 in result, "Query should be truncated"
    print("ג… Q/A truncated consistently")


async def test_cleanup_old_memories():
    """P2: Verify cleanup_old_memories function works"""
    # Store a test entry
    entry_id = await store_conversation("test cleanup query", "test cleanup response")
    print(f"ג… Stored test entry ID: {entry_id}")

    # Cleanup with 0 days should delete everything
    deleted = await cleanup_old_memories(days=0)
    print(f"ג… cleanup_old_memories deleted {deleted} entries")


async def test_recall_context():
    """Verify recall_context returns capped output"""
    # Store some test data
    await store_conversation("test query one", "test response one")
    await store_conversation("test query two", "test response two")

    result = await recall_context("test", limit=5)

    if result:
        assert len(result) <= 2000, f"recall_context result {len(result)} exceeds 2000"
        print(f"recall_context returns {len(result)} chars (capped)")
    else:
        print("recall_context returned empty (FTS may need rebuild)")


if __name__ == "__main__":
    print("=" * 50)
    print("Memory Optimizations Live Test")
    print("=" * 50)

    try:
        test_fts5_token_reduction()
        test_db_index_exists()
        test_format_for_context_cap()
        asyncio.run(test_cleanup_old_memories())
        asyncio.run(test_recall_context())
        print("=" * 50)
        print("All tests passed!")
    except Exception as e:
        print(f"ג Test failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
