"""Tests for IOC memory store — temporal correlation with decay."""

import asyncio
import time

import aiosqlite
import pytest

from services.ioc_memory_store import (
    _DB_PATH,
    prune_old_entries,
    recall_decayed_score,
    recall_history,
    save_score,
)


class TestIOCMemoryStore:
    @pytest.mark.asyncio
    async def test_save_and_recall(self):
        await save_score("10.0.0.1", "ip", 40, "test")
        events = await recall_history("10.0.0.1", "ip")
        assert len(events) >= 1
        assert events[0]["score"] == 40

    @pytest.mark.asyncio
    async def test_decayed_fresh_score(self):
        """Fresh score should retain most of its value."""
        await save_score("10.0.0.2", "ip", 50, "test_fresh")
        decayed = await recall_decayed_score("10.0.0.2", "ip")
        # Fresh: e^0 = 1, so ~50
        assert decayed >= 45.0

    @pytest.mark.asyncio
    async def test_decayed_old_score(self):
        """30-day-old score should decay significantly."""
        import uuid

        test_ip = f"10.{uuid.uuid4().hex[:5]}.{uuid.uuid4().hex[:3]}.{uuid.uuid4().hex[:3]}"
        old_ts = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - 30 * 86400),
        )
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute(
                "INSERT INTO ioc_score_history (ioc_value, ioc_type, score, context_source, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                (test_ip, "ip", 50, "old", old_ts),
            )
            await db.commit()

        decayed = await recall_decayed_score(test_ip, "ip")
        # 50 * e^(-30/14) ≈ 5.9
        assert 3.0 < decayed < 10.0

    @pytest.mark.asyncio
    async def test_multiple_scores_accumulate(self):
        """Multiple fresh scores should sum (with decay)."""
        await save_score("10.0.0.4", "ip", 30, "a")
        await save_score("10.0.0.4", "ip", 30, "b")
        decayed = await recall_decayed_score("10.0.0.4", "ip")
        # Two fresh scores of 30 each → ~60
        assert decayed >= 50.0

    @pytest.mark.asyncio
    async def test_no_history_returns_zero(self):
        decayed = await recall_decayed_score("999.999.999.999", "ip")
        assert decayed == 0.0

    @pytest.mark.asyncio
    async def test_prune_removes_old(self):
        old_ts = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - 200 * 86400),
        )
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute(
                "INSERT INTO ioc_score_history (ioc_value, ioc_type, score, context_source, timestamp) "
                "VALUES (?, ?, ?, ?, ?)",
                ("10.0.0.5", "ip", 99, "ancient", old_ts),
            )
            await db.commit()

        deleted = await prune_old_entries(max_days=180)
        assert deleted >= 1
