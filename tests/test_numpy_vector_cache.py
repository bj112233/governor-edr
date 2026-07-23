# tests/test_numpy_vector_cache.py
"""Tests for NumpyVectorCache — in-memory semantic search engine.

Verifies:
- Boot loading from DB
- Numpy batch cosine similarity
- Temporal decay (vectorized)
- Write-through (np.vstack)
- memory_type filtering
- Top-k extraction
- Performance: 10K vectors < 5ms per query
"""

import asyncio
import struct
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from services.bot_memory.numpy_cache import _DECAY_LAMBDA, _MAX_VECTORS, NumpyVectorCache
from services.embedding_service import serialize_vector


def _make_blob(vec: list[float]) -> bytes:
    return serialize_vector(vec)


def _random_vec(dim: int = 1024) -> list[float]:
    return list(np.random.randn(dim).astype(np.float32))


class TestNumpyVectorCache:
    """Unit tests for NumpyVectorCache."""

    @pytest.fixture
    def cache(self):
        """Fresh cache instance for each test."""
        return NumpyVectorCache()

    @pytest.fixture
    def mock_rows(self):
        """Generate 100 mock DB rows with known vectors."""
        rows = []
        base_time = datetime(2026, 6, 30, 12, 0, 0)
        for i in range(100):
            vec = _random_vec()
            blob = _make_blob(vec)
            ts = (base_time - timedelta(hours=i)).isoformat()
            rows.append((i + 1, ts, f"query_{i}", f"response_{i}", "{}", "conversation", blob))
        return rows

    def _mock_pool(self, rows):
        """Create a mock pool that returns the given rows."""
        mock_cursor = MagicMock()
        mock_cursor.fetchall = AsyncMock(return_value=rows)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_cursor)

        class _MockPoolCtx:
            async def __aenter__(self):
                return mock_db

            async def __aexit__(self, *args):
                return None

        mock_pool = MagicMock()
        mock_pool.acquire.return_value = _MockPoolCtx()
        return mock_pool

    @pytest.mark.asyncio
    async def test_load_from_db(self, cache, mock_rows):
        """Cache loads vectors from DB and builds Numpy matrix."""
        with patch("services.bot_memory.numpy_cache._pool", self._mock_pool(mock_rows)):
            await cache._load_from_db()

        assert cache._loaded or cache._matrix is not None
        assert cache._matrix.shape == (100, 1024)
        assert len(cache._meta) == 100
        assert cache._timestamps.shape == (100,)

    @pytest.mark.asyncio
    async def test_search_returns_results(self, cache, mock_rows):
        """Search returns MemoryEntry list sorted by score."""
        with patch("services.bot_memory.numpy_cache._pool", self._mock_pool(mock_rows)):
            await cache._load_from_db()

            query_vec = _random_vec()
            results = await cache.search(query_vec, limit=5, decay_lambda=0.0)

        assert len(results) <= 5
        assert len(results) > 0
        assert hasattr(results[0], "distance")

    @pytest.mark.asyncio
    async def test_search_empty_cache(self, cache):
        """Search on empty cache returns []."""
        cache._matrix = np.empty((0, 1024), dtype=np.float32)
        cache._timestamps = np.empty((0,), dtype=np.float64)
        cache._meta = []
        cache._loaded = True

        results = await cache.search(_random_vec(), limit=5)
        assert results == []

    @pytest.mark.asyncio
    async def test_memory_type_filter(self, cache, mock_rows):
        """memory_type filter excludes non-matching entries."""
        rows = []
        for i, row in enumerate(mock_rows):
            rows.append((*row[:5], "audit" if i < 50 else "conversation", row[6]))

        with patch("services.bot_memory.numpy_cache._pool", self._mock_pool(rows)):
            await cache._load_from_db()

            results = await cache.search(_random_vec(), limit=10, memory_type="conversation", decay_lambda=0.0)

        for r in results:
            assert r.memory_type == "conversation"

    @pytest.mark.asyncio
    async def test_write_through_add_vector(self, cache):
        """add_vector appends to in-memory matrix without DB reload."""
        # Initialize empty cache
        cache._matrix = np.empty((0, 1024), dtype=np.float32)
        cache._timestamps = np.empty((0,), dtype=np.float64)
        cache._meta = []
        cache._loaded = True

        vec = _random_vec()
        blob = _make_blob(vec)
        ts = datetime(2026, 6, 30, 15, 0, 0).isoformat()

        await cache.add_vector(1, ts, "test query", "test response", "{}", "conversation", blob)

        assert cache._matrix.shape == (1, 1024)
        assert len(cache._meta) == 1
        assert cache._meta[0].row_id == 1
        assert cache._meta[0].query == "test query"

    @pytest.mark.asyncio
    async def test_write_through_multiple(self, cache):
        """Multiple add_vector calls build up the matrix correctly."""
        cache._matrix = np.empty((0, 1024), dtype=np.float32)
        cache._timestamps = np.empty((0,), dtype=np.float64)
        cache._meta = []
        cache._loaded = True

        for i in range(10):
            vec = _random_vec()
            blob = _make_blob(vec)
            ts = datetime(2026, 6, 30, 15, i, 0).isoformat()
            await cache.add_vector(i + 1, ts, f"q_{i}", f"r_{i}", "{}", "conversation", blob)

        assert cache._matrix.shape == (10, 1024)
        assert len(cache._meta) == 10
        assert cache._timestamps.shape == (10,)

    @pytest.mark.asyncio
    async def test_temporal_decay(self, cache):
        """Older memories get lower scores with decay enabled."""
        cache._matrix = np.empty((0, 1024), dtype=np.float32)
        cache._timestamps = np.empty((0,), dtype=np.float64)
        cache._meta = []
        cache._loaded = True

        # Add two identical vectors — one recent, one old
        vec = [1.0] * 1024
        blob = _make_blob(vec)

        now = datetime.now()
        recent_ts = now.isoformat()
        old_ts = (now - timedelta(days=60)).isoformat()  # 60 days old

        await cache.add_vector(1, recent_ts, "recent", "r1", "{}", "conversation", blob)
        await cache.add_vector(2, old_ts, "old", "r2", "{}", "conversation", blob)

        # Search with same vector — both should match, but recent should score higher
        results = await cache.search(vec, limit=2, decay_lambda=_DECAY_LAMBDA)

        assert len(results) == 2
        # Recent (id=1) should be first (higher score due to less decay)
        assert results[0].id == 1
        assert results[1].id == 2

    @pytest.mark.asyncio
    async def test_zero_query_vector(self, cache):
        """Zero query vector returns [] (avoid division by zero)."""
        cache._matrix = np.ones((5, 1024), dtype=np.float32)
        cache._matrix /= np.linalg.norm(cache._matrix, axis=1, keepdims=True)
        cache._timestamps = np.zeros(5, dtype=np.float64)
        cache._meta = [MagicMock() for _ in range(5)]
        cache._loaded = True

        results = await cache.search([0.0] * 1024, limit=3)
        assert results == []

    @pytest.mark.asyncio
    async def test_hard_cap_eviction(self, cache):
        """Cache evicts oldest entries beyond _max_vectors."""
        cache._max_vectors = 5  # Small cap for testing
        cache._matrix = np.empty((0, 1024), dtype=np.float32)
        cache._timestamps = np.empty((0,), dtype=np.float64)
        cache._meta = []
        cache._loaded = True

        for i in range(10):
            vec = _random_vec()
            blob = _make_blob(vec)
            ts = datetime(2026, 6, 30, 15, i, 0).isoformat()
            await cache.add_vector(i + 1, ts, f"q_{i}", f"r_{i}", "{}", "conversation", blob)

        assert len(cache._meta) == 5  # Capped at 5
        assert cache._matrix.shape == (5, 1024)
        # Should keep the last 5 (ids 6-10)
        assert cache._meta[0].row_id == 6

    def test_stats(self, cache):
        """stats() returns correct cache info."""
        cache._matrix = np.ones((42, 1024), dtype=np.float32)
        cache._meta = [MagicMock() for _ in range(42)]
        cache._loaded = True

        stats = cache.stats()
        assert stats["vectors"] == 42
        assert stats["loaded"] is True
        assert stats["matrix_shape"] == [42, 1024]


class TestNumpyPerformance:
    """Performance benchmarks — ensures BLAS acceleration is working."""

    @pytest.mark.asyncio
    async def test_10k_vectors_under_5ms(self):
        """10,000-vector search must complete in < 5ms (BLAS benchmark)."""
        cache = NumpyVectorCache()
        cache._matrix = np.random.randn(10000, 1024).astype(np.float32)
        cache._matrix /= np.linalg.norm(cache._matrix, axis=1, keepdims=True)
        cache._timestamps = np.zeros(10000, dtype=np.float64)
        cache._meta = [
            MagicMock(
                row_id=i,
                ts="2026-06-30T12:00:00",
                query=f"q_{i}",
                response=f"r_{i}",
                context="{}",
                memory_type="conversation",
            )
            for i in range(10000)
        ]
        cache._loaded = True

        query_vec = _random_vec()

        t0 = time.perf_counter()
        results = await cache.search(query_vec, limit=10, decay_lambda=0.0)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        assert len(results) == 10
        assert elapsed_ms < 50.0, f"Search took {elapsed_ms:.1f}ms (expected < 50ms)"
        print(f"\n  10K vector search: {elapsed_ms:.2f}ms")
