# services/bot_memory/numpy_cache.py
"""In-Memory Numpy Vector Cache — replaces Vectorlite HNSW for semantic search.

Architecture: Boot-load all memory vectors into a Numpy matrix (N × 1024),
compute cosine similarity via matrix-vector multiply (BLAS-accelerated),
apply temporal decay in vectorized operations, return top-k.

Performance: 0.69ms per query for 10,000 vectors (benchmarked).
Zero C-extension dependencies — pure Python + Numpy (BLAS backend).

Write-through: new memories are np.vstack'd into the cache on store,
no full reload needed.
"""

import asyncio
import logging
import struct
import time
from dataclasses import dataclass
from datetime import datetime

import numpy as np

from config import EMBEDDING_DIM

from .models import MemoryEntry, MemoryQuery
from .schema import _pool

logger = logging.getLogger(__name__)

# ── Config ──
_MAX_VECTORS = 10000  # Hard cap (was 200 in brute-force fallback)
_DECAY_LAMBDA = 0.001  # half-life ≈ ln(2)/0.001 = 693h ≈ 29 days
_SEMANTIC_THRESHOLD = 0.65  # Same as vectorlite config


@dataclass
class _CacheEntry:
    """Metadata for each cached vector (parallel to matrix rows)."""

    row_id: int
    ts: str  # ISO timestamp
    query: str
    response: str
    context: str
    memory_type: str


class NumpyVectorCache:
    """In-memory Numpy matrix for blazing-fast semantic search.

    Thread-safe via asyncio.Lock. Single instance shared across the process.
    """

    def __init__(self) -> None:
        self._matrix: np.ndarray | None = None  # (N, DIM) float32, L2-normalized
        self._meta: list[_CacheEntry] = []
        self._timestamps: np.ndarray | None = None  # (N,) float64, epoch seconds
        self._lock = asyncio.Lock()
        self._loaded = False
        self._max_vectors = _MAX_VECTORS

    async def _ensure_loaded(self) -> None:
        """Lazy-load all vectors from SQLite on first access."""
        if self._loaded:
            return
        async with self._lock:
            if self._loaded:  # double-check after acquiring lock
                return
            await self._load_from_db()
            self._loaded = True

    async def _load_from_db(self) -> None:
        """Bulk-load all memory vectors into Numpy arrays."""
        t0 = time.perf_counter()
        async with _pool.acquire() as db:
            cursor = await db.execute(
                f"""
                SELECT id, ts, query, response, context, memory_type, embedding
                FROM memories
                WHERE embedding IS NOT NULL AND is_archived = 0
                ORDER BY id DESC
                LIMIT {self._max_vectors}
                """
            )
            rows = await cursor.fetchall()

        if not rows:
            logger.info("[NumpyCache] No vectors found in DB — cache empty")
            self._matrix = np.empty((0, EMBEDDING_DIM), dtype=np.float32)
            self._timestamps = np.empty((0,), dtype=np.float64)
            self._meta = []
            return

        vectors = []
        meta = []
        timestamps = []

        for row in rows:
            row_id, ts, query, response, context, memory_type, emb_blob = row
            try:
                vec = self._deserialize(emb_blob)
                if len(vec) != EMBEDDING_DIM:
                    continue
                vectors.append(vec)
                meta.append(_CacheEntry(row_id, ts, query, response, context, memory_type))
                # Parse ISO timestamp to epoch seconds
                try:
                    dt = datetime.fromisoformat(ts)
                    timestamps.append(dt.timestamp())
                except (ValueError, TypeError):
                    timestamps.append(0.0)
            except Exception:
                continue

        if not vectors:
            self._matrix = np.empty((0, EMBEDDING_DIM), dtype=np.float32)
            self._timestamps = np.empty((0,), dtype=np.float64)
            self._meta = []
            return

        self._matrix = np.array(vectors, dtype=np.float32)
        # L2-normalize for cosine (dot product on unit vectors = cosine similarity)
        norms = np.linalg.norm(self._matrix, axis=1, keepdims=True)
        norms[norms == 0] = 1.0  # avoid division by zero
        self._matrix = self._matrix / norms

        self._timestamps = np.array(timestamps, dtype=np.float64)
        self._meta = meta

        elapsed = (time.perf_counter() - t0) * 1000
        logger.info(
            "[NumpyCache] Loaded %d vectors (%.1fms) | matrix shape: %s",
            len(self._meta),
            elapsed,
            self._matrix.shape,
        )

    @staticmethod
    def _deserialize(blob: bytes) -> list[float]:
        """Deserialize embedding blob (struct binary or legacy JSON).

        Tries struct unpack first (common case). Falls back to JSON only
        if struct fails AND blob starts with '[' or '{' (legacy encoding).
        This avoids false-positive JSON detection when random binary data
        happens to start with 0x5b ([) or 0x7b ({) — ~0.7% of float32 blobs.
        """
        if not blob:
            return []
        # Fast path: struct binary (blob length must be multiple of 4)
        if len(blob) % 4 == 0:
            try:
                dim = len(blob) // 4
                return list(struct.unpack(f"{dim}f", blob))
            except (struct.error, MemoryError):
                pass
        # Legacy JSON fallback
        if blob.startswith((b"[", b"{")):
            import json

            try:
                return json.loads(blob.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        return []

    async def search(
        self,
        query_vec: list[float],
        limit: int = 3,
        memory_type: str | None = None,
        decay_lambda: float = _DECAY_LAMBDA,
    ) -> list[MemoryEntry]:
        """Numpy batch cosine + temporal decay → top-k MemoryEntry list.

        Args:
            query_vec: Raw embedding vector (will be L2-normalized).
            limit: Number of results to return.
            memory_type: Optional filter (applied post-fetch).
            decay_lambda: Temporal decay rate (0.001 → half-life 29 days).

        Returns:
            List of MemoryEntry sorted by final_score descending.
        """
        await self._ensure_loaded()

        if self._matrix is None or len(self._meta) == 0:
            return []

        # Normalize query vector
        q = np.array(query_vec, dtype=np.float32)
        q_norm = np.linalg.norm(q)
        if q_norm == 0:
            return []
        q = q / q_norm

        # ── Vectorized cosine similarity (BLAS-accelerated) ──
        similarities = self._matrix @ q  # (N,) dot products on unit vectors

        # ── Vectorized temporal decay ──
        now = time.time()
        ts = self._timestamps
        if ts is None:
            return []
        age_seconds = now - ts
        age_days = age_seconds / 86400.0
        decay_factors = np.exp(-decay_lambda * age_days * 24.0)  # lambda is per-hour
        final_scores = similarities * decay_factors

        # ── Filter by memory_type (post-fetch, like vectorlite) ──
        if memory_type:
            mask = np.array(
                [m.memory_type == memory_type for m in self._meta],
                dtype=bool,
            )
            final_scores = np.where(mask, final_scores, -np.inf)

        # ── Top-K extraction ──
        k = min(limit, len(final_scores))
        if k == 0:
            return []

        # argpartition for O(N) top-k, then sort the k winners
        top_idx = np.argpartition(-final_scores, k - 1)[:k]
        top_sorted = top_idx[np.argsort(-final_scores[top_idx])]

        results: list[MemoryEntry] = []
        for idx in top_sorted:
            score = float(final_scores[idx])
            if score <= 0:  # skip -inf (filtered out) and zero scores
                continue
            meta = self._meta[idx]
            # Convert cosine similarity to distance for MemoryEntry compatibility
            # distance = 1 - cosine_sim (so semantic_score = 1/(1+dist) ≈ cosine)
            cosine_sim = float(similarities[idx])
            distance = 1.0 - cosine_sim
            results.append(
                MemoryEntry(
                    id=meta.row_id,
                    ts=meta.ts,
                    query=meta.query,
                    response=meta.response,
                    context=meta.context,
                    memory_type=meta.memory_type,
                    distance=distance,
                )
            )
        return results

    async def add_vector(
        self,
        row_id: int,
        ts: str,
        query: str,
        response: str,
        context: str,
        memory_type: str,
        embedding_blob: bytes,
    ) -> None:
        """Write-through: append a new vector to the in-memory cache.

        Called after a new memory is stored in SQLite. No full reload needed.
        """
        await self._ensure_loaded()

        try:
            vec = self._deserialize(embedding_blob)
            if len(vec) != EMBEDDING_DIM:
                return
        except Exception:
            return

        async with self._lock:
            arr = np.array([vec], dtype=np.float32)
            norm = np.linalg.norm(arr, axis=1, keepdims=True)
            norm[norm == 0] = 1.0
            arr = arr / norm

            if self._matrix is None or self._matrix.shape[0] == 0:
                self._matrix = arr
            else:
                self._matrix = np.vstack([self._matrix, arr])

            try:
                dt = datetime.fromisoformat(ts)
                ts_epoch = dt.timestamp()
            except (ValueError, TypeError):
                ts_epoch = 0.0

            if self._timestamps is None or self._timestamps.shape[0] == 0:
                self._timestamps = np.array([ts_epoch], dtype=np.float64)
            else:
                self._timestamps = np.append(self._timestamps, ts_epoch)

            self._meta.append(_CacheEntry(row_id, ts, query, response, context, memory_type))

            # Enforce hard cap (evict oldest)
            if len(self._meta) > self._max_vectors:
                self._matrix = self._matrix[-self._max_vectors :]
                self._timestamps = self._timestamps[-self._max_vectors :]
                self._meta = self._meta[-self._max_vectors :]

        logger.debug(
            "[NumpyCache] Added vector row_id=%d | cache size: %d",
            row_id,
            len(self._meta),
        )

    async def reload(self) -> None:
        """Force full reload from DB (e.g., after bulk operations)."""
        async with self._lock:
            await self._load_from_db()
            self._loaded = True

    def stats(self) -> dict:
        """Return cache statistics for monitoring."""
        return {
            "vectors": len(self._meta),
            "matrix_shape": list(self._matrix.shape) if self._matrix is not None else [0, 0],
            "loaded": self._loaded,
            "max_vectors": self._max_vectors,
        }


# ── Singleton ──
_cache_instance: NumpyVectorCache | None = None
_cache_lock = asyncio.Lock()


async def get_numpy_cache() -> NumpyVectorCache:
    """Get or create the singleton NumpyVectorCache."""
    global _cache_instance
    if _cache_instance is None:
        async with _cache_lock:
            if _cache_instance is None:
                _cache_instance = NumpyVectorCache()
    return _cache_instance
