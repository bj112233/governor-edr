# services/embedding_service.py
"""Singleton embedding service with LRU caching and cosine similarity.

Centralized wrapper around LLMBridge.embed() to prevent duplicate calls
and provide a single configuration point for embedding model settings.
"""

import hashlib
import json
import logging
import math
import os
import re
from collections import OrderedDict
from time import time
from typing import Optional

from services.llm_bridge import LLMBridge

logger = logging.getLogger(__name__)

# 768 dims * 4 bytes ≈ 3KB per vector — LRU cache bounded by maxsize + TTL.

# Dynamic fragments that pollute the cache key (timestamps, msg IDs) — stripped
# before hashing so semantically identical texts collapse to one cache entry.
_DYNAMIC_PATTERNS = re.compile(
    r"\[\d{1,2}:\d{2}(?::\d{2})?\]"  # bracketed timestamps e.g. [13:29:04]
    r"|\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}"  # ISO datetimes
    r"|\bmsg[_-]?\d+\b"  # message IDs e.g. msg_123 / msg-123
    r"|\bevt_\d+\b",  # event IDs e.g. evt_1779963027656
    flags=re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")


def _normalize_text_for_cache(text: str) -> str:
    """Normalize text into a stable cache key (strip case/whitespace/dynamics)."""
    t = _DYNAMIC_PATTERNS.sub("", text).strip().lower()
    t = _WS_RE.sub(" ", t)
    if len(t.strip()) < 3:
        return text
    return t


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity (no numpy dependency)."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


def serialize_vector(v: list[float]) -> bytes:
    """Serialize float vector to bytes (4 bytes per float)."""
    import struct

    return struct.pack(f"{len(v)}f", *v)


def deserialize_vector(b: bytes) -> list[float]:
    """Deserialize bytes back to float vector.
    Backward-compatible: handles both struct binary and legacy JSON encoding.
    """
    import struct

    if not b:
        return []
    # Legacy JSON detection: first byte is '[' or '{'
    if b.startswith((b"[", b"{")):
        return json.loads(b.decode("utf-8"))
    dim = len(b) // 4
    return list(struct.unpack(f"{dim}f", b))


class EmbeddingService:
    """Singleton embedding service with isolated circuit breaker from main LLM."""

    _instance: Optional["EmbeddingService"] = None

    def __init__(self) -> None:
        self._bridge = LLMBridge.get_instance()
        self._cache: OrderedDict[str, tuple[list[float], float]] = OrderedDict()
        self._maxsize: int = int(os.getenv("EMBED_CACHE_MAX_SIZE", "2048"))
        self._ttl: float = float(os.getenv("EMBED_CACHE_TTL_SECONDS", "86400.0"))

    @classmethod
    def get_instance(cls) -> "EmbeddingService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _get(self, key: str) -> list[float] | None:
        """LRU + TTL cache read. Returns None if expired or missing."""
        if key not in self._cache:
            return None
        vec, ts = self._cache[key]
        if time() - ts > self._ttl:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return vec

    def _set(self, key: str, vec: list[float]) -> None:
        """LRU cache write with eviction."""
        now = time()
        if key in self._cache:
            self._cache.move_to_end(key)
        elif len(self._cache) >= self._maxsize:
            self._cache.popitem(last=False)
        self._cache[key] = (vec, now)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Return embeddings with LRU+TTL in-memory caching.

        Cache hits avoid the LLM call entirely.
        Misses are batched through LLMBridge.embed().
        """
        results: list[list[float] | None] = [None] * len(texts)
        missing_indices: list[int] = []
        missing_texts: list[str] = []
        hits = 0
        misses = 0

        for i, text in enumerate(texts):
            key = hashlib.sha256(_normalize_text_for_cache(text).encode("utf-8")).hexdigest()
            cached = self._get(key)
            if cached is not None:
                results[i] = cached
                hits += 1
            else:
                missing_indices.append(i)
                missing_texts.append(text)
                misses += 1

        if missing_texts:
            try:
                vectors = await self._bridge.embed(missing_texts)
                for idx, vec in zip(missing_indices, vectors):
                    key = hashlib.sha256(_normalize_text_for_cache(texts[idx]).encode("utf-8")).hexdigest()
                    self._set(key, vec)
                    results[idx] = vec
            except Exception as exc:
                logger.warning("[EmbedSvc] embed() failed: %s", exc)
                raise

        total = hits + misses
        if total:
            rate = 100.0 * hits / total
            logger.info(
                "[EmbedSvc] batch=%d hits=%d misses=%d hit_rate=%.1f%%",
                total,
                hits,
                misses,
                rate,
            )

        for i, r in enumerate(results):
            if r is None:
                raise RuntimeError(f"Embedding missing for index {i}")
        return results

    def cosine_similarity(self, a: list[float], b: list[float]) -> float:
        """Cosine similarity between two vectors."""
        return _cosine_similarity(a, b)

    def serialize(self, vector: list[float]) -> bytes:
        """Serialize a vector for SQLite BLOB storage."""
        return serialize_vector(vector)

    def deserialize(self, blob: bytes) -> list[float]:
        """Deserialize a vector from SQLite BLOB."""
        return deserialize_vector(blob)


# Module-level convenience accessors
_service: EmbeddingService | None = None


def get_embedding_service() -> EmbeddingService:
    global _service
    if _service is None:
        _service = EmbeddingService.get_instance()
    return _service


async def embed_texts(texts: list[str]) -> list[list[float]]:
    """One-shot embed convenience function."""
    return await get_embedding_service().embed(texts)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """One-shot cosine similarity convenience function."""
    return _cosine_similarity(a, b)


# Module-level convenience accessors — kept for backward compatibility.
# The canonical functions are serialize_vector / deserialize_vector above.
