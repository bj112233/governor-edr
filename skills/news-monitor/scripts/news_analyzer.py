"""News Monitor — Business Logic / Scoring (The Brain).

Embeddings, cosine similarity, HAC clustering, semantic deduplication.
No network I/O (except to the local LLM endpoint for embeddings).
No rendering, no categorization rules.
"""

from __future__ import annotations

import hashlib
import logging
import os

import aiohttp

from _news_utils import (
    Article,
    _get_db,
    _get_state,
    _sanitize_text,
    _save_state,
)

logger = logging.getLogger(__name__)

_LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5001/v1")


# ── Embedding Computation ──


async def _embed_texts(
    texts: list[str],
    model: str = os.getenv(
        "EMBEDDING_MODEL", "text-embedding-multilingual-e5-large-instruct"
    ),
) -> list[list[float]] | None:
    """Compute embeddings via local LLM endpoint. Returns None on failure."""
    try:
        url = f"{_LLM_API_BASE}/embeddings"
        prefixed = ["passage: " + t for t in texts]
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json={"model": model, "input": prefixed},
                timeout=aiohttp.ClientTimeout(total=15),
                headers={"Content-Type": "application/json"},
            ) as response:
                response.raise_for_status()
                data = await response.json()
                return [d["embedding"] for d in data.get("data", [])]
    except Exception:
        return None


# ── Cosine Similarity ──


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity (-1..1)."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _cosine_similarity_vec(a: list[float], b: list[float]) -> float:
    """Alias for HAC matrix builder."""
    return _cosine_similarity(a, b)


def _build_similarity_matrix(vectors: list[list[float]]) -> list[list[float]]:
    n = len(vectors)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            sim = _cosine_similarity_vec(vectors[i], vectors[j])
            matrix[i][j] = sim
            matrix[j][i] = sim
    return matrix


# ── Greedy Single-Linkage HAC ──


def _hac_cluster(
    vectors: list[list[float]], threshold: float = 0.82
) -> list[list[int]]:
    """Greedy single-linkage HAC. Returns clusters as lists of indices."""
    n = len(vectors)
    if n == 0:
        return []
    if n == 1:
        return [[0]]

    matrix = _build_similarity_matrix(vectors)
    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(n):
        for j in range(i + 1, n):
            if matrix[i][j] >= threshold:
                _union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        root = _find(i)
        groups.setdefault(root, []).append(i)
    return list(groups.values())


# ── Semantic Deduplication ──


async def semantic_dedup(
    articles: list[Article],
    threshold: float,
    state_key: str,
) -> list[Article]:
    """Remove semantically duplicate articles via embeddings.

    Reads/writes seen embeddings to SQLite state. Cap at 500 entries.
    """
    if not articles:
        return []

    db = await _get_db()
    try:
        seen_embeds: dict[str, list[float]] = await _get_state(
            db, f"news_monitor_{state_key}_embeddings"
        )
    finally:
        await db.close()

    texts = [f"{art.title}\n{art.summary}" for art in articles]
    vectors = await _embed_texts(texts)

    if not vectors:
        return articles

    unique: list[Article] = []
    new_embeds: dict[str, list[float]] = {}
    for art, vec in zip(articles, vectors):
        link = art.link or art.title
        is_dup = False
        for seen_vec in seen_embeds.values():
            if _cosine_similarity(vec, seen_vec) >= threshold:
                is_dup = True
                break
        if not is_dup:
            unique.append(art)
            if link:
                new_embeds[link] = vec

    seen_embeds.update(new_embeds)
    if len(seen_embeds) > 500:
        seen_embeds = dict(list(seen_embeds.items())[-500:])

    db = await _get_db()
    try:
        await _save_state(db, f"news_monitor_{state_key}_embeddings", seen_embeds)
    finally:
        await db.close()

    return unique


# ── Clustering ──


async def cluster_articles(
    articles: list[Article],
    threshold: float,
) -> list[list[Article]]:
    """Cluster articles by semantic similarity of title+summary.

    Returns clusters as lists of Article objects.
    """
    if not articles:
        return []
    texts = [f"{art.title}\n{art.summary}" for art in articles]
    vectors = await _embed_texts(texts)
    if not vectors:
        return [[art] for art in articles]
    idx_clusters = _hac_cluster(vectors, threshold=threshold)
    return [[articles[i] for i in c] for c in idx_clusters]
