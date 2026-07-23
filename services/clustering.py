# services/clustering.py
"""Generic hierarchical agglomerative clustering (HAC) for text/documents.

Reusable across: news articles, user documents, threat alerts.
"""

import logging
from typing import Optional

from services.embedding_service import cosine_similarity

logger = logging.getLogger(__name__)


def build_similarity_matrix(vectors: list[list[float]]) -> list[list[float]]:
    """Pairwise cosine similarity matrix (upper triangle inclusive)."""
    n = len(vectors)
    matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        matrix[i][i] = 1.0
        for j in range(i + 1, n):
            sim = cosine_similarity(vectors[i], vectors[j])
            matrix[i][j] = sim
            matrix[j][i] = sim
    return matrix


def hac_cluster(vectors: list[list[float]], threshold: float = 0.82) -> list[list[int]]:
    """Hierarchical agglomerative clustering.

    Returns clusters as lists of vector indices.
    Greedy single-linkage: if any pair within clusters exceeds threshold, merge.
    """
    n = len(vectors)
    if n == 0:
        return []
    if n == 1:
        return [[0]]

    matrix = build_similarity_matrix(vectors)

    # Each item starts in its own cluster
    clusters: list[list[int]] = [[i] for i in range(n)]

    while True:
        best_sim = -1.0
        best_pair: tuple[int, int] | None = None

        for i in range(len(clusters)):
            for j in range(i + 1, len(clusters)):
                # single-linkage: max similarity between any pair
                max_sim = max(matrix[a][b] for a in clusters[i] for b in clusters[j])
                if max_sim > best_sim:
                    best_sim = max_sim
                    best_pair = (i, j)

        if best_pair is None or best_sim < threshold:
            break

        i, j = best_pair
        clusters[i].extend(clusters[j])
        clusters.pop(j)

    return clusters


async def cluster_texts(
    texts: list[str],
    embed_svc,
    threshold: float = 0.82,
) -> list[list[int]]:
    """Convenience wrapper: embed texts then HAC cluster.

    Args:
        texts: List of text strings to cluster.
        embed_svc: Object with async `embed(texts: List[str]) -> List[List[float]]`.
        threshold: Cosine similarity threshold for merging clusters.

    Returns:
        Clusters as lists of indices into the original `texts` list.
    """
    if not texts:
        return []

    try:
        vectors = await embed_svc.embed(["passage: " + t for t in texts])
    except Exception as exc:
        logger.warning("[Clustering] embed failed: %s — returning singletons", exc)
        return [[i] for i in range(len(texts))]

    return hac_cluster(vectors, threshold=threshold)
