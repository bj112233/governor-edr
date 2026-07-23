"""
Semantic clustering for batch mode — group results by embedding similarity.

Uses a vectorized NumPy path when available and falls back to a pure-Python
O(n²) implementation otherwise.
"""

from _text_utils import _cosine_similarity, _embed_texts


def _cluster_numpy(results, vectors, threshold: float):
    """Vectorized cosine-similarity clustering via NumPy."""
    import numpy as np

    mat = np.array(vectors, dtype=np.float32)
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0  # avoid div-by-zero
    mat_norm = mat / norms
    sim_matrix = mat_norm @ mat_norm.T  # (n, n)

    clusters: list[list[tuple[str, str]]] = []
    assigned = [False] * len(results)
    for i in range(len(results)):
        if assigned[i]:
            continue
        cluster = [results[i]]
        assigned[i] = True
        row = sim_matrix[i, i + 1 :]
        candidates = np.where(row >= threshold)[0]
        for offset in candidates:
            j = i + 1 + int(offset)
            if not assigned[j]:
                cluster.append(results[j])
                assigned[j] = True
        clusters.append(cluster)
    return clusters


def _cluster_python(results, vectors, threshold: float):
    """Pure-Python O(n²) fallback clustering."""
    clusters: list[list[tuple[str, str]]] = []
    assigned = [False] * len(results)
    for i in range(len(results)):
        if assigned[i]:
            continue
        cluster = [results[i]]
        assigned[i] = True
        for j in range(i + 1, len(results)):
            if (
                not assigned[j]
                and _cosine_similarity(vectors[i], vectors[j]) >= threshold
            ):
                cluster.append(results[j])
                assigned[j] = True
        clusters.append(cluster)
    return clusters


def cluster_results(results, threshold: float):
    """Cluster ``results`` (list of (path, content)) by semantic similarity.

    Returns a new list ordered by cluster, each cluster preceded by a
    ``__CLUSTER_N__`` header entry. Returns ``results`` unchanged when
    embeddings are unavailable or don't match the result count.
    """
    if len(results) <= 1:
        return results

    texts_for_cluster = [content[:500] for _, content in results]
    vectors = _embed_texts(texts_for_cluster)
    if not vectors or len(vectors) != len(results):
        return results

    try:
        clusters = _cluster_numpy(results, vectors, threshold)
    except ImportError:
        clusters = _cluster_python(results, vectors, threshold)

    # Rebuild results in cluster order
    rebuilt = []
    for idx, cluster in enumerate(clusters, 1):
        rebuilt.append(
            (
                f"__CLUSTER_{idx}__",
                f"### 🔗 Cluster {idx} ({len(cluster)} documents)\n",
            )
        )
        rebuilt.extend(cluster)
    return rebuilt
