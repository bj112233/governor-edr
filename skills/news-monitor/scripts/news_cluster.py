# skills/news-monitor/scripts/news_cluster.py
"""News clustering via embeddings + HAC.

Reuses services.clustering for the algorithm and services.embedding_service
for vectorization.
"""

import logging
from typing import List

from services.clustering import cluster_texts

logger = logging.getLogger(__name__)


async def cluster_items(items: List[dict], bridge, threshold: float = 0.82) -> List[List[dict]]:
    """Cluster news items by title+summary similarity.

    Args:
        items: List of article dicts with at least 'title' and optionally 'summary'.
        bridge: LLMBridge instance (used to reach embed via EmbeddingService).
        threshold: Cosine similarity threshold for merging clusters.

    Returns:
        List of clusters, each cluster is a list of article dicts.
    """
    if not items:
        return []
    if len(items) == 1:
        return [items]

    from services.embedding_service import get_embedding_service

    svc = get_embedding_service()
    texts = [f"{it.get('title', '')}\n{it.get('summary', '')}" for it in items]

    try:
        idx_clusters = await cluster_texts(texts, svc, threshold=threshold)
    except Exception as exc:
        logger.warning("[NewsCluster] cluster_texts failed: %s — returning singletons", exc)
        return [[it] for it in items]

    # Map index clusters back to article dicts
    return [[items[i] for i in c] for c in idx_clusters]
