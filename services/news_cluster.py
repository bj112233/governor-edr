# services/news_cluster.py
"""News clustering via embeddings + HAC.

Reuses services.clustering for the algorithm and services.embedding_service
for vectorization.
"""

import logging
import re

from services.clustering import cluster_texts

logger = logging.getLogger(__name__)

# Hebrew + Latin + digits word chars; drop common stop words.
_CONTENT_RE = re.compile(r"[\w\u0590-\u05ff]+", re.UNICODE)
_STOP_WORDS_HE = {
    "ב",
    "ל",
    "של",
    "את",
    "על",
    "עם",
    "ה",
    "ו",
    "או",
    "אל",
    "לא",
    "כן",
    "גם",
    "כי",
    "אבל",
    "אם",
    "כך",
    "כדי",
    "אז",
    "עוד",
    "רק",
    "כל",
    "איזה",
    "כמה",
    "איזו",
    "מה",
    "מי",
    "איך",
    "למה",
    "איפה",
    "מתי",
    "האם",
    "is",
    "the",
    "a",
    "an",
    "to",
    "of",
    "and",
    "in",
    "for",
    "on",
    "at",
    "with",
    "from",
    "by",
    "as",
    "it",
    "this",
    "that",
    "be",
    "are",
    "was",
    # Military news is full of these — they cause over-clustering
    "צהל",
    "לוחם",
    "לוחמים",
    "חייל",
    "חיילים",
    "צבא",
    "מלחמה",
    "פיגוע",
}


def _extract_keywords(text: str) -> set[str]:
    """Extract content words (drop stop words and short tokens)."""
    words = _CONTENT_RE.findall(text.lower())
    return {w for w in words if len(w) >= 3 and w not in _STOP_WORDS_HE}


def _has_keyword_overlap(a: str, b: str) -> bool:
    """Return True if the two texts share at least 2 content words.

    Requiring 2+ words prevents over-clustering on a single common
    term (e.g. 'צה"ל' in military news, 'בנק' in economy news).
    """
    kw_a = _extract_keywords(a)
    kw_b = _extract_keywords(b)
    if not kw_a or not kw_b:
        return False
    common = kw_a & kw_b
    return len(common) >= 2


def _validate_clusters(clusters: list[list[int]], texts: list[str]) -> list[list[int]]:
    """Post-process HAC clusters: split clusters with no keyword overlap.

    Articles that don't share any content word with the first article
    in their cluster are split into singletons.
    """
    out: list[list[int]] = []
    for c in clusters:
        if len(c) <= 1:
            out.append(c)
            continue
        keep = [c[0]]
        pivot_text = texts[c[0]]
        for idx in c[1:]:
            if _has_keyword_overlap(pivot_text, texts[idx]):
                keep.append(idx)
            else:
                out.append([idx])  # split into singleton
        out.append(keep)
    return out


async def cluster_items(items: list[dict], bridge, threshold: float = 0.86) -> list[list[dict]]:
    """Cluster news items by title similarity with keyword validation.

    Args:
        items: List of article dicts with at least 'title'.
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
    # Title-only: summaries from the same source share boilerplate.
    texts = [it.get("title", "") for it in items]

    try:
        idx_clusters = await cluster_texts(texts, svc, threshold=threshold)
    except Exception as exc:
        logger.warning("[NewsCluster] cluster_texts failed: %s — returning singletons", exc)
        return [[it] for it in items]

    # Post-process: split clusters with no keyword overlap (reduces false positives
    # on short Hebrew titles where embeddings can be misleading).
    idx_clusters = _validate_clusters(idx_clusters, texts)

    return [[items[i] for i in c] for c in idx_clusters]
