# services/news_ai/clusters.py
"""Cluster summarization orchestrator — controls LLM call batching.

Refactored (Phase 2): separates chunking (pure logic) from LLM I/O.
"""

import logging

from services.thinking_parser import strip_thinking_content

from ._security import FIREWALL_DIRECTIVE
from .prompts import build_cluster_prompt, parse_cluster_response
from .single import summarize_cluster

logger = logging.getLogger(__name__)

_CLUSTER_CHUNK = 5


def _chunk_clusters(clusters: list[list[dict]], chunk_size: int = _CLUSTER_CHUNK) -> list[list[list[dict]]]:
    """Pure: split clusters into chunks of chunk_size."""
    return [clusters[i : i + chunk_size] for i in range(0, len(clusters), chunk_size)]


async def _summarize_single_chunk(
    clusters: list[list[dict]],
    bridge,
    timeout: float,
) -> list[str | None]:
    """LLM I/O: summarize one chunk (≤5 clusters) in a single prompt."""
    prompt = build_cluster_prompt(clusters)
    try:
        raw_response = await bridge.complete(
            system_prompt=(
                "You are a tactical intelligence summarizer. "
                "Do NOT include any thinking blocks or internal reasoning. "
                "Reply directly with the requested numbered format only." + FIREWALL_DIRECTIVE
            ),
            user_input=prompt,
            temperature=0.2,
            max_tokens=4096,
            timeout=timeout,
        )
        response = strip_thinking_content(raw_response or "")
        if " thinking" in response and "done" not in response.lower():
            response = response.split(" thinking", 1)[0]
        if not response.strip():
            response = raw_response or ""
        parsed: list[str | None] = list(parse_cluster_response(response, len(clusters)))
        success = sum(1 for p in parsed if p)
        logger.info("[NewsAI] bulk_summarize_clusters clusters=%d parsed=%d", len(clusters), success)
        if success == 0:
            logger.info("[NewsAI] bulk parse failed → per-cluster fallback")
            parsed = [await summarize_cluster(c, bridge) for c in clusters]
        return parsed
    except Exception as exc:
        logger.warning("[NewsAI] bulk_summarize_clusters failed: %s", exc)
        return [c[0].get("title") if c else None for c in clusters]


async def bulk_summarize_clusters(clusters: list[list[dict]], bridge, timeout: float = 75.0) -> list[str | None]:
    """Summarize all clusters in a SINGLE LLM prompt.

    Returns list of headlines (same length as clusters).
    Falls back to first-article title on failure.
    """
    if not clusters:
        return []
    if len(clusters) == 1:
        return [await summarize_cluster(clusters[0], bridge)]

    if len(clusters) > _CLUSTER_CHUNK:
        out: list[str | None] = []
        for chunk in _chunk_clusters(clusters):
            out.extend(await bulk_summarize_clusters(chunk, bridge, timeout=timeout))
        return out

    return await _summarize_single_chunk(clusters, bridge, timeout)
