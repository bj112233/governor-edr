# services/agent/routing/tool_router.py
import logging
from typing import Any

from services.agent.routing import embeddings as _emb
from services.agent.routing.hebrew_norm import _normalize_hebrew_query
from services.embedding_service import cosine_similarity

logger = logging.getLogger(__name__)


def _keyword_tool_hits(user_question: str, tool_lookup: dict[str, Any]) -> list[str]:
    """Step 1: zero-latency keyword substring match (raw + Hebrew-normalized)."""
    from config import SYSTEM_TOOL_THRESHOLD  # noqa: F401  (kept for parity)
    from services.tools.descriptions import TOOL_KEYWORD_MAP as _TOOL_KEYWORD_MAP

    q_lower = user_question.lower()
    q_norm = _normalize_hebrew_query(user_question)
    hits: list[str] = []
    for tool_name, keywords in _TOOL_KEYWORD_MAP.items():
        if tool_name not in tool_lookup:
            continue
        for kw in keywords:
            kw_l = kw.lower()
            if kw_l in q_lower or kw_l in q_norm:
                hits.append(tool_name)
                break
    return hits


async def _semantic_tool_hits(user_question: str, all_tools: list[dict[str, Any]]) -> list[str]:
    """Step 2: cosine similarity against pre-computed tool vectors."""
    from config import SYSTEM_TOOL_THRESHOLD

    if not (_emb._TOOL_SEMANTIC_READY and _emb._TOOL_EMBEDDINGS):
        return []
    try:
        from services.embedding_service import get_embedding_service

        svc = get_embedding_service()
        q_vecs = await svc.embed(["query: " + user_question])
        q_vec = q_vecs[0]
        scored: list[tuple] = []
        for t in all_tools:
            name = t.get("function", {}).get("name", "")
            vec = _emb._TOOL_EMBEDDINGS.get(name)
            if vec:
                scored.append((cosine_similarity(q_vec, vec), name))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [name for score, name in scored if score >= SYSTEM_TOOL_THRESHOLD]
    except Exception as exc:
        logger.debug("[Routing] Semantic tool filter failed: %s", exc)
        return []


def _merge_tool_results(keyword_hits: list[str], semantic_hits: list[str], max_tools: int) -> list[str]:
    """Step 3: interleave keyword and semantic hits, deduplicated.

    Keyword-first primacy preserved, but semantic hits are interleaved to
    prevent starvation when keyword over-matches (e.g. broad threat-hunt
    queries matching 9+ tools via keywords, shutting out semantically
    relevant tools like get_firewall_drops that lack exact keyword matches).
    """
    merged: list[str] = []
    ki = si = 0
    while len(merged) < max_tools and (ki < len(keyword_hits) or si < len(semantic_hits)):
        if ki < len(keyword_hits):
            name = keyword_hits[ki]
            ki += 1
            if name not in merged:
                merged.append(name)
        if len(merged) >= max_tools:
            break
        if si < len(semantic_hits):
            name = semantic_hits[si]
            si += 1
            if name not in merged:
                merged.append(name)
    return merged[:max_tools]


async def _filter_relevant_tools(
    user_question: str, all_tools: list[dict[str, Any]], max_tools: int = 5
) -> list[dict[str, Any]]:
    """Hybrid tool router: keyword-first then semantic merge.

    1. Keyword pass — zero-latency substring match against _TOOL_KEYWORD_MAP.
    2. Semantic pass — cosine similarity against pre-computed tool vectors.
    3. Merge — interleave keyword and semantic hits up to max_tools.
    Returns empty list if nothing matched (caller falls back to _TOOLS_BASIC).
    """
    tool_lookup: dict[str, Any] = {t.get("function", {}).get("name", ""): t for t in all_tools}

    keyword_hits = _keyword_tool_hits(user_question, tool_lookup)
    semantic_hits = await _semantic_tool_hits(user_question, all_tools)
    merged = _merge_tool_results(keyword_hits, semantic_hits, max_tools)

    result = [tool_lookup[name] for name in merged if name in tool_lookup]
    logger.info(
        "[AGENT-DEBUG] Hybrid tool filter: keyword=%d semantic=%d → %d tools: %s",
        len(keyword_hits),
        len(semantic_hits),
        len(result),
        [t.get("function", {}).get("name", "?") for t in result],
    )
    return result
