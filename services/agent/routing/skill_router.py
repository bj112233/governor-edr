# services/agent/routing/skill_router.py
import logging
import re
from typing import Any

from services.agent.routing import embeddings as _emb
from services.agent.routing.hebrew_norm import _normalize_hebrew_query
from services.agent.skill_keywords import _SKILL_KEYWORD_MAP
from services.embedding_service import cosine_similarity

logger = logging.getLogger(__name__)

_TRANSLATE_KEYWORDS = ("תרגם", "תרגום", "translate", "translation", "לעברית", "לאנגלית")


async def _semantic_skill_filter(
    user_question: str, all_skills: list[dict[str, Any]], max_skills: int
) -> list[dict[str, Any]]:
    """Semantic cosine-similarity filter against pre-computed skill vectors."""
    if not (_emb._SEMANTIC_READY and _emb._SKILL_EMBEDDINGS):
        return []
    try:
        from services.embedding_service import get_embedding_service

        svc = get_embedding_service()
        query_vectors = await svc.embed(["query: " + user_question])
        query_vec = query_vectors[0]

        sims = []
        for s in all_skills:
            name = s.get("function", {}).get("name", "")
            skill_vec = _emb._SKILL_EMBEDDINGS.get(name)
            if skill_vec:
                sim = cosine_similarity(query_vec, skill_vec)
                sims.append((sim, s))

        sims.sort(key=lambda x: x[0], reverse=True)
        max_sim = sims[0][0] if sims else 0.0
        rel_cutoff = max_sim - _emb._SKILL_RELATIVE_DELTA
        result = [
            skill for sim, skill in sims[:max_skills] if sim >= _emb._SKILL_SIMILARITY_THRESHOLD and sim >= rel_cutoff
        ]
        if result:
            names = [s.get("function", {}).get("name", "?") for s in result]
            logger.info("[AGENT-DEBUG] Semantic skill filter: %s", names)
        return result
    except Exception as exc:
        logger.debug("[Routing] Semantic skill filter failed: %s", exc)
        return []


def _keyword_skill_match(user_question: str) -> set[str]:
    """Match user question against the skill keyword map (raw + Hebrew-normalized)."""
    q = user_question.lower()
    q_norm = _normalize_hebrew_query(user_question)
    matched: set[str] = set()
    for kw, skill_set in _SKILL_KEYWORD_MAP.items():
        kw_lower = kw.lower()
        # Word-boundary match for short keywords (<=3 chars) to prevent
        # substring false positives like "קור" inside "קוראים"
        if len(kw_lower) <= 3:
            pattern = r"\b" + re.escape(kw_lower) + r"\b"
            if re.search(pattern, q) or re.search(pattern, q_norm):
                matched.update(skill_set)
        elif kw_lower in q or kw_lower in q_norm:
            matched.update(skill_set)
    return matched


def _detect_special_skill_signals(user_question: str, matched: set[str]) -> set[str]:
    """Heuristic detectors: tickers, text-file+translate, PDF+translate."""
    q = user_question.lower()
    # Ticker-like uppercase sequences (NVDA, AAPL…) → always include stocks-skill
    if re.search(r"\b[A-Z]{2,5}\b", user_question):
        matched.add("skill_stocks-skill")

    # Text file path with translation request → translator-skill
    if re.search(r"\.(txt|md|csv|json)\b", user_question, re.IGNORECASE):
        if any(kw in q for kw in _TRANSLATE_KEYWORDS):
            matched.add("skill_translator-skill")
            logger.info("[AGENT-DEBUG] File path + translation keywords detected → translator-skill prioritized")

    # PDF file path with translation request → file-analyst (OCR/translation)
    if re.search(r"\.pdf\b", user_question, re.IGNORECASE):
        if any(kw in q for kw in _TRANSLATE_KEYWORDS):
            matched.add("skill_file-analyst")
            logger.info(
                "[AGENT-DEBUG] PDF file + translation keywords detected → file-analyst prioritized for OCR/translation"
            )
    return matched


def _merge_skill_results(
    semantic_result: list[dict[str, Any]],
    keyword_result: list[dict[str, Any]],
    max_skills: int,
) -> list[dict[str, Any]]:
    """Hybrid merge: semantic first, keyword fills gaps, deduplicated by name."""
    combined: dict[str, dict[str, Any]] = {}
    for tool in semantic_result:
        name = tool.get("function", {}).get("name", "")
        if name:
            combined[name] = tool
    for tool in keyword_result:
        name = tool.get("function", {}).get("name", "")
        if name:
            combined[name] = tool

    if not combined:
        return []

    final_list = list(combined.values())
    logger.info(
        "[AGENT-DEBUG] Hybrid routing: Semantic=%d, Keywords=%d, Total=%d",
        len(semantic_result),
        len(keyword_result),
        len(final_list),
    )
    return final_list[:max_skills]


async def _filter_relevant_skills(
    user_question: str, all_skills: list[dict[str, Any]], max_skills: int = 12
) -> list[dict[str, Any]]:
    """Return only skills whose keywords match the user question.

    If semantic embeddings are ready, uses cosine similarity against
    pre-computed skill description vectors first.
    If no keywords match, returns the first `max_skills` skills (fallback).
    This reduces the tool-calling decision space for the local model (8K ctx budget).
    """
    semantic_result = await _semantic_skill_filter(user_question, all_skills, max_skills)

    matched = _keyword_skill_match(user_question)
    logger.info(
        f"[AGENT-DEBUG] _filter_relevant_skills: query='{user_question.lower()[:50]}' matched_keywords={matched}"
    )
    all_skill_names = [s.get("function", {}).get("name", "?") for s in all_skills]
    logger.info(f"[AGENT-DEBUG] _filter_relevant_skills: all_skill_names={all_skill_names}")
    matched = _detect_special_skill_signals(user_question, matched)

    keyword_result: list[dict[str, Any]] = []
    if matched:
        keyword_result = [s for s in all_skills if s.get("function", {}).get("name", "") in matched]
        keyword_names = [s.get("function", {}).get("name", "?") for s in keyword_result]
        logger.info(f"[AGENT-DEBUG] _filter_relevant_skills: keyword_result={keyword_names}")

    merged = _merge_skill_results(semantic_result, keyword_result, max_skills)
    if merged:
        return merged

    # No match — return empty, tools will handle the request
    logger.info("[AGENT-DEBUG] _filter_relevant_skills: no match — returning empty")
    return []
