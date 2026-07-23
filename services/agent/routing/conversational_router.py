# services/agent/routing/conversational_router.py
import logging
import re

from services.agent.routing import embeddings as _emb
from services.agent.routing.hebrew_norm import _normalize_hebrew_query
from services.agent.routing.keywords import (
    _CAPABILITY_PATTERNS_NORM,
    _CONVERSATIONAL_KEYWORDS_NORM,
    _STRICT_GREETING_PHRASES,
    _SYSTEM_KEYWORDS_NORM,
)
from services.agent.skill_keywords import _SKILL_KEYWORD_MAP
from services.embedding_service import cosine_similarity

logger = logging.getLogger(__name__)


def _strip_enriched_prefix(query: str) -> str:
    """Strip "[מבצע: Name] message" → "message". Returns lowercased body."""
    q = query.strip()
    if q.startswith("[מבצע:") and "]" in q:
        q = q.split("]", 1)[1].strip()
    return q.lower()


def _has_capability_signal(q: str, q_norm: str) -> bool:
    """Capability/help questions force full agent path (never conversational)."""
    return any(p in q for p in _CAPABILITY_PATTERNS_NORM) or any(p in q_norm for p in _CAPABILITY_PATTERNS_NORM)


def _has_system_signal(q: str, q_norm: str) -> bool:
    """System keywords are the strongest signal — checked before greeting fallbacks."""
    return any(kw in q for kw in _SYSTEM_KEYWORDS_NORM) or any(kw in q_norm for kw in _SYSTEM_KEYWORDS_NORM)


def _has_skill_signal(q: str, q_norm: str) -> bool:
    """Skill keywords force tools when a skill topic appears."""
    for kw in _SKILL_KEYWORD_MAP:
        kw_l = kw.lower()
        if len(kw_l) <= 3:
            pattern = r"\b" + re.escape(kw_l) + r"\b"
            if re.search(pattern, q) or re.search(pattern, q_norm):
                return True
        elif kw_l in q or kw_l in q_norm:
            return True
    return False


async def _semantic_conversational_check(query: str) -> bool:
    """Semantic similarity against the conversational intent vector."""
    if not (_emb._SEMANTIC_READY and _emb._CONVERSATIONAL_EMBEDDING is not None):
        return False
    try:
        from services.embedding_service import get_embedding_service

        svc = get_embedding_service()
        query_vectors = await svc.embed(["query: " + query])
        sim = cosine_similarity(query_vectors[0], _emb._CONVERSATIONAL_EMBEDDING)
        logger.debug("[Routing] Conversational similarity: %.3f", sim)
        return sim > _emb._CONVERSATIONAL_SIMILARITY_THRESHOLD
    except Exception as exc:
        logger.debug("[Routing] Semantic conversational check failed: %s", exc)
        return False


async def _is_conversational(query: str) -> bool:
    """בדיקה האם השאלה היא שיח חופשי שלא דורש כלים.

    מטפל גם בטקסט מועשר מ-handler ([מבצע: ...]) וגם בטקסט נקי.
    אם embeddings מוכנים — משתמש ב-similarity ל-intent שיחה.
    """
    if not query:
        return True

    q = _strip_enriched_prefix(query)
    q_norm = _normalize_hebrew_query(query)

    # Capability/help questions → force full agent path (never conversational)
    if _has_capability_signal(q, q_norm):
        return False

    # Pure-greeting fast path: only triggered when a strict greeting phrase
    # COVERS essentially the entire query (≤3 chars of fluff). This protects
    # short messages like "מה המצב?" while still letting "מה המצב המערכת?"
    # fall through to the system-keyword check below. Without this guard,
    # ambiguous tokens like "מצב" — present in BOTH the greeting set and
    # _SYSTEM_KEYWORDS — would always resolve to "system query".
    for phrase in _STRICT_GREETING_PHRASES:
        if phrase in q_norm and (len(q_norm) - len(phrase)) <= 3:
            return True

    # System keywords are the strongest signal — checked BEFORE the broader
    # greeting/conversational fallbacks. Without this ordering, a query like
    # "מה המצב המערכת?" would be eaten by the "מה המצב" greeting prefix
    # and routed to conversational mode, even though it clearly references
    # the system. Both raw and normalized forms are scanned so "המערכת" →
    # "מערכת" still hits.
    if _has_system_signal(q, q_norm):
        return False

    # Skill keywords — same reasoning, force tools when a skill topic appears
    if _has_skill_signal(q, q_norm):
        return False

    # Strict greeting guard — only triggered when no system/skill keyword
    # was found above. Matches against the normalized query so "מה המצב"
    # still matches when the user types it in any prefix-decorated form.
    if any(phrase in q_norm for phrase in _STRICT_GREETING_PHRASES):
        return True

    # ── Semantic conversational check (fast path) ──
    if await _semantic_conversational_check(query):
        return True

    # Check conversational keywords (raw + normalized for prefix tolerance)
    if any(kw in q for kw in _CONVERSATIONAL_KEYWORDS_NORM) or any(
        kw in q_norm for kw in _CONVERSATIONAL_KEYWORDS_NORM
    ):
        return True

    # Short messages without technical keywords are conversational.
    # Exception: uppercase ticker-like words (NVDA, AAPL, 2-5 chars) force full agent path.
    if len(q) < 10:
        if re.search(r"\b[A-Z]{2,5}\b", query):
            return False
        return True
    return False
