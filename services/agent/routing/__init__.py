# services/agent/routing/__init__.py
# Facade — backward compatible re-exports for consumers of the old routing.py
# Any import like `from services.agent import routing` or `from services.agent.routing import X`
# continues to work exactly as before.

from services.agent.routing.conversational_router import _is_conversational
from services.agent.routing.embeddings import (
    _CONVERSATIONAL_EMBEDDING,
    _CONVERSATIONAL_INTENT_TEXTS,
    _CONVERSATIONAL_SIMILARITY_THRESHOLD,
    _SEMANTIC_READY,
    _SKILL_EMBEDDINGS,
    _SKILL_RELATIVE_DELTA,
    _SKILL_SIMILARITY_THRESHOLD,
    _TOOL_EMBEDDINGS,
    _TOOL_SEMANTIC_READY,
    init_skill_embeddings,
    init_tool_embeddings,
)
from services.agent.routing.hebrew_norm import (
    _HEB_LETTER_RE,
    _HEB_PREFIXES,
    _PUNCT_RE,
    _normalize_hebrew_query,
    _normalize_keyword_set,
    _strip_hebrew_prefix,
)
from services.agent.routing.keywords import (
    _CAPABILITY_PATTERNS,
    _CAPABILITY_PATTERNS_NORM,
    _CONVERSATIONAL_KEYWORDS,
    _CONVERSATIONAL_KEYWORDS_NORM,
    _STRICT_GREETING_PHRASES,
    _SYSTEM_KEYWORDS,
    _SYSTEM_KEYWORDS_NORM,
)
from services.agent.routing.skill_router import _filter_relevant_skills
from services.agent.routing.tool_router import _filter_relevant_tools
from services.embedding_service import cosine_similarity

__all__ = [
    "init_skill_embeddings",
    "init_tool_embeddings",
    "_filter_relevant_skills",
    "_filter_relevant_tools",
    "_is_conversational",
    "_SEMANTIC_READY",
    "_SKILL_EMBEDDINGS",
    "_TOOL_EMBEDDINGS",
    "_TOOL_SEMANTIC_READY",
    "_CONVERSATIONAL_EMBEDDING",
    "_CONVERSATIONAL_SIMILARITY_THRESHOLD",
    "_CONVERSATIONAL_INTENT_TEXTS",
    "_SKILL_SIMILARITY_THRESHOLD",
    "_SKILL_RELATIVE_DELTA",
    "_normalize_hebrew_query",
    "_normalize_keyword_set",
    "_strip_hebrew_prefix",
    "_HEB_PREFIXES",
    "_HEB_LETTER_RE",
    "_PUNCT_RE",
    "_CONVERSATIONAL_KEYWORDS",
    "_CONVERSATIONAL_KEYWORDS_NORM",
    "_CAPABILITY_PATTERNS",
    "_CAPABILITY_PATTERNS_NORM",
    "_SYSTEM_KEYWORDS",
    "_SYSTEM_KEYWORDS_NORM",
    "_STRICT_GREETING_PHRASES",
    "cosine_similarity",
]
