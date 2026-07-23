# services/agent/routing/embeddings.py
import logging
from typing import Optional

from services.agent.skill_keywords import _SKILL_DESCRIPTIONS

logger = logging.getLogger(__name__)

_SKILL_SIMILARITY_THRESHOLD: float = 0.815
_SKILL_RELATIVE_DELTA: float = 0.030
_CONVERSATIONAL_SIMILARITY_THRESHOLD: float = 0.65

# ── Semantic embedding cache (populated by init_skill_embeddings at startup) ──
_SKILL_EMBEDDINGS: dict[str, list[float]] = {}
_CONVERSATIONAL_EMBEDDING: list[float] | None = None
_SEMANTIC_READY: bool = False

# ── System tool embedding cache (populated by init_tool_embeddings at startup) ──
_TOOL_EMBEDDINGS: dict[str, list[float]] = {}
_TOOL_SEMANTIC_READY: bool = False

_CONVERSATIONAL_INTENT_TEXTS = [
    "hello hi hey greetings good morning good evening",
    "how are you what is up how is it going",
    "thank you thanks okay bye goodbye see you",
    "small talk casual chat friendly conversation",
    "who are you what is your name introduce yourself",
]


async def init_skill_embeddings() -> None:
    """Pre-compute embeddings for skill descriptions and conversational intent.

    Called once at bot startup (main.py). Safe to call multiple times.
    """
    global _SKILL_EMBEDDINGS, _CONVERSATIONAL_EMBEDDING, _SEMANTIC_READY
    if _SEMANTIC_READY:
        return

    try:
        from services.embedding_service import get_embedding_service

        svc = get_embedding_service()
        skill_names = list(_SKILL_DESCRIPTIONS.keys())
        skill_texts = ["passage: " + _SKILL_DESCRIPTIONS[s] for s in skill_names]
        skill_vectors = await svc.embed(skill_texts)
        _SKILL_EMBEDDINGS = {name: vec for name, vec in zip(skill_names, skill_vectors)}
        logger.info("[Routing] Pre-computed %d skill embeddings", len(_SKILL_EMBEDDINGS))

        conv_vectors = await svc.embed(["passage: " + t for t in _CONVERSATIONAL_INTENT_TEXTS])
        dim = len(conv_vectors[0])
        avg = [0.0] * dim
        for v in conv_vectors:
            for i, x in enumerate(v):
                avg[i] += x
        for i in range(dim):
            avg[i] /= len(conv_vectors)
        _CONVERSATIONAL_EMBEDDING = avg
        logger.info("[Routing] Pre-computed conversational intent embedding")

        _SEMANTIC_READY = True
    except Exception as exc:
        logger.warning("[Routing] Embedding init failed, falling back to keywords: %s", exc)
        _SEMANTIC_READY = False


async def init_tool_embeddings() -> None:
    """Pre-compute embeddings for system tool descriptions.

    Called once at bot startup (main.py), after probe_llm_until_ready succeeds.
    Safe to call multiple times.
    """
    global _TOOL_EMBEDDINGS, _TOOL_SEMANTIC_READY
    if _TOOL_SEMANTIC_READY:
        return

    try:
        from services.embedding_service import get_embedding_service
        from services.tools.descriptions import TOOL_DESCRIPTIONS as _TOOL_DESCRIPTIONS

        svc = get_embedding_service()
        tool_names = list(_TOOL_DESCRIPTIONS.keys())
        tool_texts = ["passage: " + _TOOL_DESCRIPTIONS[t] for t in tool_names]
        tool_vectors = await svc.embed(tool_texts)
        _TOOL_EMBEDDINGS = {name: vec for name, vec in zip(tool_names, tool_vectors)}
        logger.info("[Routing] Pre-computed %d tool embeddings", len(_TOOL_EMBEDDINGS))

        _TOOL_SEMANTIC_READY = True
    except Exception as exc:
        logger.warning(
            "[Routing] Tool embedding init failed, falling back to keyword filtering: %s",
            exc,
        )
        _TOOL_SEMANTIC_READY = False
