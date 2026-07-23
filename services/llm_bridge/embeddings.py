# services/llm_bridge/embeddings.py
"""Embedding calls — stateless worker receiving client + CB."""

import asyncio
import logging

import httpx
import openai

from config import EMBEDDING_MODEL, LLM_RETRY_ATTEMPTS
from services.telemetry import get_telemetry

from .models import ContextOverflowError, _is_context_overflow

logger = logging.getLogger(__name__)


async def embed(
    client: openai.AsyncOpenAI,
    texts: list[str],
    embed_cb,
    semaphore: asyncio.Semaphore,
) -> list[list[float]]:
    """Create embeddings via the local embedding model (isolated CB)."""
    # Promote OPEN -> HALF_OPEN once cooldown elapsed
    if embed_cb.state == "open":
        embed_cb.promote_half_open()
        if embed_cb.state == "open":
            raise openai.APIConnectionError(
                message="[Bridge] Embedding circuit open — endpoint unavailable.",
                request=httpx.Request("POST", ""),
            )

    last_exc: Exception = RuntimeError("No embedding attempts made.")
    for attempt in range(1, LLM_RETRY_ATTEMPTS + 1):
        try:
            async with semaphore:
                async with get_telemetry().measure_llm("embed", EMBEDDING_MODEL):
                    response = await client.embeddings.create(
                        model=EMBEDDING_MODEL,
                        input=texts,
                    )
                vectors = [d.embedding for d in response.data]
            embed_cb.on_success()
            logger.debug(
                "[Bridge] embed() -> %d vectors, dim=%d",
                len(vectors),
                len(vectors[0]) if vectors else 0,
            )
            return vectors
        except openai.BadRequestError as exc:
            if _is_context_overflow(exc):
                logger.warning("[Bridge] embed() context_length_exceeded: %s", exc)
                raise ContextOverflowError(str(exc)) from exc
            logger.error("[Bridge] embed() bad request: %s", exc)
            raise
        except (
            TimeoutError,
            openai.APIConnectionError,
            openai.APITimeoutError,
            openai.APIStatusError,
            httpx.ConnectError,
            httpx.ReadTimeout,
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
        ) as exc:
            last_exc = exc
            embed_cb.on_failure()
            backoff = 2**attempt
            logger.warning(
                "[Bridge] embed() attempt %d/%d failed: %s. Backoff %ds.",
                attempt,
                LLM_RETRY_ATTEMPTS,
                exc,
                backoff,
            )
            if attempt < LLM_RETRY_ATTEMPTS:
                await asyncio.sleep(backoff)
    raise last_exc
