# services/news_ai/batch.py
"""Bulk enrich orchestrator — controls LLM call concurrency.

Refactored (Phase 2): separates summary I/O, sentiment I/O, and merge logic.
"""

import logging

from services.thinking_parser import strip_thinking_content

from ._security import FIREWALL_DIRECTIVE
from .prompts import (
    build_bulk_sentiment_prompt,
    build_bulk_summarize_prompt,
    parse_bulk_sentiment,
    parse_bulk_summarize,
)

logger = logging.getLogger(__name__)


async def _enrich_summaries(batch: list[dict], bridge, timeout: float) -> list[str]:
    """LLM I/O: bulk summarize one batch."""
    try:
        raw = await bridge.complete(
            system_prompt=(
                "You are a strict Hebrew news summarizer. Reply ONLY in Hebrew, "
                "using the numbered format requested. No markdown headers, no English." + FIREWALL_DIRECTIVE
            ),
            user_input=build_bulk_summarize_prompt(batch),
            temperature=0.2,
            max_tokens=min(3072, len(batch) * 80),
            timeout=timeout,
        )
        response = strip_thinking_content(raw or "")
        if not response.strip():
            response = raw or ""
        return parse_bulk_summarize(response, len(batch), batch)
    except Exception as exc:
        logger.warning("[NewsAI] bulk summarize batch failed: %s", exc)
        return [""] * len(batch)


async def _enrich_sentiments(batch: list[dict], bridge, timeout: float) -> list[str]:
    """LLM I/O: bulk sentiment-classify one batch."""
    try:
        raw = await bridge.complete(
            system_prompt=(
                "You are a bulk sentiment classifier. For EACH numbered item, "
                "reply with EXACTLY one English word: positive, negative, or neutral. "
                "Output one line per item, numbered to match the input." + FIREWALL_DIRECTIVE
            ),
            user_input=build_bulk_sentiment_prompt(batch),
            temperature=0.0,
            max_tokens=min(2048, len(batch) * 10),
            timeout=timeout,
        )
        response = strip_thinking_content(raw or "")
        if not response.strip():
            response = raw or ""
        return parse_bulk_sentiment(response, len(batch))
    except Exception as exc:
        logger.warning("[NewsAI] bulk sentiment batch failed: %s", exc)
        return ["unknown"] * len(batch)


def _merge_batch(summaries: list[str], sentiments: list[str]) -> list[dict]:
    """Pure: zip summaries + sentiments into result dicts."""
    return [{"summary": s, "sentiment": sent} for s, sent in zip(summaries, sentiments)]


async def bulk_enrich(items: list[dict], bridge, batch_size: int = 15, timeout: float = 45.0) -> list[dict]:
    """Enrich many items with summary + sentiment using TWO bulk LLM prompts per batch.

    Split into separate summary-only and sentiment-only calls to keep each
    prompt simple and avoid thinking-token bloat that exhausts max_tokens.

    Returns list of dicts with keys 'summary' and 'sentiment'.
    """
    if not items:
        return []

    results: list[dict] = []
    for start in range(0, len(items), batch_size):
        batch = items[start : start + batch_size]
        summaries = await _enrich_summaries(batch, bridge, timeout)
        sentiments = await _enrich_sentiments(batch, bridge, timeout)
        results.extend(_merge_batch(summaries, sentiments))
        logger.info(
            "[NewsAI] bulk_enrich batch=%d/%d summaries=%d sentiments=%d",
            len(batch),
            len(items),
            sum(1 for s in summaries if s),
            sum(1 for s in sentiments if s != "unknown"),
        )

    return results
