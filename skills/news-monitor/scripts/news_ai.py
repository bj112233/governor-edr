# skills/news-monitor/scripts/news_ai.py
"""AI helpers for the news pipeline — summarization, sentiment, categorization.

All functions return None on LLM failure for graceful fallback.
When `bridge` is None, falls back to direct local LLM API call.
"""

import asyncio
import logging
import os
from typing import Any, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5001/v1")
_LM_CHAT_URL = f"{_LLM_API_BASE}/chat/completions"
_LM_MODEL = os.getenv("LLM_MODEL", "")
# Sampling aligned with the main bridge (Qwen3.5 Instruct, non-thinking).
_LM_TOP_P = float(os.getenv("LLM_TOP_P", "0.8"))
_LM_TOP_K = int(os.getenv("LLM_TOP_K", "20"))
_LM_PRESENCE_PENALTY = float(os.getenv("LLM_PRESENCE_PENALTY", "0.0"))


async def _llm_chat_async(
    system_prompt: str,
    user_input: str,
    temperature: float = 0.1,
    max_tokens: int = 2000,
    timeout: float = 20.0,
) -> Optional[str]:
    """Async chat via local LLM API using aiohttp."""
    payload: dict[str, Any] = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input},
        ],
        "temperature": temperature,
        "top_p": _LM_TOP_P,
        "top_k": _LM_TOP_K,
        "presence_penalty": _LM_PRESENCE_PENALTY,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    if _LM_MODEL:
        payload["model"] = _LM_MODEL

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                _LM_CHAT_URL,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers={"Content-Type": "application/json"},
            ) as response:
                response.raise_for_status()
                data = await response.json()
                return data["choices"][0]["message"]["content"]
    except Exception as exc:
        logger.debug("[NewsAI] _llm_chat_async failed: %s", exc)
    return None


def _call_llm(
    bridge,
    system_prompt: str,
    user_input: str,
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> Optional[str]:
    """Dispatch to bridge or direct API."""
    if bridge is not None:
        import asyncio

        try:
            return asyncio.get_event_loop().run_until_complete(
                bridge.complete(
                    system_prompt=system_prompt,
                    user_input=user_input,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=timeout,
                )
            )
        except Exception as exc:
            logger.debug("[NewsAI] bridge.complete failed: %s", exc)
            return None
    try:
        return asyncio.get_event_loop().run_until_complete(
            _llm_chat_async(system_prompt, user_input, temperature, max_tokens, timeout)
        )
    except Exception as exc:
        logger.debug("[NewsAI] _llm_chat_async sync fallback failed: %s", exc)
        return None


async def _call_llm_async(
    bridge,
    system_prompt: str,
    user_input: str,
    temperature: float,
    max_tokens: int,
    timeout: float,
) -> Optional[str]:
    """Async dispatcher — bridge.complete if bridge provided, else local LLM async."""
    if bridge is not None:
        try:
            return await bridge.complete(
                system_prompt=system_prompt,
                user_input=user_input,
                temperature=temperature,
                max_tokens=max_tokens,
                timeout=timeout,
            )
        except Exception as exc:
            logger.debug("[NewsAI] bridge.complete failed: %s", exc)
            return None
    return await _llm_chat_async(
        system_prompt, user_input, temperature, max_tokens, timeout
    )


async def summarize_article(title: str, summary_or_text: str, bridge) -> Optional[str]:
    """Summarize a single article into 1-3 sentences. Returns None on failure."""
    if not summary_or_text.strip():
        return None

    prompt = (
        "Summarize the following news article in 1-3 concise sentences. "
        "Use the language of the original text. Be factual and neutral.\n\n"
        f"Title: {title}\n"
        f"Text: {summary_or_text[:1200]}"
    )

    result = await _call_llm_async(
        bridge,
        system_prompt="You are a precise news summarizer.",
        user_input=prompt,
        temperature=0.2,
        max_tokens=250,
        timeout=20.0,
    )
    return result.strip() if result else None


async def batch_summarize(
    items: List[dict], bridge, max_workers: int = 3
) -> List[Optional[str]]:
    """Summarize multiple articles in parallel (capped concurrency)."""
    if not items:
        return []

    semaphore = asyncio.Semaphore(max_workers)

    async def _one(it: dict) -> Optional[str]:
        async with semaphore:
            text = it.get("full_text", "") or it.get("summary", "")
            return await summarize_article(it.get("title", ""), text, bridge)

    return await asyncio.gather(*[_one(it) for it in items])


async def classify_sentiment(title: str, text: str, bridge) -> str:
    """Classify sentiment as positive / negative / neutral / unknown.
    Returns 'unknown' on LLM failure."""
    prompt = (
        "Classify the sentiment of this news headline+summary as exactly one word: "
        "positive, negative, neutral. Reply with only that single word.\n\n"
        f"Headline: {title}\n"
        f"Summary: {text[:500]}"
    )

    result = await _call_llm_async(
        bridge,
        system_prompt="You are a sentiment classifier. Reply with one word only.",
        user_input=prompt,
        temperature=0.0,
        max_tokens=10,
        timeout=10.0,
    )
    if result:
        clean = result.strip().lower().rstrip(".")
        if clean in ("positive", "negative", "neutral"):
            return clean
    return "unknown"


async def batch_sentiment(items: List[dict], bridge, max_workers: int = 3) -> List[str]:
    """Classify sentiment for multiple articles in parallel."""
    if not items:
        return []

    semaphore = asyncio.Semaphore(max_workers)

    async def _one(it: dict) -> str:
        async with semaphore:
            text = it.get("full_text", "") or it.get("summary", "")
            return await classify_sentiment(it.get("title", ""), text, bridge)

    return await asyncio.gather(*[_one(it) for it in items])


async def llm_categorize(
    title: str, text: str, bridge, categories: List[str]
) -> Optional[str]:
    """Zero-shot categorization into one of the provided categories.
    Returns None on failure or if category is not in the allowed list."""
    if not categories:
        return None

    cat_list = ", ".join(categories)
    prompt = (
        f"Categorize this news article into exactly one of these categories: {cat_list}. "
        "Reply with only the category name, nothing else.\n\n"
        f"Title: {title}\n"
        f"Text: {text[:800]}"
    )

    result = await _call_llm_async(
        bridge,
        system_prompt="You are a news categorizer. Reply with one category name only.",
        user_input=prompt,
        temperature=0.1,
        max_tokens=20,
        timeout=10.0,
    )
    if result:
        clean = result.strip().lower().rstrip(".")
        allowed = {c.lower() for c in categories}
        if clean in allowed:
            for c in categories:
                if c.lower() == clean:
                    return c
    return None


async def summarize_cluster(cluster_articles: List[dict], bridge) -> Optional[str]:
    """Summarize a cluster of related articles into one story headline."""
    if not cluster_articles:
        return None

    lines = []
    for a in cluster_articles:
        title = a.get("title", "").strip()
        summary = a.get("summary", "").strip()
        if title:
            lines.append(f"- {title}")
        if summary:
            lines.append(f"  {summary[:200]}")

    prompt = (
        "The following are headlines about the same news story. "
        "Write a single concise headline (max 10 words) that captures the core story. "
        "Use the language of the headlines.\n\n"
        + "\n".join(lines[:10])  # cap to avoid token bloat
    )

    result = await _call_llm_async(
        bridge,
        system_prompt="You are a news editor writing concise headlines.",
        user_input=prompt,
        temperature=0.2,
        max_tokens=80,
        timeout=15.0,
    )
    return result.strip() if result else None
