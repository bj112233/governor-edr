# services/news_ai/single.py
"""Per-item LLM calls — receive bridge as injected param."""

import logging
from typing import Optional

from services.thinking_parser import strip_thinking_content

from ._security import FIREWALL_DIRECTIVE, sanitize, wrap_untrusted_block

logger = logging.getLogger(__name__)

# ── A-1: Short-circuit threshold — RSS summaries under this are already concise ──
_RSS_SUMMARY_SHORTCIRCUIT_CHARS = 500

# ── A-2: Deterministic sentiment lexicon (cyber/security news domain) ──
_POSITIVE_WORDS = frozenset({
    "surge", "gain", "rise", "boost", "recover", "improve", "success",
    "secure", "patch", "fix", "protect", "defend", "upgrade", "growth",
    "profit", "win", "resolve", "mitigate", "strengthen", "approve",
})
_NEGATIVE_WORDS = frozenset({
    "breach", "attack", "fall", "loss", "leak", "hack", "exploit",
    "vulnerability", "malware", "ransomware", "threat", "compromise",
    "expose", "steal", "inject", "phishing", "drop", "crash", "fail",
    "outage", "critical", "severe", "weaponize", "target", "victim",
})


def _classify_sentiment_deterministic(title: str, text: str) -> str | None:
    """Keyword-based sentiment — returns 'positive'/'negative'/'neutral' or None (ambiguous → LLM)."""
    combined = (title + " " + text).lower()
    tokens = set(combined.split())
    pos = len(tokens & _POSITIVE_WORDS)
    neg = len(tokens & _NEGATIVE_WORDS)
    if pos > neg and pos > 0:
        return "positive"
    if neg > pos and neg > 0:
        return "negative"
    if pos > 0 and neg == pos:
        return "neutral"
    return None


async def summarize_article(title: str, summary_or_text: str, bridge) -> str | None:
    """Summarize a single article into 1-3 sentences. Returns None on failure."""
    if not summary_or_text.strip():
        return None
    # A-1: RSS feeds already provide concise summaries — skip LLM for short text.
    stripped = summary_or_text.strip()
    if len(stripped) < _RSS_SUMMARY_SHORTCIRCUIT_CHARS:
        return stripped
    safe_title = sanitize(title)
    safe_text = sanitize(summary_or_text[:1200])
    untrusted = wrap_untrusted_block(f"Title: {safe_title}\nText: {safe_text}")
    prompt = (
        "Summarize the following news article in 1-3 concise sentences. "
        "Use the language of the original text. Be factual and neutral.\n\n"
        f"{untrusted}"
    )
    try:
        result = await bridge.complete(
            system_prompt="You are a precise news summarizer." + FIREWALL_DIRECTIVE,
            user_input=prompt,
            temperature=0.2,
            max_tokens=250,
            timeout=20.0,
        )
        if result:
            return result.strip()
    except Exception as exc:
        logger.debug("[NewsAI] summarize_article failed: %s", exc)
    return None


async def batch_summarize(items: list[dict], bridge, max_workers: int = 1) -> list[str | None]:
    """Summarize multiple articles in parallel (capped concurrency)."""
    import asyncio

    if not items:
        return []
    semaphore = asyncio.Semaphore(max_workers)

    async def _one(it: dict) -> str | None:
        async with semaphore:
            text = it.get("full_text", "") or it.get("summary", "")
            return await summarize_article(it.get("title", ""), text, bridge)

    return await asyncio.gather(*[_one(it) for it in items])


async def classify_sentiment(title: str, text: str, bridge) -> str:
    """Classify sentiment as positive / negative / neutral / unknown."""
    # A-2: Try deterministic keyword-based classifier first (zero GPU cost).
    deterministic = _classify_sentiment_deterministic(title, text)
    if deterministic is not None:
        return deterministic
    safe_title = sanitize(title)
    safe_text = sanitize(text[:500])
    untrusted = wrap_untrusted_block(f"Headline: {safe_title}\nSummary: {safe_text}")
    prompt = (
        "Classify the sentiment of this news headline+summary as exactly one word: "
        "positive, negative, neutral. Reply with only that single word.\n\n"
        f"{untrusted}"
    )
    try:
        result = await bridge.complete(
            system_prompt="You are a sentiment classifier. Reply with one word only." + FIREWALL_DIRECTIVE,
            user_input=prompt,
            temperature=0.0,
            max_tokens=10,
            timeout=10.0,
        )
        if result:
            clean = result.strip().lower().rstrip(".")
            if clean in ("positive", "negative", "neutral"):
                return clean
    except Exception as exc:
        logger.debug("[NewsAI] classify_sentiment failed: %s", exc)
    return "unknown"


async def batch_sentiment(items: list[dict], bridge, max_workers: int = 3) -> list[str]:
    """Classify sentiment for multiple articles in parallel."""
    import asyncio

    if not items:
        return []
    semaphore = asyncio.Semaphore(max_workers)

    async def _one(it: dict) -> str:
        async with semaphore:
            text = it.get("full_text", "") or it.get("summary", "")
            return await classify_sentiment(it.get("title", ""), text, bridge)

    return await asyncio.gather(*[_one(it) for it in items])


async def llm_categorize(title: str, text: str, bridge, categories: list[str]) -> str | None:
    """Zero-shot categorization into one of the provided categories."""
    if not categories:
        return None
    cat_list = ", ".join(categories)
    safe_title = sanitize(title)
    safe_text = sanitize(text[:800])
    untrusted = wrap_untrusted_block(f"Title: {safe_title}\nText: {safe_text}")
    prompt = (
        f"Categorize this news article into exactly one of these categories: {cat_list}. "
        "Reply with only the category name, nothing else.\n\n"
        f"{untrusted}"
    )
    try:
        result = await bridge.complete(
            system_prompt="You are a news categorizer. Reply with one category name only." + FIREWALL_DIRECTIVE,
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
    except Exception as exc:
        logger.debug("[NewsAI] llm_categorize failed: %s", exc)
    return None


async def summarize_cluster(cluster_articles: list[dict], bridge) -> str | None:
    """Summarize a cluster of related articles: 1 headline + 2 bullet insights."""
    if not cluster_articles:
        return None
    lines = []
    for a in cluster_articles:
        title = sanitize(a.get("title", "").strip())
        summary = sanitize(a.get("summary", "").strip())
        if title:
            lines.append(f"- {title}")
        if summary:
            lines.append(f"  {summary[:200]}")
    untrusted = wrap_untrusted_block("\n".join(lines[:10]))
    prompt = (
        "You are a tactical news analyst. Based on the following related articles, "
        "provide a concise summary. You MUST reply in Hebrew (keep cyber/tech terms in English).\n"
        "Do NOT include prefixes like 'Headline:' or 'Summary:'.\n"
        "Format your response EXACTLY like this (3 lines total):\n"
        "[A single clear headline, max 10 words]\n"
        "• [First key insight, max 10 words]\n"
        "• [Second key insight, max 10 words]\n\n"
        f"Articles:\n{untrusted}"
    )
    try:
        result = await bridge.complete(
            system_prompt=(
                "You are a tactical intelligence summarizer. "
                "Do NOT include any thinking blocks or internal reasoning. "
                "Output strictly in the requested format." + FIREWALL_DIRECTIVE
            ),
            user_input=prompt,
            temperature=0.2,
            max_tokens=512,
            timeout=20.0,
        )
        if not result:
            return None
        cleaned = strip_thinking_content(result)
        if " thinking" in cleaned and "done" not in cleaned.lower():
            cleaned = cleaned.split(" thinking", 1)[0]
        cleaned = cleaned.strip()
        return cleaned or None
    except Exception as exc:
        logger.debug("[NewsAI] summarize_cluster failed: %s", exc)
    return None
