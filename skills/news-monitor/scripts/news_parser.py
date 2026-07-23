"""News Monitor — Data Transformation Layer.

Categorization, keyword filtering, text normalization.
No I/O, no rendering, no embeddings.
"""

from __future__ import annotations

import logging
import re

from _news_utils import Article

logger = logging.getLogger(__name__)

# Regex cache for keyword word-boundary matching (compiled once per unique keyword)
_keyword_pattern_cache: dict[str, re.Pattern] = {}


def _get_keyword_pattern(kw: str) -> re.Pattern:
    """Compile and cache regex pattern for a keyword (once per process)."""
    if kw not in _keyword_pattern_cache:
        _keyword_pattern_cache[kw] = re.compile(
            r"\b" + re.escape(kw) + r"\b", re.IGNORECASE
        )
    return _keyword_pattern_cache[kw]


# ── Rule-based Categorization ──

_CATEGORY_RULES: list[tuple[str, list[str]]] = [
    (
        "cyber",
        [
            "cyber",
            "ransomware",
            "malware",
            "phishing",
            "exploit",
            "vulnerab",
            "CVE-",
            "0day",
            "zero-day",
            "סייבר",
            "פריצה",
            "כופר",
            "תוקף",
            "פגיעות",
        ],
    ),
    (
        "ai",
        [
            "openai",
            "anthropic",
            "gemini",
            "llama",
            "GPT-",
            "AI ",
            "LLM",
            "machine learning",
            "neural",
            "בינה מלאכותית",
            "מודל שפה",
        ],
    ),
    (
        "finance",
        [
            "stock",
            "market",
            "Nasdaq",
            "S&P",
            "dow ",
            "earnings",
            "inflation",
            "fed ",
            "rate hike",
            "בורסה",
            "מניה",
            "ריבית",
            "אינפלציה",
        ],
    ),
    (
        "politics",
        [
            "knesset",
            "election",
            "minister",
            "כנסת",
            "ממשלה",
            "שר ",
            "ראש הממשלה",
            "בחירות",
            "מפלגה",
        ],
    ),
    (
        "security_mil",
        [
            "IDF",
            "Hamas",
            "Hezbollah",
            "missile",
            'צה"ל',
            "חמאס",
            "חיזבאללה",
            "טיל",
            "פיגוע",
            "ירי",
            "מטחים",
        ],
    ),
    (
        "health",
        [
            "covid",
            "vaccine",
            "WHO",
            "FDA approval",
            "outbreak",
            "בריאות",
            "חיסון",
            "קופת חולים",
            "וירוס",
        ],
    ),
    (
        "sports",
        [
            "league",
            "match",
            "tournament",
            "league cup",
            "ליגה",
            "טורניר",
            "כדורגל",
            "כדורסל",
            "אולימפיאדה",
        ],
    ),
    ("tech", ["startup", "release", "framework", "סטארטאפ", "טכנולוגי"]),
]


def auto_categorize(article: Article) -> Article:
    """Apply rule-based category matching to an article."""
    text = f"{article.title} {article.summary}".lower()
    for cat, kws in _CATEGORY_RULES:
        for kw in kws:
            if kw.lower() in text:
                return article.model_copy(update={"category": cat})
    return article


# ── Keyword Filtering ──


def keyword_match(articles: list[Article | dict], keywords: list[str]) -> list[Article | dict]:
    """Filter articles by keyword presence in title or summary.

    Accepts both Article objects and plain dicts (for test compatibility).
    Returns the same type as input (dict in → dict out, Article in → Article out).
    ASCII keywords use word-boundary regex (avoids 'AI' matching 'Pain').
    Non-ASCII (Hebrew, etc.) falls back to substring for compatibility.
    """
    matched: list[Article | dict] = []
    for article in articles:
        if isinstance(article, dict):
            text = f"{article.get('title', '')} {article.get('summary', '')}".lower()
        else:
            text = f"{article.title} {article.summary}".lower()
        for kw in keywords:
            kw_lower = kw.lower()
            if kw.isascii():
                pattern = _get_keyword_pattern(kw_lower)
                if pattern.search(text):
                    if isinstance(article, dict):
                        matched.append({**article, "matched": kw})
                    else:
                        matched.append(article.model_copy(update={"matched": kw}))
                    break
            else:
                if kw_lower in text:
                    if isinstance(article, dict):
                        matched.append({**article, "matched": kw})
                    else:
                        matched.append(article.model_copy(update={"matched": kw}))
                    break
    return matched


# ── Data Contract Enforcement ──


def to_articles(items: list[dict]) -> list[Article]:
    """Convert raw fetcher dicts into typed Article models."""
    return [
        Article(
            title=it.get("title", ""),
            link=it.get("link", ""),
            summary=it.get("summary", ""),
            category=it.get("category", "general"),
            published=it.get("published", ""),
            source=it.get("source", ""),
        )
        for it in items
    ]
