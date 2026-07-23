# services/agent/bypass/news.py
"""News bypass router — thin layer that detects news requests and delegates to news-monitor skill."""

import asyncio
import json
import logging
import re
from pathlib import Path

from config import NEWS_MAX_ITEMS
from services.bot_memory import async_store_conversation
from services.llm_bridge.bridge import LLMBridge
from services.llm_bridge.models import _STATE_OPEN
from services.news_ai.batch import bulk_enrich
from services.news_ai.clusters import bulk_summarize_clusters
from services.news_ai.reports import consolidate_to_report
from services.news_cluster import cluster_items
from services.skills_engine import get_skills_engine
from services.time_format import format_feed_time_short as _fmt_date

logger = logging.getLogger(__name__)

_SENTIMENT_EMOJI = {
    "positive": "🟢",
    "negative": "🔴",
    "neutral": "⚪",
    "unknown": "⚪",
}

# Mapping of Hebrew/English keywords → skill_news-monitor command. Order
# matters: more specific topics (sports, economy, cyber) are checked before
# generic 'news' to avoid false routing.
_NEWS_TOPIC_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "sports",
        (
            "ספורט",
            "כדורגל",
            "כדורסל",
            "ליגה",
            "מכבי",
            "הפועל",
            "sport",
            "soccer",
            "basketball",
        ),
    ),
    (
        "economy_il",
        (
            "כלכלה",
            "בורסה",
            "מניות",
            'ת"א 35',
            "תא 35",
            "כלכלי",
            "economy",
            "stock market",
            "economic",
        ),
    ),
    (
        "cyber",
        ("סייבר", "אבטחה", "האקר", "פריצה", "cyber", "hack", "breach", "ransomware"),
    ),
    ("tech_ai", ("טכנולוגיה", "בינה מלאכותית", "AI", "טק", "tech", "technology")),
    (
        "security_mil",
        ("ביטחון", "בטחון", "צבא", 'צה"ל', "מלחמה", "military", "defense", "idf"),
    ),
    ("politics_il", ("פוליטיקה", "ממשלה", "כנסת", "נתניהו", "politics")),
    ("health", ("בריאות", "רפואה", "health", "medical")),
    ("auto", ("רכב", "מכונית", "auto", "car")),
    ("realestate", ('נדל"ן', "נדלן", "דירה", "real estate", "realestate")),
    (
        "world",
        ("עולם", "בינלאומי", 'ארה"ב', "ארהב", "אירופה", "world", "international"),
    ),
    ("news_il", ("חדשות", "מבזקים", "כותרות", "news", "headlines", "breaking")),
)

_HEB_WORD_NUMS: dict[str, int] = {
    "אחת": 1,
    "אחד": 1,
    "שתי": 2,
    "שתיים": 2,
    "שניים": 2,
    "שני": 2,
    "שלוש": 3,
    "שלושה": 3,
    "ארבע": 4,
    "ארבעה": 4,
    "חמש": 5,
    "חמישה": 5,
    "שש": 6,
    "שישה": 6,
    "שבע": 7,
    "שבעה": 7,
    "שמונה": 8,
    "תשע": 9,
    "תשעה": 9,
    "עשר": 10,
    "עשרה": 10,
    "חמש-עשרה": 15,
    "חמש עשרה": 15,
    "עשרים": 20,
    "שלושים": 30,
}


def _detect_news_topic(question: str) -> str | None:
    """Return the news-monitor topic command if the question is a news/headlines
    request, otherwise None. Returns the FIRST matching topic by specificity
    order — sports/economy beat generic 'חדשות'."""
    q = question.lower()
    has_news_marker = any(
        kw in q
        for kw in (
            "חדשות",
            "כותרות",
            "מבזקים",
            "כתבה",
            "כתבות",
            "תביא לי",
            "news",
            "headlines",
            "article",
            "articles",
            "מארץ",
            "מהיום",
            "מצב",
            "בישראל",
            "מה קורה",
        )
    )
    # Strong news markers OR a topic keyword that implies news context
    for topic, kws in _NEWS_TOPIC_KEYWORDS:
        for kw in kws:
            if kw.lower() in q:
                # Topic-specific keywords need a news marker too, except for
                # the obvious 'חדשות'/'כותרות' which themselves are markers.
                if topic == "news_il" or has_news_marker:
                    return topic
    return None


def _extract_news_limit(question: str) -> int | None:
    """Extract requested headline count from a user question."""
    q = question.lower()

    # 1. Sanitize format context to prevent 'אחד/אחת' from hijacking numeric extraction
    q = re.sub(r"(בלוק|הודעה|קובץ|טקסט|רשימה)\s+(אחד|אחת)", "", q)

    # 2. Extract Latin digits (Highest Priority)
    m = re.search(r"\b(\d{1,3})\b", q)
    if m:
        n = int(m.group(1))
        return max(1, min(50, n))

    # 3. Extract Hebrew word-numbers
    for word, n in sorted(_HEB_WORD_NUMS.items(), key=lambda kv: -len(kv[0])):
        if word in q:
            return max(1, min(50, n))

    # 4. Fallback: Universal 'all' ONLY if no explicit numbers were provided
    # \b in python works for Unicode words. This prevents matching 'אוכל' or 'מיכל'.
    if re.search(r"\b(כל|הכל|כולן)\b", q):
        return NEWS_MAX_ITEMS  # Assuming this constant is imported/defined

    return None


async def _call_news_skill(topic: str, user_question: str) -> str:
    """Delegate to news-monitor skill. Returns JSON or error message."""
    engine = get_skills_engine()
    limit = _extract_news_limit(user_question)
    args_dict: dict[str, str | int | None] = {"format": "json", "config": f"config/feeds_{topic}.json"}
    if limit:
        args_dict["limit"] = limit
    args = json.dumps(args_dict, ensure_ascii=False, separators=(",", ":"))
    logger.info(f"[AGENT] News bypass: topic={topic} limit={limit or 'default'}")
    try:
        result = await engine.execute("news-monitor", topic, args)
    except Exception as e:
        logger.error(f"[AGENT] News skill failed: {e}")
        return "⚠️ שירות החדשות לא זמין כרגע."
    return result or "אין לי מידע עדכני על זה כרגע."


def _format_articles_markdown(articles: list[dict], topic: str, limit: int | None) -> str:
    """Format JSON articles list as readable Markdown."""
    if not articles:
        return "אין כתבות חדשות בנושא זה כרגע."
    lines = [f"📰 *{len(articles)} כתבות בנושא {topic.replace('_', ' ')}*\n"]
    for a in articles[: limit or 10]:
        title = a.get("title", "").strip()
        link = a.get("link", "").strip()
        summary = a.get("summary", "").strip()
        source = a.get("source", "").strip()
        if title:
            lines.append(f"*{title}*")
        if summary:
            lines.append(summary[:200])
        if link:
            lines.append(f"🔗 {link}")
        if source:
            lines.append(f"_{source}_")
        lines.append("")
    return "\n".join(lines)


async def _extract_full_texts(articles: list[dict]) -> None:
    """Fetch full article text in parallel, mutating articles in-place.
    Capped at 2000 chars per article; failures leave 'full_text' as empty string."""
    import importlib.util

    script_path = Path(__file__).resolve().parents[2] / "skills" / "news-monitor" / "scripts" / "news_monitor.py"
    if not script_path.exists():
        logger.debug("[NewsBypass] news_monitor.py not found at %s", script_path)
        return

    try:
        spec = importlib.util.spec_from_file_location("news_monitor", script_path)
        if spec is None or spec.loader is None:
            return
        nm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(nm)
        fetch_article_text = nm.fetch_article_text
    except Exception as exc:
        logger.debug("[NewsBypass] Could not load fetch_article_text: %s", exc)
        return

    idx_link = [(i, a["link"]) for i, a in enumerate(articles) if a.get("link")]
    if not idx_link:
        return

    texts = await asyncio.gather(*[fetch_article_text(link) for _, link in idx_link], return_exceptions=True)
    for (idx, _), text in zip(idx_link, texts):
        if isinstance(text, Exception):
            articles[idx]["full_text"] = ""
        else:
            articles[idx]["full_text"] = str(text)[:2000] if text else ""


async def _ai_news_pipeline(topic: str, user_question: str) -> str | None:
    """Full AI pipeline: fetch → dedup → extract → embed → cluster → summarize → format."""
    from .news_pipeline import ai_news_pipeline

    return await ai_news_pipeline(topic, user_question)


async def _direct_news_bypass(topic: str, user_question: str) -> str:
    """Hybrid bypass: try AI pipeline first, fall back to raw RSS if LLM
    circuit is open or AI pipeline fails."""
    bridge = LLMBridge.get_instance()

    # Priority 1: AI pipeline (full-text → embeddings → cluster → summarize)
    if bridge.cb.state != _STATE_OPEN:
        try:
            result = await _ai_news_pipeline(topic, user_question)
            if result:
                logger.info("[AGENT] News AI pipeline completed")
                try:
                    await async_store_conversation(user_question, result)
                except Exception as e:
                    logger.debug("[AGENT] Memory storage failed (news bypass): %s", e)
                return result
        except Exception as e:
            logger.error("[AGENT] AI news pipeline failed: %s", e)

    # Priority 2: LLM circuit open or AI failed → raw RSS fallback
    result = await _call_news_skill(topic, user_question)

    if not result or result.startswith("❌"):
        return "אין לי מידע עדכני על זה כרגע."

    try:
        await async_store_conversation(user_question, result)
    except Exception as e:
        logger.debug("[AGENT] Memory storage failed (news bypass): %s", e)

    try:
        data = json.loads(result)
        articles = data.get("articles", []) if isinstance(data, dict) else data
        limit = _extract_news_limit(user_question)
        return _format_articles_markdown(articles, topic, limit)
    except Exception:
        return result
