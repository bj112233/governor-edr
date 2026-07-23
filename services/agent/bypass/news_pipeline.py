"""News AI pipeline — fetch, dedup, cluster, summarize, format.

Extracted from bypass/news.py (SRP). Contains the multi-stage AI pipeline
that was a single E(38) CC function. Now split into 4 focused helpers.
"""

import json
import logging

from config import NEWS_MAX_ITEMS
from services.llm_bridge.bridge import LLMBridge
from services.news_ai.batch import bulk_enrich
from services.news_ai.clusters import bulk_summarize_clusters
from services.news_ai.reports import consolidate_to_report
from services.news_cluster import cluster_items
from services.skills_engine import get_skills_engine
from services.time_format import format_feed_time_short as _fmt_date

from .news import _SENTIMENT_EMOJI, _extract_full_texts, _extract_news_limit

logger = logging.getLogger(__name__)

_TOPIC_EMOJI = {
    "economy": "💰",
    "economy_il": "💰",
    "cyber": "🛡️",
    "tech_ai": "🤖",
    "tech": "💻",
    "politics": "🏛️",
    "politics_il": "🏛️",
    "security": "🔒",
    "security_mil": "🎖️",
    "health": "🏥",
    "sports": "⚽",
    "world": "🌍",
    "auto": "🚗",
    "realestate": "🏘️",
    "news_il": "📰",
}


async def fetch_and_dedup_articles(topic: str, user_question: str) -> list[dict] | None:
    """Fetch articles from news skill, dedup by link, extract full text if needed."""
    limit = _extract_news_limit(user_question) or NEWS_MAX_ITEMS
    engine = get_skills_engine()
    args_dict = {"format": "json", "config": f"config/feeds_{topic}.json", "limit": limit}
    args = json.dumps(args_dict, ensure_ascii=False, separators=(",", ":"))
    logger.info("[AGENT] News AI pipeline: topic=%s limit=%s", topic, limit)

    raw = await engine.execute("news-monitor", topic, args)
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning("[AGENT] News skill returned non-JSON: %s", e)
        return None

    articles = data if isinstance(data, list) else data.get("articles", [])
    if not articles:
        logger.warning("[AGENT] News skill returned empty article list")
        return None

    seen_links: set[str] = set()
    unique_articles: list[dict] = []
    for a in articles:
        link = a.get("link", "")
        if link and link in seen_links:
            continue
        if link:
            seen_links.add(link)
        unique_articles.append(a)

    logger.info("[AGENT] Fetched %d articles, %d unique", len(articles), len(unique_articles))
    unique_articles = unique_articles[:limit]

    short_summary_count = sum(1 for a in unique_articles if len(a.get("summary", "")) < 200)
    if short_summary_count >= 3:
        logger.info("[AGENT] Extracting full text for %d articles", len(unique_articles))
        try:
            await _extract_full_texts(unique_articles)
        except Exception as exc:
            logger.debug("[AGENT] Full-text extraction failed, continuing without: %s", exc)

    return unique_articles


async def cluster_and_summarize(
    unique_articles: list[dict], topic: str, bridge: LLMBridge
) -> tuple[list, list[str | None], list[str], str | None]:
    """Cluster articles, summarize, enrich sentiments, build unified report."""
    clusters = await cluster_items(unique_articles, bridge, threshold=0.86)
    logger.info("[AGENT] Formed %d story clusters", len(clusters))

    cluster_summaries: list[str | None] = []
    cluster_sentiments: list[str] = []
    if clusters:
        cluster_summaries = await bulk_summarize_clusters(clusters, bridge)
        sentinel_articles = [
            next((a for a in c if a.get("full_text") or a.get("summary")), c[0] if c else {}) for c in clusters
        ]
        enriched = await bulk_enrich(sentinel_articles, bridge, batch_size=15)
        cluster_sentiments = [e.get("sentiment", "unknown") for e in enriched]

    unified_report = None
    if len(clusters) > 1 and cluster_summaries:
        unified_report = await consolidate_to_report(
            [s for s in cluster_summaries if s],
            cluster_sentiments,
            topic,
            bridge,
        )

    return clusters, cluster_summaries, cluster_sentiments, unified_report


def _format_cluster_header(cluster, summary, sentiment, emoji, sent_emoji) -> list[str]:
    """Format the cluster header (headline from summary or first article)."""
    first = cluster[0]
    if summary:
        summary_lines = summary.split("\n")
        clean_headline = summary_lines[0].replace("Headline:", "").replace("כותרת:", "").strip()
        header = [f"{emoji} {sent_emoji} *{clean_headline}*"]
        for bullet in summary_lines[1:]:
            if bullet.strip():
                header.append(bullet.strip())
        return header
    headline = first.get("title", "סיפור חדשות")
    return [f"{emoji} {sent_emoji} *{headline}*"]


def _format_article_entry(a: dict) -> str | None:
    """Format a single article as markdown lines. Returns None if no title."""
    title = a.get("title", "").strip()
    if not title:
        return None
    link = a.get("link", "").strip()
    source = a.get("source", "").strip()
    date_raw = a.get("published", "").strip()
    parts = [f"🔹 {title}"]
    if link:
        parts.append(f"🔗 {link}")
    meta_parts = []
    if source:
        meta_parts.append(source)
    date_fmt = _fmt_date(date_raw)
    if date_fmt:
        meta_parts.append(date_fmt)
    if meta_parts:
        parts.append(f"_{' · '.join(meta_parts)}_")
    return "\n".join(parts)


def format_news_report(
    unique_articles: list[dict],
    clusters: list,
    cluster_summaries: list[str | None],
    cluster_sentiments: list[str],
    unified_report: str | None,
    topic: str,
) -> str:
    """Format the final news report as markdown."""
    lines = [f"📰 *{len(unique_articles)} כתבות ב-{len(clusters)} סיפורים*\n"]

    if unified_report:
        lines.append("📋 *סיכום כללי:*")
        lines.append(unified_report)
        lines.append("")
        lines.append("---")
        lines.append("")

    for cluster, summary, sentiment in zip(clusters, cluster_summaries, cluster_sentiments):
        if not cluster:
            continue
        cat = cluster[0].get("category", "").lower()
        emoji = _TOPIC_EMOJI.get(cat) or _TOPIC_EMOJI.get(topic) or "📰"
        sent_emoji = _SENTIMENT_EMOJI.get(sentiment, "⚪")

        lines.extend(_format_cluster_header(cluster, summary, sentiment, emoji, sent_emoji))

        for a in cluster:
            entry = _format_article_entry(a)
            if entry:
                lines.append(entry)
        lines.append("")

    return "\n".join(lines)


async def ai_news_pipeline(topic: str, user_question: str) -> str | None:
    """Full AI pipeline: fetch → dedup → extract → embed → cluster → summarize → format."""
    unique_articles = await fetch_and_dedup_articles(topic, user_question)
    if not unique_articles:
        return None

    bridge = LLMBridge.get_instance()
    clusters, cluster_summaries, cluster_sentiments, unified_report = await cluster_and_summarize(
        unique_articles, topic, bridge
    )

    return format_news_report(unique_articles, clusters, cluster_summaries, cluster_sentiments, unified_report, topic)
