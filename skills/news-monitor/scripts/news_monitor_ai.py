"""News Monitor — AI enrichment stage.

Summarization, sentiment scoring, LLM categorization, and clustering.
All AI features are optional and degrade gracefully when news_ai is absent.
"""

from __future__ import annotations

import json
import logging

from _news_utils import Article, NewsMonitorArgs
from news_analyzer import cluster_articles

logger = logging.getLogger(__name__)


def needs_ai(args: NewsMonitorArgs) -> bool:
    """Whether any AI-driven feature is requested."""
    return bool(
        args.summarize or args.sentiment or args.llm_categorize or args.cluster
    )


def needs_llm_enrich(args: NewsMonitorArgs) -> bool:
    """Whether per-article LLM enrichment (summarize/sentiment/llm_categorize)."""
    return bool(args.summarize or args.sentiment or args.llm_categorize)


async def run_llm_enrichment(
    args: NewsMonitorArgs, articles: list[Article], news_ai
) -> None:
    """Apply summarize / sentiment / LLM categorize (mutates in place)."""
    if args.summarize:
        await _apply_summaries(articles, news_ai)
    if args.sentiment:
        await _apply_sentiments(articles, news_ai)
    if args.llm_categorize and args.config:
        await _apply_llm_categorize(args, articles, news_ai)


async def _apply_summaries(articles: list[Article], news_ai) -> None:
    summaries = await news_ai.batch_summarize(
        [a.model_dump() for a in articles], bridge=None, max_workers=3
    )
    if not summaries:
        return
    for art, s in zip(articles, summaries):
        if s:
            art.ai_summary = s


async def _apply_sentiments(articles: list[Article], news_ai) -> None:
    sentiments = await news_ai.batch_sentiment(
        [a.model_dump() for a in articles], bridge=None, max_workers=3
    )
    if not sentiments:
        return
    for art, s in zip(articles, sentiments):
        if s:
            art.sentiment = s


async def _apply_llm_categorize(
    args: NewsMonitorArgs, articles: list[Article], news_ai
) -> None:
    categories = _load_categories(args)
    if not categories:
        return
    for art in articles:
        cat = await news_ai.llm_categorize(
            art.title,
            art.full_text or art.summary,
            bridge=None,
            categories=categories,
        )
        if cat:
            art.category = cat


def _load_categories(args: NewsMonitorArgs) -> list[str]:
    """Read distinct feed categories from the config file."""
    try:
        with open(args.config, encoding="utf-8") as f:
            cfg_cats = json.load(f)
    except Exception as exc:
        logger.debug("[NewsMonitor] LLM categorize failed: %s", exc)
        return []
    return list({f.get("category", "general") for f in cfg_cats.get("feeds", [])})


async def run_clustering(
    args: NewsMonitorArgs, articles: list[Article], news_ai
) -> list[Article]:
    """Stage 8: cluster articles; optionally summarize cluster headlines."""
    if not (args.cluster and articles):
        return articles
    clusters = await cluster_articles(articles, args.cluster_threshold)
    if args.summarize and news_ai is not None:
        return await _summarized_clusters(clusters, news_ai)
    return _flatten_clusters(clusters)


def _flatten_clusters(clusters: list[list[Article]]) -> list[Article]:
    flat: list[Article] = []
    for c in clusters:
        flat.extend(c)
    return flat


async def _summarized_clusters(
    clusters: list[list[Article]], news_ai
) -> list[Article]:
    headlines: list[str] = []
    for c in clusters:
        headline = await news_ai.summarize_cluster(
            [a.model_dump() for a in c], bridge=None
        )
        headlines.append(headline or c[0].title)
    articles: list[Article] = []
    for ci, c in enumerate(clusters):
        articles.append(
            Article(
                title=headlines[ci],
                link=c[0].link,
                published=c[0].published,
                summary="",
                ai_summary="; ".join(
                    [f"📰 {a.source}: {a.title}" for a in c]
                )[:500],
                sentiment=c[0].sentiment,
                category=c[0].category,
            )
        )
    return articles
