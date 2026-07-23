"""News Monitor — scrape RSS feeds and news sites, summarize, keyword-alert.

Shim layer for backward compatibility.
All logic has been moved to the new modular architecture:
  _news_utils.py      — Pydantic models, SQLite state, text/date helpers
  news_fetcher.py     — RSS/site/article fetching (I/O)
  news_parser.py      — categorization, keyword filtering (transformation)
  news_analyzer.py    — embeddings, clustering, dedup (scoring)
  news_monitor_facade.py — orchestrator, renderer, CLI entry point
"""

from __future__ import annotations

# ── Re-export new public API from facade ──
from news_monitor_facade import (
    format_md,
    run_news_monitor,
)

# ── Re-export models for downstream imports ──
from _news_utils import (
    Article,
    NewsMonitorArgs,
    NewsMonitorResult,
    _fmt_date,
    _format_published,
    _get_db,
    _get_state,
    _is_recent,
    _sanitize_text,
    _save_state,
)
from news_analyzer import (
    _build_similarity_matrix,
    _cosine_similarity,
    _cosine_similarity_vec,
    _embed_texts,
    _hac_cluster,
    cluster_articles,
    semantic_dedup,
)
from news_fetcher import (
    fetch_article_text,
    fetch_rss,
    fetch_site,
)
from news_parser import (
    _CATEGORY_RULES,
    auto_categorize,
    keyword_match,
    to_articles,
)

# ── Backward-compat aliases ──

__all__ = [
    # CLI / facade
    "run_news_monitor",
    "format_md",
    # Models
    "Article",
    "NewsMonitorArgs",
    "NewsMonitorResult",
    # Fetcher
    "fetch_rss",
    "fetch_site",
    "fetch_article_text",
    # Parser
    "auto_categorize",
    "keyword_match",
    "to_articles",
    "_CATEGORY_RULES",
    # Analyzer
    "_embed_texts",
    "_cosine_similarity",
    "_cosine_similarity_vec",
    "_build_similarity_matrix",
    "_hac_cluster",
    "semantic_dedup",
    "cluster_articles",
    # State / utils
    "_get_db",
    "_get_state",
    "_save_state",
    "_sanitize_text",
    "_fmt_date",
    "_format_published",
    "_is_recent",
]

if __name__ == "__main__":
    import runpy
    runpy.run_module("news_monitor_facade", run_name="__main__")
