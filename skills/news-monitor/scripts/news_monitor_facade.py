"""News Monitor — Orchestrator Facade.

Coordinates: fetcher → parser → analyzer → renderer.
No business logic lives here — pure pipeline orchestration.

Stage modules:
  news_monitor_fetch.py   — raw item acquisition + full-text extraction
  news_monitor_filter.py  — dedup, categorize, keyword/alert filtering
  news_monitor_ai.py      — summarize, sentiment, LLM categorize, cluster
  news_monitor_render.py  — sanitize + render output
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
import sys
from pathlib import Path

from _news_utils import (
    Article,
    NewsMonitorArgs,
    NewsMonitorResult,
)
from news_analyzer import _embed_texts, cluster_articles, semantic_dedup
from news_fetcher import (
    fetch_article_text,
    fetch_rss,
    fetch_site,
)
from news_parser import (
    auto_categorize,
    keyword_match,
    to_articles,
)
from news_renderer import format_json, format_md

from news_monitor_ai import (
    needs_ai,
    needs_llm_enrich,
    run_clustering,
    run_llm_enrichment,
)
from news_monitor_fetch import extract_full_text, fetch_raw_items
from news_monitor_filter import (
    apply_auto_categorize,
    apply_keyword_filter,
    apply_semantic_dedup,
    dedup_by_link,
)
from news_monitor_render import render_output, sanitize_articles

logger = logging.getLogger(__name__)

# Re-export the subsystem public API so downstream code can keep importing
# canonical names from the facade. Listing them here also tells vulture these
# imports are intentional re-exports (not dead code).
__all__ = [
    # Pipeline entry point
    "run_news_monitor",
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
    # Analyzer
    "_embed_texts",
    "cluster_articles",
    "semantic_dedup",
    # Renderer
    "format_json",
    "format_md",
]


# ── Optional AI loader ──


def _load_news_ai():
    """Load optional news_ai module from the same directory."""
    path = Path(__file__).parent / "news_ai.py"
    if not path.exists():
        return None
    try:
        spec = importlib.util.spec_from_file_location("news_ai", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as exc:
        logger.debug("[NewsMonitor] Could not load news_ai: %s", exc)
        return None


# ── Orchestrator ──


async def run_news_monitor(args: NewsMonitorArgs) -> NewsMonitorResult:
    """Main pipeline: fetch → parse → analyze → render."""
    _reconfigure_stdout()
    raw_items = await fetch_raw_items(args)
    if not raw_items:
        return _empty_result()

    if args.extract:
        await extract_full_text(raw_items)

    articles = to_articles(raw_items)
    articles = dedup_by_link(articles)
    articles = await apply_semantic_dedup(args, articles)
    articles = apply_auto_categorize(args, articles)
    articles = await apply_keyword_filter(args, articles)

    news_ai = _resolve_news_ai(args, articles)
    if needs_llm_enrich(args) and articles and news_ai is not None:
        await run_llm_enrichment(args, articles, news_ai)

    articles = await run_clustering(args, articles, news_ai)

    safe_articles = sanitize_articles(articles)
    render_output(args, safe_articles)
    return NewsMonitorResult(articles=safe_articles)


def _reconfigure_stdout() -> None:
    """Force UTF-8 stdout on Windows to avoid encoding errors."""
    if sys.platform != "win32":
        return
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _empty_result() -> NewsMonitorResult:
    return NewsMonitorResult(
        articles=[
            Article(
                title="No news items found",
                link="",
                summary="The configured feeds returned no recent articles.",
            )
        ]
    )


def _resolve_news_ai(args: NewsMonitorArgs, articles: list[Article]):
    """Load news_ai only when an AI feature is requested and articles exist."""
    if not (needs_ai(args) and articles):
        return None
    news_ai = _load_news_ai()
    if news_ai is None:
        logger.warning(
            "[NewsMonitor] news_ai.py not available — skipping AI features"
        )
    return news_ai


# ── Entry Point ──


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            json.dumps(
                {"error": "Missing JSON argument. Pass a JSON string as sys.argv[1]."},
                ensure_ascii=False,
            )
        )
        sys.exit(1)

    try:
        raw = json.loads(sys.argv[1])
        args = NewsMonitorArgs(**raw)
        result = asyncio.run(run_news_monitor(args))
        print(result.model_dump_json(exclude_none=True, indent=2))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"Invalid JSON: {exc}"}, ensure_ascii=False))
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        sys.exit(1)
