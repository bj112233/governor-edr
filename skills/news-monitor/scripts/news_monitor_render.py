"""News Monitor — Render stage.

Field sanitization and output rendering (file or stdout). Pure
transformation — no I/O beyond the final write.
"""

from __future__ import annotations

import logging

from _news_utils import Article, NewsMonitorArgs, _sanitize_text
from news_renderer import format_json, format_md

logger = logging.getLogger(__name__)


def sanitize_articles(articles: list[Article]) -> list[Article]:
    """Stage 9a: strip control chars from every text field before render."""
    safe_articles: list[Article] = []
    for art in articles:
        safe_articles.append(
            Article(
                title=_sanitize_text(art.title),
                link=_sanitize_text(art.link),
                summary=_sanitize_text(art.summary),
                category=_sanitize_text(art.category),
                published=_sanitize_text(art.published),
                source=_sanitize_text(art.source),
                matched=_sanitize_text(art.matched),
                sentiment=_sanitize_text(art.sentiment),
                ai_summary=_sanitize_text(art.ai_summary),
            )
        )
    return safe_articles


def render_output(args: NewsMonitorArgs, articles: list[Article]) -> None:
    """Stage 9b: write rendered output to file or stdout."""
    text = format_json(articles) if args.format == "json" else format_md(articles)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        logger.info("Saved %d items to %s", len(articles), args.output)
    else:
        logger.info("Output:\n%s", text)
