"""News Monitor — Rendering / formatting (Markdown, JSON).

Pure output formatting — no network, no state, no AI.
"""

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _news_utils import Article


_SENTIMENT_EMOJI = {
    "positive": "📈",
    "negative": "📉",
    "neutral": "➖",
    "unknown": "➖",
}


def format_md(articles: list, title: str = "News Digest") -> str:
    """Convert Articles to Markdown digest."""
    from _news_utils import _fmt_date

    lines = [f"# {title}\n"]
    for art in articles:
        if not art.title.strip():
            continue
        if art.link:
            lines.append(f"- [{art.title.strip()}]({art.link})")
        else:
            continue
        if art.published:
            lines.append(f"  - 🕒 {_fmt_date(art.published)}")
        if art.ai_summary:
            clean = _strip_html(art.ai_summary)[:300]
            if clean:
                lines.append(f"  - 🤖 {clean}")
        elif art.summary:
            clean = _strip_html(art.summary)[:300]
            if clean:
                lines.append(f"  - {clean}...")
        if art.sentiment:
            lines.append(
                f"  - {_SENTIMENT_EMOJI.get(art.sentiment, '➖')} {art.sentiment}"
            )
        if art.matched:
            lines.append(f"  - 🔑 Keyword: `{art.matched}`")
        lines.append("")
    return "\n".join(lines)


def format_json(articles: list) -> str:
    """Convert Articles to JSON string."""
    return json.dumps(
        [a.model_dump() for a in articles],
        ensure_ascii=False,
        indent=2,
        default=str,
    )


def _strip_html(text: str) -> str:
    """Remove HTML tags and collapse whitespace."""
    if not text or "<" not in text:
        return text
    no_tags = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", no_tags).strip()
