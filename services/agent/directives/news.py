# services/agent/directives/news.py
"""News skill routing directive — registers itself with the registry."""

from __future__ import annotations

from typing import Any, Optional

from services.agent.bypass.news import _detect_news_topic
from services.agent.directives.registry import directive_registry

_NEWS_TOOL_NAMES = {"skill_news-monitor", "skill_news_monitor"}


def _news_directive(user_question: str, context: dict[str, Any]) -> str | None:
    """Force the LLM to call the news skill verbatim and preserve `[title](URL)`.

    Only fires when:
    1. The user question is detected as a news/headlines request, AND
    2. The news skill tool is currently in the active tool set
       (otherwise the directive would dangle on a tool that does not exist).
    """
    active: set = context.get("active_tool_names", set())
    if not (active & _NEWS_TOOL_NAMES):
        return None
    topic = _detect_news_topic(user_question)
    if not topic:
        return None
    return (
        f"[ROUTING DIRECTIVE — MUST FOLLOW]: This is a news/headlines request.\n"
        f'STEP 1: Call skill_news-monitor with command="{topic}".\n'
        f"STEP 2: Copy-paste the tool's return value VERBATIM to the user. "
        f"The tool returns Markdown like `- [title](URL)` — you MUST preserve "
        f"the full `[title](URL)` syntax. Dropping the `(URL)` part or "
        f'replacing it with quotes like `"title"` is FORBIDDEN. '
        f"Every headline MUST have a clickable link.\n"
        f"STEP 3: Do NOT reformat dates, do NOT translate titles, do NOT "
        f"summarize. Do NOT answer from memory. Do NOT invent headlines. "
        f"If the tool returns nothing, reply 'אין לי מידע עדכני על זה כרגע.'"
    )


directive_registry.register("news", _news_directive, priority=10)
