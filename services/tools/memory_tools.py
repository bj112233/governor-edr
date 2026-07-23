# services/tools/memory_tools.py
"""Memory search and reasoning tools."""

from pydantic import BaseModel, Field

from services.alert_history import query_alert_history_raw
from services.bot_memory import recall_context
from services.memory_db import search_conversations as _search_conversations
from services.tools.registry import ToolSpec


class SearchMemoryArgs(BaseModel):
    query: str = Field(..., description="Search query")
    limit: int = Field(5, description="Max results")


class SearchPastConversationsArgs(BaseModel):
    query: str = Field(..., description="What to search for in past conversations")
    days_back: int = Field(7, description="How many days back to search (default 7)")
    limit: int = Field(5, description="Number of results (default 5)")


class QueryAlertHistoryArgs(BaseModel):
    limit: int = Field(10, description="Number of recent alerts to return (default 10)")


async def _memory_search_handler(query: str, limit: int = 5) -> str:
    """Search conversation memory (semantic + FTS5)."""
    try:
        context = await recall_context(query, limit)
        if not context or not context.strip():
            return "🔍 לא נמצאו תוצאות בזיכרון."
        return f"**🔍 תוצאות חיפוש בזיכרון:**\n{context}"
    except Exception as exc:
        return f"❌ שגיאת חיפוש זיכרון: {exc}"


async def _query_alert_history_wrapper(limit=10, **_):
    return await query_alert_history_raw(int(limit))


def get_memory_tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="search_memory",
            description="Search conversation memory (FTS5).",
            pydantic_model=SearchMemoryArgs,
            handler=_memory_search_handler,
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="search_past_conversations",
            description="Search long-term memory for past interactions by semantic similarity.",
            pydantic_model=SearchPastConversationsArgs,
            handler=_search_conversations,
            expose_to_mcp=False,
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="query_alert_history",
            description="Recent SOC alerts from local DB.",
            pydantic_model=QueryAlertHistoryArgs,
            handler=_query_alert_history_wrapper,
            safety_level="safe",
            requires_data_integrity=False,
        ),
    ]
