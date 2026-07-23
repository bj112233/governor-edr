"""MCP tools router — thin shim that registers handlers with ToolSpec."""

from services.ai_search import web_search as _web_search
from services.tools.mcp_handlers import (
    approve_pending_action_tool,
    deny_pending_action_tool,
    osint_hunt_tool,
    recent_memory_tool,
    sentinel_clear_event_queue,
    sentinel_get_pending_events,
    sentinel_get_system_snapshot_full,
    skill_file_analyst,
    skill_intel,
    skill_web_scraper,
    telegram_approve_pairing,
    telegram_list_pairings,
    telegram_send_message,
    trigger_news_digest_tool,
)
from services.tools.mcp_models import (
    IntelArgs,
    NoArgs,
    OsintHuntArgs,
    RecentMemoryArgs,
    SentinelGetPendingEventsArgs,
    SkillFileAnalystArgs,
    TelegramApprovePairingArgs,
    TelegramSendMessageArgs,
    TriggerNewsDigestArgs,
    WebScraperArgs,
    WebSearchArgs,
)
from services.tools.registry import ToolSpec


def get_mcp_tools() -> list[ToolSpec]:
    """Return all MCP-only and web search tools."""
    return [
        ToolSpec(
            name="web_search",
            description="Web search (weather, news, prices, facts).",
            pydantic_model=WebSearchArgs,
            handler=_web_search,
        ),
        ToolSpec(
            name="approve_pending_action",
            description="Execute pending remediation action.",
            pydantic_model=NoArgs,
            handler=approve_pending_action_tool,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="deny_pending_action",
            description="Cancel the pending remediation action.",
            pydantic_model=NoArgs,
            handler=deny_pending_action_tool,
        ),
        ToolSpec(
            name="sentinel_get_system_snapshot_full",
            description="Full system snapshot with alert analysis.",
            pydantic_model=NoArgs,
            handler=sentinel_get_system_snapshot_full,
        ),
        ToolSpec(
            name="sentinel_get_pending_events",
            description="Pending events from Sentinel event bus.",
            pydantic_model=SentinelGetPendingEventsArgs,
            handler=sentinel_get_pending_events,
        ),
        ToolSpec(
            name="sentinel_clear_event_queue",
            description="Clear Sentinel event queue.",
            pydantic_model=NoArgs,
            handler=sentinel_clear_event_queue,
        ),
        ToolSpec(
            name="telegram_list_pairings",
            description="List pending Telegram pairing requests.",
            pydantic_model=NoArgs,
            handler=telegram_list_pairings,
            expose_to_llm=False,
        ),
        ToolSpec(
            name="telegram_approve_pairing",
            description="Approve a Telegram pairing request by code.",
            pydantic_model=TelegramApprovePairingArgs,
            handler=telegram_approve_pairing,
            expose_to_llm=False,
        ),
        ToolSpec(
            name="telegram_send_message",
            description="Send a message to a Telegram chat.",
            pydantic_model=TelegramSendMessageArgs,
            handler=telegram_send_message,
        ),
        ToolSpec(
            name="trigger_news_digest",
            description="Trigger daily news digest to Telegram.",
            pydantic_model=TriggerNewsDigestArgs,
            handler=trigger_news_digest_tool,
        ),
        ToolSpec(
            name="recent_memory",
            description="Search recent conversation history.",
            pydantic_model=RecentMemoryArgs,
            handler=recent_memory_tool,
        ),
        ToolSpec(
            name="skill_file_analyst",
            description="Analyze a local file using the file-analyst skill.",
            pydantic_model=SkillFileAnalystArgs,
            handler=skill_file_analyst,
            expose_to_llm=False,
        ),
        ToolSpec(
            name="skill_web_scraper",
            description="Scrape a web page using the web-scraper skill.",
            pydantic_model=WebScraperArgs,
            handler=skill_web_scraper,
            expose_to_llm=False,
        ),
        ToolSpec(
            name="skill_intel",
            description="Israeli threat intelligence analysis using the intel-skill.",
            pydantic_model=IntelArgs,
            handler=skill_intel,
            expose_to_llm=False,
        ),
        ToolSpec(
            name="osint_hunt",
            description="Autonomous OSINT threat hunt on a topic.",
            pydantic_model=OsintHuntArgs,
            handler=osint_hunt_tool,
            expose_to_mcp=False,
        ),
    ]
