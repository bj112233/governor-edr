"""MCP tool data contracts — Pydantic models for tool I/O schemas."""

from pydantic import BaseModel, Field


class NoArgs(BaseModel):
    """Placeholder for tools with no arguments."""

    pass


class WebSearchArgs(BaseModel):
    """Web search query."""

    query: str = Field(..., description="The search query in the user's language.")


class SentinelGetPendingEventsArgs(BaseModel):
    """Event bus query parameters."""

    limit: int = Field(10, description="Maximum number of events to return")


class TelegramApprovePairingArgs(BaseModel):
    """Telegram pairing approval."""

    code: str = Field(..., description="Pairing code to approve")


class TelegramSendMessageArgs(BaseModel):
    """Telegram message parameters."""

    chat_id: str = Field(..., description="Chat ID or username")
    message: str = Field(..., description="Message text")


class TriggerNewsDigestArgs(BaseModel):
    """News digest trigger parameters."""

    category: str = Field("", description="Category to filter (optional)")


class RecentMemoryArgs(BaseModel):
    """Memory search parameters."""

    query: str = Field("recent", description="Search query (default: recent)")
    limit: int = Field(5, description="Max results")


class SkillFileAnalystArgs(BaseModel):
    """File analyst skill parameters."""

    path: str = Field(..., description="File path to analyze")


class WebScraperArgs(BaseModel):
    """Web scraper skill parameters."""

    url: str = Field(..., description="URL to scrape")


class IntelArgs(BaseModel):
    """Intel skill parameters."""

    target: str = Field(..., description="IP address or domain to analyze")


class OsintHuntArgs(BaseModel):
    """OSINT hunt parameters."""

    topic: str = Field(
        ...,
        description="Topic or indicator to hunt (e.g. CVE, IP, domain, threat actor)",
    )


__all__ = [
    "NoArgs",
    "WebSearchArgs",
    "SentinelGetPendingEventsArgs",
    "TelegramApprovePairingArgs",
    "TelegramSendMessageArgs",
    "TriggerNewsDigestArgs",
    "RecentMemoryArgs",
    "SkillFileAnalystArgs",
    "WebScraperArgs",
    "IntelArgs",
    "OsintHuntArgs",
]
