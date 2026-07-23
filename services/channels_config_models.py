# services/channels_config_models.py
"""Pydantic models for Telegram channel configuration — enums + small models.

Extracted from channels_config.py (SRP). TelegramConfig (the main composite
model with validation logic) stays in channels_config.py.
"""

from __future__ import annotations

from enum import Enum, StrEnum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class DmPolicy(StrEnum):
    """DM Policy options for Telegram channel."""

    PAIRING = "pairing"
    ALLOWLIST = "allowlist"
    OPEN = "open"
    DISABLED = "disabled"


class GroupPolicy(StrEnum):
    """Group policy options."""

    OPEN = "open"
    ALLOWLIST = "allowlist"
    DISABLED = "disabled"


class ErrorPolicy(StrEnum):
    """Error reply policy."""

    REPLY = "reply"
    SILENT = "silent"


class StreamingMode(StrEnum):
    """Streaming preview mode."""

    OFF = "off"
    PARTIAL = "partial"
    BLOCK = "block"
    PROGRESS = "progress"


class TelegramGroupConfig(BaseModel):
    """Per-group configuration for Telegram."""

    enabled: bool = True
    group_policy: GroupPolicy | None = None
    require_mention: bool = True
    allow_from: list[str] = Field(default_factory=list)
    skills: list[str] | None = None
    system_prompt: str | None = None
    error_policy: ErrorPolicy | None = None
    error_cooldown_ms: int | None = None


class TelegramTopicConfig(BaseModel):
    """Per-topic configuration for forum threads."""

    enabled: bool = True
    agent_id: str | None = None
    group_policy: GroupPolicy | None = None
    require_mention: bool | None = None
    system_prompt: str | None = None


class TelegramExecApprovals(BaseModel):
    """Exec approval configuration via Telegram."""

    enabled: bool = False
    approvers: list[str] = Field(default_factory=list)
    target: Literal["dm", "channel", "both"] = "dm"
    agent_filter: str | None = None
    session_filter: str | None = None


class TelegramAccountConfig(BaseModel):
    """Named account configuration for multi-account setups."""

    bot_token: str | None = None
    token_file: str | None = None
    dm_policy: DmPolicy | None = None
    allow_from: list[str] = Field(default_factory=list)
    group_allow_from: list[str] = Field(default_factory=list)
    exec_approvals: TelegramExecApprovals | None = None


class TelegramCapabilities(BaseModel):
    """Telegram capability toggles."""

    inline_buttons: Literal["off", "dm", "group", "all", "allowlist"] = "allowlist"


class TelegramActions(BaseModel):
    """Telegram action gates."""

    send_message: bool = True
    edit_message: bool = True
    delete_message: bool = False
    reactions: bool = True
    poll: bool = True
    sticker: bool = False


class TelegramCommands(BaseModel):
    """Telegram commands configuration."""

    native: bool | None = None
    native_skills: bool = True


class TelegramNetworkConfig(BaseModel):
    """Network configuration for Telegram Bot API."""

    auto_select_family: bool | None = None
    dns_result_order: Literal["ipv4first", "verbatim"] | None = "ipv4first"
    dangerously_allow_private_network: bool = False


class TelegramRetryConfig(BaseModel):
    """Retry policy for Telegram API calls."""

    attempts: int = 3
    min_delay_ms: int = 1000
    max_delay_ms: int = 10000
    jitter: bool = True
