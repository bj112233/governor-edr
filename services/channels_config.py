# services/channels_config.py
"""
Channel Configuration — Pydantic models for Telegram channel setup.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator

from services.channels_config_models import (  # noqa: E402,F401
    DmPolicy,
    ErrorPolicy,
    GroupPolicy,
    StreamingMode,
    TelegramAccountConfig,
    TelegramActions,
    TelegramCapabilities,
    TelegramCommands,
    TelegramExecApprovals,
    TelegramGroupConfig,
    TelegramNetworkConfig,
    TelegramRetryConfig,
    TelegramTopicConfig,
)


class TelegramConfig(BaseModel):
    """
    Full Telegram channel configuration.
    """

    # Startup/Auth
    enabled: bool = False
    bot_token: str | None = None
    token_file: str | None = None

    # Multi-account support
    accounts: dict[str, TelegramAccountConfig] = Field(default_factory=dict)
    default_account: str | None = None

    # Access Control — DM
    dm_policy: DmPolicy = DmPolicy.PAIRING
    allow_from: list[str] = Field(default_factory=list)

    # Access Control — Groups
    group_policy: GroupPolicy = GroupPolicy.ALLOWLIST
    group_allow_from: list[str] = Field(default_factory=list)
    groups: dict[str, TelegramGroupConfig] = Field(default_factory=dict)

    # Direct message topics (DM threads)
    direct: dict[str, dict[str, TelegramTopicConfig]] = Field(default_factory=dict)

    # Exec approvals
    exec_approvals: TelegramExecApprovals = Field(default_factory=TelegramExecApprovals)

    # Commands/Menu
    commands: TelegramCommands = Field(default_factory=TelegramCommands)

    # Threading/Replies
    reply_to_mode: Literal["off", "first", "all"] = "off"

    # Streaming
    streaming: StreamingMode = StreamingMode.PARTIAL

    # Formatting/Delivery
    text_chunk_limit: int = 4000
    chunk_mode: Literal["length", "newline"] = "newline"
    link_preview: bool = True
    response_prefix: str | None = None

    # Media/Network
    media_max_mb: int = 100
    timeout_seconds: int = 30
    retry: TelegramRetryConfig = Field(default_factory=TelegramRetryConfig)
    network: TelegramNetworkConfig = Field(default_factory=TelegramNetworkConfig)
    proxy: str | None = None

    # Webhook (alternative to long polling)
    webhook_url: str | None = None
    webhook_secret: str | None = None
    webhook_path: str = "/telegram-webhook"
    webhook_host: str = "127.0.0.1"
    webhook_port: int = 8787

    # Actions/Capabilities
    capabilities: TelegramCapabilities = Field(default_factory=TelegramCapabilities)
    actions: TelegramActions = Field(default_factory=TelegramActions)

    # Reactions
    reaction_notifications: Literal["off", "own", "all"] = "own"
    reaction_level: Literal["off", "ack", "minimal", "extensive"] = "minimal"

    # Errors
    error_policy: ErrorPolicy = ErrorPolicy.REPLY
    error_cooldown_ms: int = 60000

    # Default routing target for CLI
    default_to: str | None = None

    @field_validator("allow_from", "group_allow_from", mode="before")
    @classmethod
    def normalize_telegram_ids(cls, v: Any) -> list[str]:
        """Normalize Telegram IDs: remove telegram:/tg: prefixes."""
        if not isinstance(v, list):
            return []
        result = []
        for item in v:
            if isinstance(item, str):
                # Remove prefixes
                item = item.strip()
                if item.startswith("telegram:"):
                    item = item[9:]
                elif item.startswith("tg:"):
                    item = item[3:]
                result.append(item)
        return result

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook(cls, v: str | None, info) -> str | None:
        """Ensure webhook_secret is set if webhook_url is used."""
        if v:
            values = info.data
            if not values.get("webhook_secret"):
                raise ValueError("webhook_secret is required when webhook_url is set")
        return v

    def get_effective_bot_token(self, account: str | None = None) -> str | None:
        """Get effective bot token for account (or default)."""
        if account and account in self.accounts:
            acc = self.accounts[account]
            return acc.bot_token or self.bot_token
        return self.bot_token

    def is_dm_allowed(self, user_id: int | str) -> bool:
        """Check if DM from user_id is allowed based on policy."""
        uid = str(user_id)

        if self.dm_policy == DmPolicy.DISABLED:
            return False
        if self.dm_policy == DmPolicy.OPEN:
            return "*" in self.allow_from or uid in self.allow_from
        if self.dm_policy == DmPolicy.ALLOWLIST:
            return uid in self.allow_from
        if self.dm_policy == DmPolicy.PAIRING:
            # Pairing requires explicit approval — handled separately
            return False
        return False

    def is_group_allowed(self, group_id: int | str, user_id: int | str) -> bool:
        """Check if user can interact in group."""
        gid = str(group_id)
        uid = str(user_id)

        # Check group-specific config
        if gid in self.groups:
            gcfg = self.groups[gid]
            if not gcfg.enabled:
                return False
            policy = gcfg.group_policy or self.group_policy
            if policy == GroupPolicy.DISABLED:
                return False
            if policy == GroupPolicy.OPEN:
                return True
            if policy == GroupPolicy.ALLOWLIST:
                return uid in gcfg.allow_from or uid in self.group_allow_from

        # Fall back to global group policy
        if self.group_policy == GroupPolicy.DISABLED:
            return False
        if self.group_policy == GroupPolicy.OPEN:
            return True
        if self.group_policy == GroupPolicy.ALLOWLIST:
            return uid in self.group_allow_from

        return False


class ChannelsConfig(BaseModel):
    """Root channels configuration container."""

    telegram: TelegramConfig = Field(default_factory=TelegramConfig)


def load_channels_config(raw: dict[str, Any]) -> ChannelsConfig:
    """Load channels configuration from dict (e.g., from JSON/YAML)."""
    return ChannelsConfig.model_validate(raw)


def get_default_config() -> ChannelsConfig:
    """Get default channels configuration (disabled)."""
    return ChannelsConfig(
        telegram=TelegramConfig(
            enabled=False,
            dm_policy=DmPolicy.PAIRING,
            group_policy=GroupPolicy.ALLOWLIST,
        )
    )
