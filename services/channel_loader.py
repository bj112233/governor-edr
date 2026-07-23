# services/channel_loader.py
"""
Channel Configuration Loader — טוען תצורת ערוצים מ-JSON/YAML עם תמיכה ב-env vars.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

from services.channels_config import ChannelsConfig

logger = logging.getLogger(__name__)


def _expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} and $VAR in strings."""
    if isinstance(value, str):
        # Pattern: ${VAR} or ${VAR:-default}
        pattern = r"\$\{([^}]+)\}"

        def replace(match: re.Match) -> str:
            expr = match.group(1)
            if ":-" in expr:
                var, default = expr.split(":-", 1)
                return os.getenv(var, default)
            val = os.getenv(expr, "")
            if not val:
                logger.warning(
                    "[ChannelLoader] env var ${%s} referenced in channels.json is unset/empty",
                    expr,
                )
            return val

        return re.sub(pattern, replace, value)

    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}

    elif isinstance(value, list):
        return [_expand_env_vars(item) for item in value]

    return value


def load_channels_json(path: str | None = None) -> ChannelsConfig:
    """
    Load channels configuration from JSON file.

    Args:
        path: Path to JSON file. If None, searches for channels.json in common locations.

    Returns:
        ChannelsConfig instance
    """
    if path is None:
        # Search for channels.json
        search_paths = [
            "channels.json",
            "config/channels.json",
            ".config/channels.json",
            "/etc/sentinel/channels.json",
        ]
        for p in search_paths:
            if Path(p).exists():
                path = p
                break

    if not path or not Path(path).exists():
        logger.warning("[ChannelLoader] No channels.json found, using defaults")
        return ChannelsConfig()

    logger.info(f"[ChannelLoader] Loading channels config from {path}")

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    # Expand environment variables
    expanded = _expand_env_vars(raw)

    # Handle empty strings from env vars as None
    def clean_empty(value: Any) -> Any:
        if isinstance(value, str) and value == "":
            return None
        elif isinstance(value, dict):
            return {k: clean_empty(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [clean_empty(item) for item in value]
        return value

    cleaned = clean_empty(expanded)

    # Remove None values for optional fields
    def remove_none(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: remove_none(v) for k, v in value.items() if v is not None}
        elif isinstance(value, list):
            return [remove_none(item) for item in value]
        return value

    final = remove_none(cleaned)

    try:
        config = ChannelsConfig.model_validate(final)
        logger.info(f"[ChannelLoader] Loaded config: Telegram enabled={config.telegram.enabled}")
        return config
    except Exception as e:
        logger.error(f"[ChannelLoader] Failed to parse config: {e}")
        logger.warning("[ChannelLoader] Using default config")
        return ChannelsConfig()
