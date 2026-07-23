"""Config loader — skill profiles + delivery settings."""

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_SKILL_CONFIG_DIR = Path(__file__).parent.parent.parent / "skills" / "news-monitor" / "config"
_DELIVERY_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "news_feeds.json"
_EXCLUDE_PROFILES = {"feeds_breaking.json", "feeds_cti.json"}


def load_delivery_config() -> dict:
    """Load delivery settings from JSON."""
    try:
        with open(_DELIVERY_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("delivery", {}).get("telegram", {})
    except FileNotFoundError:
        logger.warning("[NewsConfig] Delivery config not found: %s", _DELIVERY_CONFIG_PATH)
        return {}


def load_profiles() -> list[dict]:
    """Load all skill profile configs (excluding breaking-news)."""
    profiles: list[dict] = []
    if not _SKILL_CONFIG_DIR.exists():
        logger.error("[NewsConfig] Skill config dir not found: %s", _SKILL_CONFIG_DIR)
        return profiles

    total_feeds = 0
    for config_file in sorted(_SKILL_CONFIG_DIR.glob("feeds_*.json")):
        if config_file.name in _EXCLUDE_PROFILES:
            continue
        try:
            with open(config_file, encoding="utf-8") as f:
                profile_data = json.load(f)
            name = config_file.stem.replace("feeds_", "")
            feeds = profile_data.get("feeds", [])
            profiles.append(
                {
                    "name": name,
                    "feeds": feeds,
                    "keywords": profile_data.get("keywords", []),
                }
            )
            total_feeds += len(feeds)
            logger.info(
                "[NewsConfig]   profile=%s: %d feeds, %d keywords",
                name,
                len(feeds),
                len(profile_data.get("keywords", [])),
            )
        except Exception as exc:
            logger.warning("[NewsConfig] Failed to load %s: %s", config_file.name, exc)

    logger.info("[NewsConfig] Loaded %d profiles, %d feeds total", len(profiles), total_feeds)
    return profiles
