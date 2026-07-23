# services/breaking_news/config.py
"""Configuration loading + keyword regex building."""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

BREAKING_NEWS_CONFIG = (
    Path(__file__).parent.parent.parent / "skills" / "news-monitor" / "config" / "feeds_breaking.json"
)

FALLBACK_NEWS_CONFIG = {
    "feeds": [
        {
            "name": "N12 חדשות",
            "url": "https://rcs.mako.co.il/rss/news-israel.xml",
            "category": "breaking",
            "enabled": True,
        }
    ],
    "urgent_keywords": [
        "התרעה",
        "חירום",
        "פיגוע",
        "נפילה",
        "יירוט",
        "חדירה",
        "אזעקה",
    ],
    "delivery": {
        "telegram": {
            "enabled": True,
            "batch_size": 3,
        }
    },
}


class NewsConfig:
    """Loaded breaking news configuration."""

    def __init__(self) -> None:
        self.config: dict = {}
        self.keyword_regex: re.Pattern | None = None
        self.secondary_regex: re.Pattern | None = None
        self.context_regex: re.Pattern | None = None

    async def load(self) -> None:
        """Load config with fallback on any error."""
        try:

            def _read():
                with open(BREAKING_NEWS_CONFIG, encoding="utf-8") as f:
                    return json.load(f)

            self.config = await asyncio.to_thread(_read)
            logger.info(
                "[BreakingNews] Loaded config with %d feeds",
                len(self.config.get("feeds", [])),
            )
        except FileNotFoundError:
            logger.critical(
                "[BreakingNews] Config not found: %s. Using fallback.",
                BREAKING_NEWS_CONFIG,
            )
            self.config = dict(FALLBACK_NEWS_CONFIG)
        except json.JSONDecodeError as exc:
            logger.critical(
                "[BreakingNews] Config corrupted (JSONDecodeError: %s). Using fallback.",
                exc,
            )
            self.config = dict(FALLBACK_NEWS_CONFIG)
        except Exception as exc:
            logger.critical("[BreakingNews] Failed to load config (%s). Using fallback.", exc)
            self.config = dict(FALLBACK_NEWS_CONFIG)
        self._build_keyword_regex()
        self._build_secondary_regex()
        self._build_context_regex()

    def _build_keyword_regex(self) -> None:
        """Build Hebrew-aware regex with prefix/suffix boundaries."""
        kws = self.config.get("urgent_keywords", [])
        if not kws:
            self.keyword_regex = None
            return
        prefix = r"(?:^|\s|[בהולמשכ])"
        suffix = r'(?:\s|[.,:;?!\'"\-]|$)'
        escaped = "|".join(map(re.escape, kws))
        self.keyword_regex = re.compile(f"{prefix}({escaped}){suffix}", re.IGNORECASE)
        logger.info("[BreakingNews] Built keyword regex with %d keywords", len(kws))

    def _build_secondary_regex(self) -> None:
        """Build regex for secondary keywords (locations/entities that alone = false positive).

        No boundaries — this regex runs on m.group(1) from keyword_regex,
        which is already a clean extracted token. Double-bounding would fail
        on edge-captured spaces.
        """
        kws = self.config.get("secondary_keywords", [])
        if not kws:
            self.secondary_regex = None
            return
        escaped = "|".join(map(re.escape, kws))
        self.secondary_regex = re.compile(f"^({escaped})$", re.IGNORECASE)
        logger.info("[BreakingNews] Built secondary regex with %d keywords", len(kws))

    def _build_context_regex(self) -> None:
        """Build regex for context modifiers (security-signal words).

        Uses stem-prefix matching (e.g. 'אזעק' matches אזעקה/אזעקות/אזעקת)
        so no suffix boundary is needed.
        """
        kws = self.config.get("context_modifiers", [])
        if not kws:
            self.context_regex = None
            return
        escaped = "|".join(map(re.escape, kws))
        self.context_regex = re.compile(f"(?:{escaped})", re.IGNORECASE)
        logger.info("[BreakingNews] Built context regex with %d modifiers", len(kws))
