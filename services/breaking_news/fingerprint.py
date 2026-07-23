# services/breaking_news/fingerprint.py
"""Deterministic event fingerprint extraction for cross-feed clustering.

Replaces the dead embeddings-based semantic dedup. Extracts a symbolic
fingerprint (event_type, location, actor) from a title via regex/keyword
maps loaded from feeds_breaking.json (event_types/locations/actors arrays).

Two items with the same fingerprint + within the sliding window (state.py)
are the same event reported by different feeds → consolidate, don't duplicate.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_CONFIG_PATH = Path(__file__).parent.parent.parent / "skills" / "news-monitor" / "config" / "feeds_breaking.json"

# ─── Fallback patterns (used when config file lacks categorized arrays) ──────
_FALLBACK_EVENT_TYPES: list[tuple[str, str]] = [
    ("פיגוע_דקירה", r"פיגוע\s*דקירה|דקר\b|דקירה"),
    ("פיגוע_דריסה", r"פיגוע\s*דריסה|דרס\b|דריסה"),
    ("פיגוע_ירי", r"פיגוע\s*ירי|ירי\s*לעבר|(?<![\u05D0-\u05EA])ירה(?![\u05D0-\u05EA])"),
    ("תקיפה_צבאית", r"תקף[הו]?\s*(?:צה\"ל|חיל|כוחות)|מבצע\s*צבאי|צה\"ל\s*תקף"),
    ("תקיפה_כללית", r"תקיפ[הת]|תקף[הו]?|מתקפ[הת]"),
    ("שריפה", r"שריפ[הת]|דליק[הת]"),
    ("ירי_רקטות", r"ירי\s*רקטות|רקט[הות]|צבע\s*אדום|אזעק[הת]"),
]

_FALLBACK_LOCATIONS: list[tuple[str, str]] = [
    ("ירושלים", r"ירושלים"),
    ("תל_אביב", r"תל\s*אביב"),
    ("חיפה", r"חיפה"),
    ("לבנון", r"לבנון|ביירות"),
    ("עזה", r"עזה"),
    ("איראן", r"איראן|טהרן"),
    ("גולן", r"גולן|רמת\s*הגולן"),
]

_FALLBACK_ACTORS: list[tuple[str, str]] = [
    ("צהל", r"צה\"?ל"),
    ("משטרה", r"משטר[הת]"),
    ("חמאס", r"חמאס"),
    ("חיזבאללה", r"חיזבאללה"),
]

# ─── Hebrew final-letter normalization ──────────────────────────────────────
# Hebrew has 5 letters with distinct final (sofit) forms: ץ/צ, ך/כ, ם/מ, ן/נ, ף/פ.
# Regex "פיצוץ" (ends with ץ U+05E5) does NOT match "פיצוצים" (has צ U+05E6).
# Normalizing both text and patterns to non-final forms before matching fixes this.
_FINAL_TO_REGULAR = str.maketrans("ץךםןף", "צכמנפ")


def _normalize_hebrew(text: str) -> str:
    """Normalize Hebrew final letters to regular forms for regex matching."""
    return text.translate(_FINAL_TO_REGULAR)


def _load_patterns_from_config() -> tuple[list[tuple[str, re.Pattern[str]]], ...] | None:
    """Load categorized patterns from feeds_breaking.json.

    Returns (event_types, locations, actors) — each a list of (key, compiled_regex).
    Returns None if the config file is missing or lacks the categorized arrays.
    """
    try:
        if not _CONFIG_PATH.exists():
            return None
        with open(_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)

        def _build(arr_key: str) -> list[tuple[str, re.Pattern[str]]]:
            arr = data.get(arr_key, [])
            result: list[tuple[str, re.Pattern[str]]] = []
            for entry in arr:
                if not isinstance(entry, dict):
                    continue
                key = entry.get("key", "")
                patterns = entry.get("patterns", [])
                if not key or not patterns:
                    continue
                regex_str = "|".join(_normalize_hebrew(p) for p in patterns)
                result.append((key, re.compile(regex_str, re.IGNORECASE)))
            return result

        et = _build("event_types")
        loc = _build("locations")
        act = _build("actors")
        if not et and not loc and not act:
            return None
        return et, loc, act
    except Exception as exc:
        logger.warning("[Fingerprint] Failed to load config patterns: %s — using fallback", exc)
        return None


def _build_fallback() -> tuple[list[tuple[str, re.Pattern[str]]], ...]:
    """Build fallback patterns from hardcoded defaults."""
    return (
        [(k, re.compile(_normalize_hebrew(p), re.IGNORECASE)) for k, p in _FALLBACK_EVENT_TYPES],
        [(k, re.compile(_normalize_hebrew(p), re.IGNORECASE)) for k, p in _FALLBACK_LOCATIONS],
        [(k, re.compile(_normalize_hebrew(p), re.IGNORECASE)) for k, p in _FALLBACK_ACTORS],
    )


# Load at import time (module-level cache)
_loaded = _load_patterns_from_config()
if _loaded is not None:
    _EVENT_TYPE_PATTERNS, _LOCATION_PATTERNS, _ACTOR_PATTERNS = _loaded
    logger.info(
        "[Fingerprint] Loaded from config: %d event_types, %d locations, %d actors",
        len(_EVENT_TYPE_PATTERNS),
        len(_LOCATION_PATTERNS),
        len(_ACTOR_PATTERNS),
    )
else:
    _EVENT_TYPE_PATTERNS, _LOCATION_PATTERNS, _ACTOR_PATTERNS = _build_fallback()
    logger.info(
        "[Fingerprint] Using fallback patterns: %d event_types, %d locations, %d actors",
        len(_EVENT_TYPE_PATTERNS),
        len(_LOCATION_PATTERNS),
        len(_ACTOR_PATTERNS),
    )


def _first_match(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> str:
    """Return the canonical key of the first matching pattern, or ''."""
    normalized = _normalize_hebrew(text)
    for key, pat in patterns:
        if pat.search(normalized):
            return key
    return ""


@dataclass(frozen=True)
class EventFingerprint:
    """Symbolic identity of a news event — NOT statistical.

    Two items with the same (event_type, location, actor) are the same event
    reported by different feeds. Time is NOT part of the hash — sliding-window
    validation in state.py handles temporal proximity.
    """

    event_type: str
    location: str
    actor: str

    @property
    def key(self) -> str:
        raw = f"{self.event_type}|{self.location}|{self.actor}"
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def is_empty(self) -> bool:
        return not (self.event_type or self.location or self.actor)


def extract_fingerprint(title: str, summary: str = "") -> EventFingerprint:
    """Extract deterministic fingerprint from title (+summary as fallback)."""
    event_type = _first_match(title, _EVENT_TYPE_PATTERNS) or _first_match(summary, _EVENT_TYPE_PATTERNS)
    location = _first_match(title, _LOCATION_PATTERNS) or _first_match(summary, _LOCATION_PATTERNS)
    actor = _first_match(title, _ACTOR_PATTERNS) or _first_match(summary, _ACTOR_PATTERNS)
    fp = EventFingerprint(event_type=event_type, location=location, actor=actor)
    logger.debug(
        "[Fingerprint] '%s' → type=%s loc=%s actor=%s key=%s",
        title[:60],
        event_type or "—",
        location or "—",
        actor or "—",
        fp.key,
    )
    return fp
