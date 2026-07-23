# services/react_budget.py
"""Dynamic iteration budget for the ReAct loop.

Pure function. Determines how many ReAct iterations a topic deserves
based on linguistic complexity, keyword presence, and IOC candidates.

Range: 3 (simple) to 10 (complex APT campaign with IOC leads).
"""

from __future__ import annotations

import re

_BASE_BUDGET = 5
_MIN_BUDGET = 3
_MAX_BUDGET = 10

# Keywords that signal complex multi-step investigations
_COMPLEX_KEYWORDS = {
    "apt",
    "campaign",
    "botnet",
    "0-day",
    "zero-day",
    "zeroday",
    "ransomware",
    "supply chain",
    "lateral",
    "persistence",
    "exfiltration",
    "c2",
    "command and control",
    "threat actor",
    "intrusion",
    "forensics",
    "attribution",
    "infrastructure",
}

# IOC patterns for detecting leads in the topic itself
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _score_word_count(topic_lower: str) -> int:
    """+1 if topic has more than 3 words (multi-faceted)."""
    return 1 if len(topic_lower.split()) > 3 else 0


def _score_keywords(topic_lower: str) -> int:
    """+2 max if topic contains complex investigation keywords."""
    keyword_matches = sum(1 for kw in _COMPLEX_KEYWORDS if kw in topic_lower)
    return min(2, keyword_matches) if keyword_matches > 0 else 0


def _score_iocs(topic: str) -> int:
    """+1 if topic itself contains IOC candidates (leads to chase)."""
    return 1 if (_IP_RE.search(topic) or _DOMAIN_RE.search(topic) or _HASH_RE.search(topic)) else 0


def _score_hints(complexity_hints: dict | None) -> int:
    """Score from optional external hints."""
    if not complexity_hints:
        return 0
    score = 0
    if complexity_hints.get("has_iocs"):
        score += 1
    if complexity_hints.get("is_apt"):
        score += 2
    return score


def compute_budget(topic: str, complexity_hints: dict | None = None) -> int:
    """Compute dynamic iteration budget for a ReAct investigation.

    Args:
        topic: The investigation topic string.
        complexity_hints: Optional dict with extra signals (e.g. {"has_iocs": True}).

    Returns:
        int between _MIN_BUDGET and _MAX_BUDGET.
    """
    if not topic or not topic.strip():
        return _MIN_BUDGET

    topic_lower = topic.lower()
    budget = (
        _BASE_BUDGET
        + _score_word_count(topic_lower)
        + _score_keywords(topic_lower)
        + _score_iocs(topic)
        + _score_hints(complexity_hints)
    )

    return max(_MIN_BUDGET, min(_MAX_BUDGET, budget))
