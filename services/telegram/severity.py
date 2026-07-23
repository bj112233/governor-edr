# services/telegram/severity.py
"""Centralized severity → emoji mapping (SSOT) for all Telegram surfaces.

Replaces the 4 divergent dicts previously scattered across:
- services/alert_dispatcher.py  (lowercase keys, ⚪ default)
- services/alert_history_query.py (UPPERCASE keys, no info/ok)
- services/intel_enricher.py    (score-based classification with Hebrew labels)
- services/formatters.py        (regex prefix parser, no dict)

Canonical palette (5 levels + 1 unknown):
    critical / malicious  → 🔴
    warn                  → 🟠
    suspicious            → 🟡
    ok / clean            → 🟢
    info                  → ⚪
    unknown               → ⚪
"""

from __future__ import annotations

# Canonical severity → emoji. Keys are lowercase.
SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "malicious": "🔴",
    "warn": "🟠",
    "warning": "🟠",
    "suspicious": "🟡",
    "ok": "🟢",
    "clean": "🟢",
    "info": "⚪",
    "unknown": "⚪",
}

# Uppercase variant for consumers that store severity as UPPER (alert_history).
SEVERITY_EMOJI_UPPER: dict[str, str] = {k.upper(): v for k, v in SEVERITY_EMOJI.items()}

# Reverse map: emoji → canonical severity (UPPERCASE, for alert_history).
# Canonical forms chosen explicitly so duplicates (warn/warning) collapse to
# the preferred short token. Order: critical > malicious for 🔴.
EMOJI_SEVERITY: dict[str, str] = {
    "🔴": "CRITICAL",
    "🟠": "WARN",
    "🟡": "SUSPICIOUS",
    "🟢": "OK",
    "⚪": "INFO",
}

# Display order (highest → lowest) for sort/comparison.
EMOJI_ORDER: dict[str, int] = {"🔴": 3, "🟠": 2, "🟡": 1, "🟢": 0, "⚪": -1}

UNKNOWN_EMOJI = "⚪"


def severity_emoji(severity: str | None) -> str:
    """Return the canonical emoji for a severity token (case-insensitive).

    Accepts both lowercase ('critical') and uppercase ('CRITICAL') inputs.
    Returns UNKNOWN_EMOJI (⚪) for None / unrecognized values.
    """
    if not severity:
        return UNKNOWN_EMOJI
    key = severity.strip().lower()
    return SEVERITY_EMOJI.get(key, UNKNOWN_EMOJI)


def severity_emoji_by_score(score: int | float) -> str:
    """Map a 0-100 risk score to a severity emoji.

    Bands (aligned with intel_enricher.format_enrichment_summary):
        >= 70 → 🔴 malicious
        >= 40 → 🟠 suspicious
        >= 15 → 🟡 unknown
        <  15 → 🟢 clean
    """
    s = int(score)
    if s >= 70:
        return "🔴"
    if s >= 40:
        return "🟠"
    if s >= 15:
        return "🟡"
    return "🟢"
