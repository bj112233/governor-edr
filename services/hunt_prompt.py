# services/hunt_prompt.py
"""Hunt prompt builder + threat score extraction — extracted from threat_hunter.py (SRP)."""

import logging
import re
from typing import Any

from config import THREAT_HUNT_MAX_ALERTS, THREAT_HUNT_MAX_MEMORY_CHARS

logger = logging.getLogger(__name__)

_ALERT_CHAR_CAP = 200

_SCORE_XML_RE = re.compile(r"<SCORE>\s*([0-9]*\.?[0-9]+)\s*</SCORE>", re.IGNORECASE)
# Fallback: line-anchored "THREAT_SCORE: 0.X" or "score: 0.X" — NOT liberal
# mid-sentence matching (which catches "9.5/10" or "-0.3").
# Requires the number to be the LAST token on the line (anchored by $).
_SCORE_FALLBACK_RE = re.compile(
    r"^\s*(?:THREAT_SCORE|Threat Score|ציון איום|ציון|score)\s*[:=]\s*([0-9]*\.?[0-9]+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def build_hunt_prompt(
    snapshot: dict[str, Any],
    alerts: list[tuple],
    memory: str,
    hard_facts: str = "",
) -> str:
    """Build a tightly-truncated hunting prompt (<2000 tokens target).

    Self-contained truncation: enforces alert count + char caps + memory cap
    regardless of whether the caller pre-truncated. Defense-in-depth against
    context window blowout.

    Args:
        hard_facts: Pre-hunt enrichment results (HARD FACTS from AbuseIPDB/VT).
                    Injected as immutable ground truth — LLM cannot contradict.
    """
    cpu = snapshot.get("cpu", 0)
    ram = snapshot.get("mem", 0)
    disk_alerts = snapshot.get("disk_alerts", [])
    net = snapshot.get("suspicious_net", [])[:5]

    lines = [
        "אתה Sentinel Threat Hunter. בצע ציד איומים יזום ומעמיק על המערכת.",
        "אסור לך לדלג על שלב החקירה. חובה להפעיל כלים לפני סיכום.",
        "בדוק: חיבורים חיצוניים חשודים, תהליכים חריגים, לוג אירועי אבטחה, ושירותים פעילים.",
        f"מצב מערכת: CPU={cpu:.0f}% RAM={ram:.0f}% דיסק_התראות={len(disk_alerts)} קשרים_חשודים={len(net)}.",
        f"קשרים חשודים: {', '.join(net) or 'אין'}.",
    ]
    if hard_facts:
        lines.append(hard_facts)
        logger.info("[ThreatHunter] Injecting HARD FACTS from pre-hunt enrichment into prompt.")
    for ts, trigger, _report in alerts[:THREAT_HUNT_MAX_ALERTS]:
        lines.append(f"התראה {ts}: {trigger[:_ALERT_CHAR_CAP]}")
    if memory:
        lines.append(f"זיכרון רלוונטי: {memory[:THREAT_HUNT_MAX_MEMORY_CHARS]}")
    lines.append("נתח את מצב האיום לעומק. בדוק חיבורים חשודים, תהליכים חריגים, ואירועי אבטחה.")
    lines.append("OUTPUT FORMAT (MANDATORY — failure to follow = analysis rejected):")
    lines.append("1. כתוב דוח מלא בעברית (מינימום 200 תווים) — סיכום ממצאים, הערכת איום, המלצות.")
    lines.append(
        "שמר מונחי סייבר באנגלית: MITRE ATT&CK, TTP, IOC, Encoded Commands, Execution Policy Bypass, Defense Evasion, Persistence, Lateral Movement, Privilege Escalation."
    )
    lines.append("2. רק אחרי הדוח המלא, בשורה האחרונה, כתוב את הציון בתג XML מדויק:")
    lines.append("<SCORE>0.X</SCORE>")
    lines.append("(0.0 = Safe, 1.0 = Critical). Do not add any text inside the tags except the float number.")
    lines.append("אסור להתחיל את התשובה ב-<SCORE>. הדוח חייב להופיע קודם.")
    lines.append("If you cannot output XML tags, write the score on its own line as: THREAT_SCORE: 0.X")
    return "\n".join(lines)


def extract_threat_score(text: str) -> float:
    """Parse threat score from agent output — XML tag first, liberal fallback second.

    Fail-closed: returns 0.1 (analysis failure) if no score found,
    NOT 0.0 (clean). This prevents false negatives when the LLM
    forgets the score line or produces unparseable output.
    """
    # 1. XML tag (strict — the prompt requests this format)
    match = _SCORE_XML_RE.search(text)
    # 2. Liberal fallback: any number near score-related keywords
    if not match:
        match = _SCORE_FALLBACK_RE.search(text)
    if not match:
        logger.warning("[ThreatHunter] No THREAT_SCORE found in agent output — using 0.1 (analysis failure)")
        return 0.1
    try:
        val = float(match.group(1))
    except ValueError:
        logger.warning("[ThreatHunter] THREAT_SCORE parse error: %s — using 0.1", match.group(1))
        return 0.1
    # Auto-correct: model may write 85 instead of 0.85, or 8 instead of 0.8
    raw = match.group(1)
    if val > 10:
        val = val / 100.0  # percentage → 0..1 (85 → 0.85, 100 → 1.0)
    elif val > 1.0 and "." not in raw:
        val = val / 10.0  # bare integer 2-9 → 0.2-0.9 (8 → 0.8)
    elif val > 1.0:
        val = 1.0  # decimal >1.0 (e.g. 1.5) — clamp to max
    return max(0.0, min(1.0, val))
