"""Intel Skill — Threat Scoring Engine.

Pure math. No I/O. Receives enriched data dicts, outputs 0-100 score.
Deterministic and easily unit-testable.

ThreatVerdict (v2): assess() returns score + action + reason for auto-block pipeline.
score_ip/domain/hash remain backward-compatible (return int).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

_RISKY_PORTS = {23, 3389, 445}  # Telnet, RDP, SMB

# Action thresholds
_BLOCK_THRESHOLD = 85
_ALERT_THRESHOLD = 50

# Decay: tau=14 days. Half-life = tau * ln(2) ≈ 9.7 days
_DECAY_TAU_DAYS = 14.0


@dataclass(frozen=True, slots=True)
class ThreatVerdict:
    """Structured threat assessment — score + recommended action + reason.

    Consumed by pending_actions pipeline to auto-queue block requests.
    """

    score: int
    action: str  # "BLOCK" | "ALERT" | "MONITOR" | "CLEAN"
    reason: str  # human-readable explanation
    ioc_type: str = ""  # "ip" | "domain" | "hash"
    indicators: list[str] = field(default_factory=list)


def score_ip(abuse: dict, maltiverse: dict, vt: dict, ipapi: dict, shodan: dict) -> int:
    """Backward-compatible: returns int score only."""
    return assess_ip(abuse, maltiverse, vt, ipapi, shodan).score


def assess_ip(abuse: dict, maltiverse: dict, vt: dict, ipapi: dict, shodan: dict) -> ThreatVerdict:
    """Full threat assessment for an IP — score + action + reason + indicators."""
    s = 0
    indicators: list[str] = []

    if abuse.get("available"):
        conf = int(abuse.get("abuse_confidence") or 0)
        s = max(s, conf)
        if conf >= 50:
            indicators.append(f"abuseipdb:{conf}")

    if maltiverse.get("available") and maltiverse.get("found"):
        cls = maltiverse.get("classification", "unknown")
        if cls == "malicious":
            s = max(s, 80 + min(15, maltiverse.get("blacklist_count", 0)))
            indicators.append("maltiverse:malicious")
        elif cls == "suspicious":
            s = max(s, 50)
            indicators.append("maltiverse:suspicious")

    if vt.get("available") and vt.get("found"):
        mal = int(vt.get("malicious") or 0) + int(vt.get("suspicious") or 0)
        s = max(s, min(100, mal * 10))
        if mal > 0:
            indicators.append(f"vt:{mal}detections")

    if ipapi.get("available"):
        if ipapi.get("vpn"):
            s += 15
            indicators.append("vpn")
        if ipapi.get("tor"):
            s += 15
            indicators.append("tor")
        if ipapi.get("proxy"):
            s += 10
            indicators.append("proxy")
        if ipapi.get("hosting"):
            s += 5

    if shodan.get("available"):
        vulns = shodan.get("vulns", [])
        s += min(25, len(vulns) * 5)
        ports = set(shodan.get("ports", []))
        overlap = ports & _RISKY_PORTS
        if overlap:
            s += min(15, len(overlap) * 5)
            indicators.append(f"risky_ports:{','.join(str(p) for p in overlap)}")

    score = min(s, 100)
    return ThreatVerdict(
        score=score,
        action=_action_from_score(score),
        reason=_reason_from_indicators(indicators, score),
        ioc_type="ip",
        indicators=indicators,
    )


def score_domain(maltiverse: dict, vt: dict, rdap: dict) -> int:
    """Backward-compatible: returns int score only."""
    return assess_domain(maltiverse, vt, rdap).score


def assess_domain(maltiverse: dict, vt: dict, rdap: dict) -> ThreatVerdict:
    """Full threat assessment for a domain — score + action + reason."""
    s = 0
    indicators: list[str] = []

    if maltiverse.get("available") and maltiverse.get("found"):
        cls = maltiverse.get("classification", "unknown")
        if cls == "malicious":
            s = max(s, 80)
            indicators.append("maltiverse:malicious")
        elif cls == "suspicious":
            s = max(s, 50)
            indicators.append("maltiverse:suspicious")

    if vt.get("available") and vt.get("found"):
        mal = int(vt.get("malicious") or 0) + int(vt.get("suspicious") or 0)
        s = max(s, min(100, mal * 8))
        if mal > 0:
            indicators.append(f"vt:{mal}detections")

    reg = rdap.get("registered") if rdap.get("available") else None
    if reg and reg[:4].isdigit():
        try:
            age_days = (datetime.now(UTC) - datetime.fromisoformat(reg.replace("Z", "+00:00"))).days
            if age_days < 30:
                s += 20
                indicators.append(f"domain_age:{age_days}d")
        except Exception:
            pass

    score = min(s, 100)
    return ThreatVerdict(
        score=score,
        action=_action_from_score(score),
        reason=_reason_from_indicators(indicators, score),
        ioc_type="domain",
        indicators=indicators,
    )


def score_hash(maltiverse: dict, vt: dict) -> int:
    """Backward-compatible: returns int score only."""
    return assess_hash(maltiverse, vt).score


def assess_hash(maltiverse: dict, vt: dict) -> ThreatVerdict:
    """Full threat assessment for a file hash — score + action + reason."""
    s = 0
    indicators: list[str] = []

    if maltiverse.get("available") and maltiverse.get("found"):
        cls = maltiverse.get("classification", "unknown")
        if cls == "malicious":
            s = 90
            indicators.append("maltiverse:malicious")
        elif cls == "suspicious":
            s = 60
            indicators.append("maltiverse:suspicious")

    if vt.get("available") and vt.get("found"):
        mal = int(vt.get("malicious") or 0) + int(vt.get("suspicious") or 0)
        s = max(s, min(100, mal * 6))
        if mal > 0:
            indicators.append(f"vt:{mal}detections")

    score = min(s, 100)
    return ThreatVerdict(
        score=score,
        action=_action_from_score(score),
        reason=_reason_from_indicators(indicators, score),
        ioc_type="hash",
        indicators=indicators,
    )


def score_with_israeli_factors(base_score: int, il_domain: dict, hebrew_phish: dict) -> int:
    """ניקוד עם גורמים ישראליים"""
    score = base_score

    if il_domain.get("is_il_domain"):
        if il_domain.get("suspicious_indicators"):
            score += len(il_domain["suspicious_indicators"]) * 15
            score = min(score + 25, 100)

    if hebrew_phish.get("hebrew_detected"):
        score += hebrew_phish.get("risk_score", 0)
        score = min(score + 30, 100)

    return min(score, 100)


def verdict_emoji(score: int) -> str:
    if score >= 75:
        return "🔴 זדוני סביר"
    if score >= 40:
        return "🟠 חשוד"
    if score >= 10:
        return "🟡 לבדוק"
    return "🟢 נקי"


def _action_from_score(score: int) -> str:
    """Map score to recommended action for the FSM pipeline."""
    if score >= _BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= _ALERT_THRESHOLD:
        return "ALERT"
    if score >= 10:
        return "MONITOR"
    return "CLEAN"


def _reason_from_indicators(indicators: list[str], score: int) -> str:
    """Build human-readable reason from indicators list."""
    if not indicators:
        return f"score={score} (no specific indicators)"
    return f"score={score} ({', '.join(indicators)})"


def apply_decay(
    current_score: int,
    historical_decayed: float,
    max_total: int = 100,
) -> int:
    """Combine current score with decayed historical score.

    Formula: S_total = min(max_total, S_current + S_decayed_history)
    The historical score is pre-decayed by the caller (ioc_memory_store).

    This is pure math — no I/O. The caller handles DB recall + save.
    """
    combined = current_score + historical_decayed
    return min(max_total, int(round(combined)))


def assess_ip_with_history(
    abuse: dict,
    maltiverse: dict,
    vt: dict,
    ipapi: dict,
    shodan: dict,
    historical_decayed: float = 0.0,
) -> ThreatVerdict:
    """Assess IP with temporal correlation (decayed historical score).

    Args:
        historical_decayed: Pre-decayed sum of past scores (from ioc_memory_store).
            0.0 if no history. The caller is responsible for DB recall + save.
    """
    verdict = assess_ip(abuse, maltiverse, vt, ipapi, shodan)
    if historical_decayed <= 0:
        return verdict

    boosted = apply_decay(verdict.score, historical_decayed)
    if boosted > verdict.score:
        indicators = verdict.indicators + [f"history:+{boosted - verdict.score}"]
        return ThreatVerdict(
            score=boosted,
            action=_action_from_score(boosted),
            reason=_reason_from_indicators(indicators, boosted),
            ioc_type="ip",
            indicators=indicators,
        )
    return verdict
