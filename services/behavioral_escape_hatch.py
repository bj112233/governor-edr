# services/behavioral_escape_hatch.py
"""Behavioral Escape Hatch — overrides clean-IOC clamp when local behavior is anomalous.

Physical law: "A clean network signature does NOT cancel a malicious
behavioral signature." Attackers live on trusted cloud (Azure/AWS/GCP).
When all IOCs are clean per intel but the LOCAL behavior is anomalous,
the clamp is lifted in tiers — preventing false negatives on cloud C2.

Tiers (applied when pre_hunt.all_clean == True):
  0-1 anomalies → 0.40 (hard clamp, cloud wins, LLM silenced)
  2-3 anomalies → 0.50 (elevated, logged, no dispatch)
  4+  anomalies → 0.70 (crosses 0.6 dispatch — behavioral evidence)
  MITRE TTP     → 1.00 (full override — local TTP is ground truth)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# ── Clamp tiers ────────────────────────────────────────────────────────────
_BEHAVIORAL_CLAMP_2_3 = 0.50  # 2-3 anomalies: elevated (logged, no dispatch)
_BEHAVIORAL_CLAMP_4_PLUS = 0.70  # 4+ anomalies: crosses 0.6 dispatch threshold
_BEHAVIORAL_CLAMP_TTP = 1.0  # MITRE TTP match: full override

# ── Alert-history trigger patterns (3 categories, counted once each) ────────
# RAM spike + RAM drop count as ONE signal (RAM anomaly), not two.
_ALERT_CPU = "cpu_spike"
_ALERT_RAM = ("ram_spike", "ram_drop")
_ALERT_NET = "new_external_ip"

# S-7: Resource-only anomalies (CPU/RAM) are susceptible to Windows Update
# noise. Require at least one behavioral signal (net/proc/disk) to reach the
# 4+ tier — prevents low-severity resource noise from lifting the clamp.
_BEHAVIORAL_SIGNALS = ("net", "proc", "disk")


def count_behavioral_anomalies(
    snapshot: dict[str, Any],
    alerts: list[tuple],
) -> tuple[int, bool]:
    """Count distinct behavioral anomaly signals from snapshot + alert history.

    Signals (each counted once max):
    1. CPU spike in recent alerts (cpu:cpu_spike)
    2. RAM anomaly in recent alerts (ram:ram_spike OR ram:ram_drop)
    3. New external IP in recent alerts (net:new_external_ip)
    4. Disk alert in snapshot (disk_alerts non-empty)
    5. Suspicious network connections in snapshot (suspicious_net OR
       filtered_net — C1+C2 fix: filtered connections are CDN/cloud C2
       suspects when behavior is anomalous)
    6. Suspicious processes in snapshot (suspicious_procs non-empty)

    Returns (count, has_behavioral_signal). has_behavioral_signal is True
    when at least one signal is from net/proc/disk (not just CPU/RAM resource
    noise). Used by compute_behavioral_clamp to gate the 4+ tier.
    """
    count = 0
    has_behavioral = False
    alert_triggers = " ".join(t for _, t, _ in alerts).lower()

    # 1: CPU spike
    if _ALERT_CPU in alert_triggers:
        count += 1
    # 2: RAM anomaly (spike OR drop — counted once)
    if any(p in alert_triggers for p in _ALERT_RAM):
        count += 1
    # 3: New external IP
    if _ALERT_NET in alert_triggers:
        count += 1
        has_behavioral = True

    # 4: Disk alerts in snapshot
    if snapshot.get("disk_alerts"):
        count += 1
        has_behavioral = True

    # 5: Suspicious network connections — check BOTH suspicious_net
    # (survivors) AND filtered_net (CDN/cloud suppressed by noise filter).
    # C1+C2 fix: filtered_net contains cloud connections that are invisible
    # to IOC enrichment but are prime C2 suspects when behavior is anomalous.
    if snapshot.get("suspicious_net") or snapshot.get("filtered_net"):
        count += 1
        has_behavioral = True

    # 6: Suspicious processes (powershell/wmic/certutil/mshta running)
    if snapshot.get("suspicious_procs"):
        count += 1
        has_behavioral = True

    return count, has_behavioral


def has_local_ttp(snapshot: dict[str, Any]) -> bool:
    """Check if any suspicious process has a confirmed MITRE TTP match.

    Runs cmdline_analyzer on each suspicious process's command line.
    A TTP match (e.g. T1059.001 encoded command) is ground truth —
    it overrides ALL clean-IOC clamps, regardless of ISP reputation.
    """
    from services.cmdline_analyzer import analyze_cmdline

    procs = snapshot.get("suspicious_procs") or []
    for proc in procs:
        cmdline = proc.get("cmdline") or ""
        if not cmdline:
            continue
        matches = analyze_cmdline(cmdline)
        if matches and any(m.suggested_score >= 70 for m in matches):
            return True
    return False


def compute_behavioral_clamp(
    snapshot: dict[str, Any],
    alerts: list[tuple],
    llm_score: float,
    base_clamp: float,
) -> float:
    """Compute the effective clamp limit when all IOCs are clean per intel.

    Returns the clamp limit (not the final score — caller applies min()).
    Logs the tier decision for audit trail.
    """
    anomaly_count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
    has_ttp = has_local_ttp(snapshot)

    if has_ttp:
        clamp_limit = _BEHAVIORAL_CLAMP_TTP
        logger.warning(
            "[ThreatHunter] Behavioral Escape Hatch: MITRE TTP match overrides "
            "clean IOCs — clamp lifted to %.1f (local TTP is ground truth).",
            clamp_limit,
        )
    elif anomaly_count >= 4 and has_behavioral:
        # S-7: 4+ tier requires at least one behavioral signal (net/proc/disk).
        # Resource-only noise (CPU+RAM+disk from Windows Update) stays at 0.50.
        clamp_limit = _BEHAVIORAL_CLAMP_4_PLUS
        logger.warning(
            "[ThreatHunter] Behavioral Escape Hatch: %d anomalies (behavioral=True) — clamp lifted to %.2f "
            "(crosses dispatch threshold despite clean ISP).",
            anomaly_count,
            clamp_limit,
        )
    elif anomaly_count >= 2:
        clamp_limit = _BEHAVIORAL_CLAMP_2_3
        logger.info(
            "[ThreatHunter] Behavioral Escape Hatch: %d anomalies — clamp lifted to %.2f (elevated, below dispatch).",
            anomaly_count,
            clamp_limit,
        )
    else:
        clamp_limit = base_clamp
        logger.warning(
            "[ThreatHunter] All IOCs clean + %d anomalies — clamping LLM=%.2f to %.1f.",
            anomaly_count,
            llm_score,
            clamp_limit,
        )

    return clamp_limit
