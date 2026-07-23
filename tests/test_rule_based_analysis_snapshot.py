# tests/test_rule_based_analysis_snapshot.py
"""Snapshot tests for startup._workers._rule_based_analysis.

Locks the heuristic severity + category output across SRP refactors
(Sprint 4 Ratchet 7).
"""

import pytest

from services.startup._workers import _rule_based_analysis


def _snap(**kw):
    base = {"cpu": 0, "mem": 0, "disk_alerts": [], "suspicious_net": []}
    base.update(kw)
    return base


def test_low_severity_no_anomalies():
    out = _rule_based_analysis(_snap(cpu=10, mem=20))
    assert out.startswith("🟢 נמוכה")
    assert "כללית" in out


def test_critical_severity_cpu():
    out = _rule_based_analysis(_snap(cpu=95, mem=20))
    assert out.startswith("🔴 קריטית")


def test_critical_severity_ram():
    out = _rule_based_analysis(_snap(cpu=10, mem=98))
    assert out.startswith("🔴 קריטית")


def test_high_severity_disk_alert():
    out = _rule_based_analysis(_snap(cpu=10, mem=20, disk_alerts=["C: 95%"]))
    assert out.startswith("🟠 גבוהה")
    assert "אחסון" in out


def test_medium_severity_suspicious_net():
    out = _rule_based_analysis(_snap(cpu=10, mem=20, suspicious_net=["a", "b", "c", "d", "e", "f"]))
    assert out.startswith("🟡 בינונית")


def test_cpu_category():
    out = _rule_based_analysis(_snap(cpu=95, mem=20))
    assert "עומס CPU" in out


def test_ram_category():
    out = _rule_based_analysis(_snap(cpu=10, mem=98))
    assert "עומס זיכרון" in out


def test_suspicious_net_non_standard_ports():
    # Connections on non-standard ports → "רשת חשודה (N פורטים לא סטנדרטיים)"
    out = _rule_based_analysis(_snap(cpu=10, mem=20, suspicious_net=["1.2.3.4:22 (ssh:100)"]))
    assert "רשת חשודה" in out
    assert "פורטים לא סטנדרטיים" in out


def test_suspicious_net_standard_ports_only():
    # Port 443 is standard → "חיבורים חיצוניים (N)"
    out = _rule_based_analysis(_snap(cpu=10, mem=20, suspicious_net=["1.2.3.4:443 (chrome:100)"]))
    assert "חיבורים חיצוניים" in out
    assert "פורטים לא סטנדרטיים" not in out


def test_multiple_categories_joined():
    out = _rule_based_analysis(_snap(cpu=95, mem=98, disk_alerts=["C: 99%"]))
    assert "עומס CPU" in out
    assert "עומס זיכרון" in out
    assert "אחסון" in out
    assert " + " in out


def test_llm_unavailable_suffix():
    out = _rule_based_analysis(_snap(cpu=10, mem=20))
    assert "ניתוח heuristic (LLM unavailable)" in out
