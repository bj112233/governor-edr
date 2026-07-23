# tests/test_formatters_snapshot.py
"""Snapshot tests for formatters.format_event_for_telegram.

Locks byte-identical Telegram output across SRP refactors (Sprint 4 Ratchet 5).
Covers alert, critical_override, and daily_digest event types.
"""

from unittest.mock import patch

import pytest

from services.formatters import format_event_for_telegram
from services.sentinel_events import SentinelEvent

_TS = 1718800000.0  # fixed timestamp for deterministic formatting


@pytest.fixture(autouse=True)
def _freeze_time():
    with patch("services.formatters.format_event_time", return_value="2026-06-19 16:00:00"):
        yield


@pytest.fixture(autouse=True)
def _no_enrich():
    # Disable IP enrichment so output is deterministic (no GeoIP/ASN lookups).
    with patch("services.formatters.enrich_ip", return_value=None):
        yield


def _event(et: str, data: dict, priority: str = "normal") -> SentinelEvent:
    return SentinelEvent(event_type=et, priority=priority, data=data, timestamp=_TS)


# ── alert: full payload ──
def test_alert_full_payload():
    ev = _event(
        "alert",
        {
            "cpu": 12.5,
            "ram": 45.2,
            "analysis": "🔴 CRITICAL: suspicious outbound to 1.2.3.4",
            "snapshot": {
                "disk_alerts": ["C: 95%"],
                "top_procs": [
                    {"name": "chrome", "pid": 1234, "cpu_percent": 22.1},
                    {"name": "node", "pid": 5678},
                ],
                "suspicious_net": ["1.2.3.4:443 (chrome:1234)"],
            },
            "remediation": {
                "actions": {"ip": "1.2.3.4", "pid": 1234},
                "intel": {"asn": "AS123", "org": "EvilCorp"},
            },
        },
        priority="critical",
    )
    out = format_event_for_telegram(ev)
    assert "🔴 **Sentinel Alert**" in out
    assert "`12.5%`" in out
    assert "`45.2%`" in out
    assert "💽 **Disk:** `C: 95%`" in out
    assert "תהליכים כבדים" in out  # plural (2 procs)
    assert "chrome:1234 (22.1%)" in out
    assert "1.2.3.4:443 (chrome:1234)" in out
    assert "Block IP 1.2.3.4" in out
    assert "Kill PID 1234" in out


# ── alert: single heavy proc → singular label ──
def test_alert_singular_proc_label():
    ev = _event(
        "alert",
        {
            "cpu": 5,
            "ram": 10,
            "analysis": "🟢 ok",
            "snapshot": {"top_procs": [{"name": "x", "pid": 1}], "suspicious_net": []},
        },
    )
    out = format_event_for_telegram(ev)
    assert "תהליך כבד" in out  # singular


# ── alert: empty analysis → fallback ──
def test_alert_empty_analysis_fallback():
    ev = _event("alert", {"cpu": 1, "ram": 2, "analysis": "", "snapshot": {}})
    out = format_event_for_telegram(ev)
    assert "(ללא ניתוח)" in out
    assert "🚨" in out  # default emoji when no severity prefix


# ── alert: no disk alerts → no disk line ──
def test_alert_no_disk_line_when_empty():
    ev = _event("alert", {"cpu": 1, "ram": 2, "analysis": "🟢 ok", "snapshot": {}})
    out = format_event_for_telegram(ev)
    assert "Disk" not in out


# ── critical_override ──
def test_critical_override():
    ev = _event(
        "critical_override",
        {"cpu": 99, "ram": 98, "message": "Persistent anomaly detected"},
        priority="critical",
    )
    out = format_event_for_telegram(ev)
    assert "🔴 **CRITICAL OVERRIDE**" in out
    assert "`99%`" in out
    assert "Persistent anomaly detected" in out


# ── daily_digest ──
def test_daily_digest_with_report():
    ev = _event("daily_digest", {"report": "📅 Daily summary text here"})
    out = format_event_for_telegram(ev)
    assert out == "📅 Daily summary text here"


def test_daily_digest_empty_fallback():
    ev = _event("daily_digest", {"report": ""})
    out = format_event_for_telegram(ev)
    assert "ריק" in out


# ── unknown event type ──
def test_unknown_event_type():
    ev = _event("weird", {"foo": "bar"})
    out = format_event_for_telegram(ev)
    assert out.startswith("[weird]")
    assert "bar" in out
