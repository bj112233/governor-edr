# tests/test_alert_history_query.py
"""Unit tests for alert_history_query formatters.

Covers `format_daily_summary` readability fix: Hebrew labels, severity
breakdown, peak z-score, baseline, compact time list, executive summary,
empty case, and unknown-trigger fallback.
"""

import pytest

# Import the parent module first to resolve the circular re-export chain
# (alert_history.py re-exports from alert_history_query.py at its bottom).
import services.alert_history  # noqa: F401
from services.alert_history_query import (
    _parse_alert_report,
    format_daily_summary,
)

_CPU = (
    "🟠 התראת Sentinel [WARN]\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "קטגוריה: CPU\n"
    "מדד: cpu_spike\n"
    "ערך נוכחי: 14.7%\n"
    "בסיס: μ=2.5, σ=2.0\n\n"
    "CPU sustained spike: 14.7% (baseline μ=2.5, σ=2.0, z=6.1)"
)
_NET = (
    "🟡 התראת Sentinel [SUSPICIOUS]\n"
    "━━━━━━━━━━━━━━━━━━━━━━\n"
    "קטגוריה: רשת / איומים\n"
    "סטטוס: suspicious\n\n"
    "New external IP: 1.2.3.4"
)


def _cpu(value: float, z: float) -> str:
    return _CPU.replace("14.7%", f"{value}%").replace("z=6.1", f"z={z}")


# ── _parse_alert_report ──────────────────────────────────────────────


def test_parse_extracts_all_fields():
    p = _parse_alert_report(_CPU)
    assert p["sev"] == "WARN"
    assert p["sev_icon"] == "🟠"
    assert p["cat"] == "CPU"
    assert p["metric"] == "cpu_spike"
    assert p["current"] == pytest.approx(14.7)
    assert p["mu"] == pytest.approx(2.5)
    assert p["sigma"] == pytest.approx(2.0)
    assert p["z"] == pytest.approx(6.1)


def test_parse_falls_back_to_leading_emoji_on_malformed_text():
    # Missing the "[WARN]" token but leading emoji present.
    p = _parse_alert_report("🟠 תראת פגומה\nקטגוריה: CPU\nמדד: cpu_spike")
    assert p["sev_icon"] == "🟠"
    assert p["sev"] == "WARN"


def test_parse_empty_report_returns_defaults():
    p = _parse_alert_report("")
    assert p["sev"] is None
    assert p["sev_icon"] == "⚪"
    assert p["current"] is None


def test_parse_network_alert_has_no_continuous_fields():
    p = _parse_alert_report(_NET)
    assert p["sev"] == "SUSPICIOUS"
    assert p["sev_icon"] == "🟡"
    assert p["cat"] == "רשת / איומים"
    assert p["current"] is None
    assert p["z"] is None


# ── format_daily_summary ─────────────────────────────────────────────


def test_empty_alerts_returns_placeholder():
    assert "אין התראות" in format_daily_summary([])


def test_summary_has_executive_header_with_severity_split():
    alerts = [
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _cpu(14.7, 6.1)),
        ("2026-06-30 06:28:57", "cpu:cpu_spike", _cpu(9.5, 3.6)),
        ("2026-06-29 16:57:28", "net:new_external_ip", _NET),
    ]
    out = format_daily_summary(alerts)
    assert "3 התראות" in out
    assert "🟠 2" in out
    assert "🟡 1" in out
    assert "דומיננטית" in out


def test_summary_group_shows_peak_z_and_baseline():
    alerts = [
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _cpu(14.7, 6.1)),
        ("2026-06-30 06:28:57", "cpu:cpu_spike", _cpu(9.5, 3.6)),
    ]
    out = format_daily_summary(alerts)
    assert "🖥️ CPU — זינוק מעורפל" in out
    assert "שיא: 14.7%" in out
    assert "z=6.1" in out
    assert "בסיס μ=2.5 σ=2.0" in out
    assert "06:53" in out


def test_summary_compact_time_list_truncates_with_remainder():
    alerts = [
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _cpu(14.7, 6.1)),
        ("2026-06-30 06:28:57", "cpu:cpu_spike", _cpu(9.5, 3.6)),
        ("2026-06-30 02:21:39", "cpu:cpu_spike", _cpu(12.2, 5.9)),
    ]
    out = format_daily_summary(alerts, max_alerts=2)
    assert "+1" in out
    assert "02:21" not in out.split("+1")[0]  # truncated beyond max_alerts


def test_summary_unknown_trigger_falls_back_to_raw_key():
    # Report with an unrecognized category → label falls back to raw trigger key.
    report = "🟠 התראת Sentinel [WARN]\nקטגוריה: FOO\nמדד: bar_baz\nערך נוכחי: 5.0%\n\nx z=1.0"
    alerts = [("2026-06-30 08:00:00", "foo:bar_baz", report)]
    out = format_daily_summary(alerts)
    assert "foo:bar_baz" in out


def test_summary_groups_sorted_by_count_descending():
    alerts = [
        ("2026-06-29 16:57:28", "net:new_external_ip", _NET),
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _cpu(14.7, 6.1)),
        ("2026-06-30 06:28:57", "cpu:cpu_spike", _cpu(9.5, 3.6)),
    ]
    out = format_daily_summary(alerts)
    cpu_pos = out.find("🖥️ CPU")
    net_pos = out.find("🌐 רשת")
    assert cpu_pos < net_pos  # CPU (2) before Net (1)


def test_summary_ram_drop_negative_z_shown():
    drop = (
        "🟠 התראת Sentinel [WARN]\n"
        "קטגוריה: RAM\nמדד: ram_drop\nערך נוכחי: 21.0%\n"
        "בסיס: μ=37.0, σ=2.0\n\nRAM drop z=-8.0"
    )
    out = format_daily_summary([("2026-06-29 21:41:04", "ram:ram_drop", drop)])
    assert "z=-8.0" in out
    assert "💾 RAM — צניחת זיכרון" in out
