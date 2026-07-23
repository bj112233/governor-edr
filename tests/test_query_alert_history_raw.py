# tests/test_query_alert_history_raw.py
"""Tests for query_alert_history_raw readability fix.

Verifies the function uses _parse_alert_report for clean output instead
of dumping raw report text with broken severity detection.
"""

from unittest.mock import AsyncMock, patch

import pytest

# Import parent module first to resolve circular re-export chain.
import services.alert_history  # noqa: F401
from services.alert_history_query import query_alert_history_raw

_HEADER = "🟠 התראת Sentinel [WARN]\n━━━━━━━━━━━━━━━━━━━━━━\n"
_CPU = _HEADER + "קטגוריה: CPU\nמדד: cpu_spike\nערך נוכחי: 14.7%\nבסיס: μ=2.5, σ=2.0\n\nz=6.1"
_NET = _HEADER + "קטגוריה: NET\nמדד: new_external_ip\n\nחיבור חדש: 185.220.101.34"
_PROC = _HEADER + "קטגוריה: PROC\nמדד: new_heavy_process\n\nminer.exe (PID 666) — 85.3% CPU"
_CRIT = "🔴 התראת Sentinel [CRITICAL]\n━━━\nקטגוריה: PROC\nמדד: ttp_detected\n\nMITRE T1059.001"


async def test_empty_alerts():
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=[]):
        result = await query_alert_history_raw(0)
    assert "אין התראות" in result


async def test_cpu_spike_clean_output():
    alerts = [("2026-06-30 06:53:14", "cpu:cpu_spike", _CPU)]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "🟠" in result
    assert "ערך: 14.7%" in result
    assert "z=6.1" in result
    assert "μ=2.5 σ=2.0" in result
    assert "התראת Sentinel" not in result


async def test_severity_correct_not_always_low():
    """Old code always returned 🟢 Low for new-format alerts. Verify fix."""
    alerts = [
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _CPU),
        ("2026-06-30 06:00:00", "proc:ttp_detected", _CRIT),
    ]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "🟠" in result
    assert "🔴" in result
    assert "🟢 Low" not in result


async def test_net_alert_extracts_ip():
    alerts = [("2026-06-30 09:15:00", "net:new_external_ip", _NET)]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "185.220.101.34" in result


async def test_proc_alert_extracts_name_and_cpu():
    alerts = [("2026-06-30 08:00:00", "proc:new_heavy_process", _PROC)]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "miner.exe" in result
    assert "85.3%" in result


async def test_label_uses_hebrew_not_raw_trigger():
    alerts = [("2026-06-30 06:53:14", "cpu:cpu_spike", _CPU)]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "🖥️ CPU" in result


async def test_fallback_strips_separators_for_unknown_metric():
    alerts = [("2026-06-30 08:00:00", "foo:bar", "raw text\n━━━━━━\nwith separators")]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    # SEPARATOR header is intentional; raw report ━ must be stripped from detail.
    detail = [ln for ln in result.split("\n") if "raw text" in ln]
    assert detail and "━" not in detail[0]
    assert "raw text" in result


async def test_multiple_alerts_numbered():
    alerts = [
        ("2026-06-30 06:53:14", "cpu:cpu_spike", _CPU),
        ("2026-06-30 06:28:57", "cpu:cpu_spike", _CPU.replace("14.7", "9.5").replace("6.1", "3.6")),
        ("2026-06-30 09:15:00", "net:new_external_ip", _NET),
    ]
    with patch("services.alert_history_query.get_recent_alerts", new_callable=AsyncMock, return_value=alerts):
        result = await query_alert_history_raw(10)
    assert "**#1**" in result
    assert "**#2**" in result
    assert "**#3**" in result
