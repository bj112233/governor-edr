# tests/test_security_sitrep.py
"""Tests for generate_security_sitrep — LLM executive summary in daily report.

Verifies the SITREP is generated from parsed alert fields, fed to the LLM,
and inserted into the daily report before the point-by-point alert list.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.startup._reporting import build_daily_report, generate_security_sitrep

_HEADER = "🟠 התראת Sentinel [WARN]\n━━━\n"
_CPU = _HEADER + "קטגוריה: CPU\nמדד: cpu_spike\nערך נוכחי: 14.7%\nבסיס: μ=2.5, σ=2.0\n\nz=6.1"
_NET = _HEADER + "קטגוריה: NET\nמדד: new_external_ip\n\nחיבור חדש: 185.220.101.34"

_ALERTS = [
    ("2026-06-30 11:31:24", "cpu:cpu_spike", _CPU),
    ("2026-06-30 09:15:00", "net:new_external_ip", _NET),
]


async def test_empty_alerts_returns_empty():
    result = await generate_security_sitrep([], "• CPU: 5% | RAM: 50%")
    assert result == ""


async def test_sitrep_calls_llm_with_alert_data():
    bridge = MagicMock()
    bridge.complete = AsyncMock(return_value="## סיכום\nמגמת CPU גבוהה.")
    with (
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
    ):
        result = await generate_security_sitrep(_ALERTS, "• CPU: 5% | RAM: 50%")
    assert "## סיכום" in result
    # Verify LLM was called with alert data
    call_args = bridge.complete.call_args
    user_input = call_args.kwargs.get("user_input") or call_args.args[0]
    assert "cpu_spike" in user_input or "CPU" in user_input
    assert "14.7" in user_input
    assert "z=6.1" in user_input


async def test_sitrep_failure_returns_empty():
    with patch("services.llm_bridge.LLMBridge.get_instance", side_effect=Exception("LLM down")):
        result = await generate_security_sitrep(_ALERTS, "• CPU: 5%")
    assert result == ""


async def test_build_daily_report_includes_sitrep_section():
    """Daily report must contain SITREP section before alert list."""
    snapshot = {"cpu": 5, "mem": 50, "disk_alerts": [], "top_procs": []}
    bridge = MagicMock()
    bridge.complete = AsyncMock(return_value="## SITREP\nהכל תקין.")
    with (
        patch("services.startup._reporting.get_system_snapshot", new_callable=AsyncMock, return_value=snapshot),
        patch("services.startup._reporting.get_alerts_last_24h", new_callable=AsyncMock, return_value=_ALERTS),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.startup._reporting.DAILY_REPORT_INCLUDE_TOP_PROCS", False),
    ):
        report = await build_daily_report()
    assert "SITREP אבטחה" in report
    assert "## SITREP" in report
    # SITREP must appear before the alert list
    sitrep_pos = report.find("SITREP אבטחה")
    alerts_pos = report.find("התראות 24 שעות")
    assert sitrep_pos < alerts_pos


async def test_build_daily_report_without_sitrep_if_llm_fails():
    """If LLM fails, report still has alerts but no SITREP section."""
    snapshot = {"cpu": 5, "mem": 50, "disk_alerts": [], "top_procs": []}
    with (
        patch("services.startup._reporting.get_system_snapshot", new_callable=AsyncMock, return_value=snapshot),
        patch("services.startup._reporting.get_alerts_last_24h", new_callable=AsyncMock, return_value=_ALERTS),
        patch("services.llm_bridge.LLMBridge.get_instance", side_effect=Exception("LLM down")),
        patch("services.startup._reporting.DAILY_REPORT_INCLUDE_TOP_PROCS", False),
    ):
        report = await build_daily_report()
    assert "SITREP אבטחה" not in report
    assert "התראות 24 שעות" in report


async def test_build_daily_report_no_alerts_no_sitrep():
    """No alerts → no SITREP call, no SITREP section."""
    snapshot = {"cpu": 5, "mem": 50, "disk_alerts": [], "top_procs": []}
    bridge = MagicMock()
    bridge.complete = AsyncMock(return_value="should not be called")
    with (
        patch("services.startup._reporting.get_system_snapshot", new_callable=AsyncMock, return_value=snapshot),
        patch("services.startup._reporting.get_alerts_last_24h", new_callable=AsyncMock, return_value=[]),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.startup._reporting.DAILY_REPORT_INCLUDE_TOP_PROCS", False),
        patch("services.startup._reporting._get_hunt_summary_line", new_callable=AsyncMock, return_value=""),
    ):
        report = await build_daily_report()
    assert "SITREP" not in report
    bridge.complete.assert_not_called()


async def test_build_daily_report_includes_hunt_summary():
    """Daily report must include OSINT hunt line when hunts exist."""
    snapshot = {"cpu": 5, "mem": 50, "disk_alerts": [], "top_procs": []}
    bridge = MagicMock()
    bridge.complete = AsyncMock(return_value="## SITREP\nok")
    hunt_line = "• 3 הנטים | דירוג ממוצע: 45.2 | שוגרו: 1 | עליון: CVE-2026-1234 exploit"
    with (
        patch("services.startup._reporting.get_system_snapshot", new_callable=AsyncMock, return_value=snapshot),
        patch("services.startup._reporting.get_alerts_last_24h", new_callable=AsyncMock, return_value=_ALERTS),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.startup._reporting.DAILY_REPORT_INCLUDE_TOP_PROCS", False),
        patch("services.startup._reporting._get_hunt_summary_line", new_callable=AsyncMock, return_value=hunt_line),
    ):
        report = await build_daily_report()
    assert "OSINT Hunts" in report
    assert "3 הנטים" in report
    assert "45.2" in report


async def test_build_daily_report_no_hunt_section_when_empty():
    """No hunts → no OSINT Hunts section."""
    snapshot = {"cpu": 5, "mem": 50, "disk_alerts": [], "top_procs": []}
    bridge = MagicMock()
    bridge.complete = AsyncMock(return_value="## SITREP\nok")
    with (
        patch("services.startup._reporting.get_system_snapshot", new_callable=AsyncMock, return_value=snapshot),
        patch("services.startup._reporting.get_alerts_last_24h", new_callable=AsyncMock, return_value=_ALERTS),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.startup._reporting.DAILY_REPORT_INCLUDE_TOP_PROCS", False),
        patch("services.startup._reporting._get_hunt_summary_line", new_callable=AsyncMock, return_value=""),
    ):
        report = await build_daily_report()
    assert "OSINT Hunts" not in report


async def test_get_hunt_summary_line_with_hunts():
    """_get_hunt_summary_line returns focused one-liner."""
    from services.startup._reporting import _get_hunt_summary_line

    hunts = [
        {
            "timestamp": "2026-06-30T10:00",
            "threat_score": 80.0,
            "summary": "CVE-2026-1234 critical exploit",
            "dispatched": True,
        },
        {"timestamp": "2026-06-30T08:00", "threat_score": 20.0, "summary": "low priority scan", "dispatched": False},
    ]
    with patch("services.memory_db.get_hunts_last_24h", new_callable=AsyncMock, return_value=hunts):
        line = await _get_hunt_summary_line()
    assert "2 הנטים" in line
    assert "50.0" in line  # avg score
    assert "1" in line  # dispatched count
    assert "CVE-2026-1234" in line  # top hunt summary


async def test_get_hunt_summary_line_empty():
    """No hunts → empty string."""
    from services.startup._reporting import _get_hunt_summary_line

    with patch("services.memory_db.get_hunts_last_24h", new_callable=AsyncMock, return_value=[]):
        line = await _get_hunt_summary_line()
    assert line == ""
