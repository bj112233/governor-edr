# tests/test_alert_dispatcher.py
"""Unit tests for alert_dispatcher gates and formatting."""

import asyncio
from unittest.mock import patch

from services.alert_dispatcher import AlertDispatcher
from services.monitor_analyzer import AnomalyEvent
from services.threat_classifier import ThreatAssessment


def _anomaly(severity: str = "warn") -> AnomalyEvent:
    return AnomalyEvent(
        category="cpu",
        metric="cpu_zscore",
        current=80.0,
        baseline=50.0,
        std=10.0,
        severity=severity,
        reason="CPU high",
    )


def _run(coro):
    return asyncio.run(coro)


# ── Severity gate ──


def test_severity_gate_blocks_info():
    dispatcher = AlertDispatcher()
    with (
        patch("services.alert_dispatcher_helpers.send_alert_event") as mock_send,
        patch("services.alert_dispatcher_helpers.save_alert"),
    ):
        result = _run(dispatcher.dispatch([_anomaly("info")]))
        assert result.sent == 0
        assert result.suppressed_severity == 1
        mock_send.assert_not_called()


def test_severity_gate_passes_warn():
    dispatcher = AlertDispatcher()
    with (
        patch("services.alert_dispatcher_helpers.send_alert_event") as mock_send,
        patch("services.alert_dispatcher_helpers.save_alert"),
    ):
        result = _run(dispatcher.dispatch([_anomaly("warn")]))
        assert result.sent == 1
        assert result.suppressed_severity == 0
        mock_send.assert_called_once()


# ── Cooldown gate ──


def test_cooldown_blocks_duplicate_within_window():
    dispatcher = AlertDispatcher(cooldown_seconds=60.0)
    with (
        patch("services.alert_dispatcher_helpers.send_alert_event") as mock_send,
        patch("services.alert_dispatcher_helpers.save_alert"),
    ):
        # First dispatch: sent
        result = _run(dispatcher.dispatch([_anomaly("warn")]))
        assert result.sent == 1
        assert mock_send.call_count == 1

        # Immediate duplicate: blocked
        result = _run(dispatcher.dispatch([_anomaly("warn")]))
        assert result.sent == 0
        assert result.suppressed_cooldown == 1
        assert mock_send.call_count == 1  # still only 1 send


# ── Rate-limit gate ──


def test_rate_limit_blocks_overflow():
    # cooldown=0 so alerts reach rate-limit gate (not blocked by cooldown first)
    dispatcher = AlertDispatcher(cooldown_seconds=0.0, max_alerts_per_window=2, rate_limit_window=60.0)
    with (
        patch("services.alert_dispatcher_helpers.send_alert_event") as mock_send,
        patch("services.alert_dispatcher_helpers.save_alert"),
    ):
        result = _run(dispatcher.dispatch([_anomaly("warn"), _anomaly("warn"), _anomaly("warn")]))
        assert result.sent == 2
        assert result.suppressed_rate_limit == 1
        assert mock_send.call_count == 2  # only 2 sent


# ── Unify + Format ──


def test_unify_combines_anomalies_and_threats():
    dispatcher = AlertDispatcher()
    anomalies = [_anomaly("warn")]
    threats = [ThreatAssessment(status="suspicious", reason="beaconing")]
    unified = dispatcher._unify(anomalies, threats)
    assert len(unified) == 2
    assert unified[0]["type"] == "anomaly"
    assert unified[1]["type"] == "threat"


def test_format_alert_no_duplicate_snapshot_context():
    """The alert narrative must NOT repeat header info (time/CPU/RAM/disk):
    those are rendered once by formatters.format_event_for_telegram. The
    snapshot arg is accepted for backward compat but intentionally unused
    in the narrative body."""
    dispatcher = AlertDispatcher()
    alert = {
        "type": "anomaly",
        "category": "cpu",
        "metric": "cpu_zscore",
        "severity": "warn",
        "current": 80.0,
        "baseline": 50.0,
        "std": 10.0,
        "reason": "CPU sustained high",
    }
    text = dispatcher._format_alert(alert, snapshot={"cpu": 99.0, "mem": 60.0})
    assert "Sentinel" in text
    assert "CPU sustained high" in text  # narrative present
    assert "ערך נוכחי: 80.0%" in text  # alert-intrinsic, not snapshot
    # Snapshot-context lines must NOT appear (would duplicate header).
    assert "99.0%" not in text  # snapshot cpu absent
    assert "📊" not in text  # header symbol absent
    assert "💾" not in text  # disk symbol absent
    assert "זמן:" not in text  # time line absent
