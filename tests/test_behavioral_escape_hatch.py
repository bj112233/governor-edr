"""Tests for Behavioral Escape Hatch — overrides clean-IOC clamp on anomalies."""

from unittest.mock import MagicMock, patch

import pytest

from services.behavioral_escape_hatch import (
    _BEHAVIORAL_CLAMP_2_3,
    _BEHAVIORAL_CLAMP_4_PLUS,
    _BEHAVIORAL_CLAMP_TTP,
    compute_behavioral_clamp,
    count_behavioral_anomalies,
    has_local_ttp,
)


class TestCountBehavioralAnomalies:
    def test_zero_anomalies_clean_system(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = []
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 0 and not has_behavioral

    def test_cpu_spike_alert_counts(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("2026-01-01", "cpu:cpu_spike", "report")]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and not has_behavioral

    def test_ram_anomaly_alert_counts(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("2026-01-01", "ram:ram_drop", "report")]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and not has_behavioral

    def test_new_external_ip_alert_counts(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("2026-01-01", "net:new_external_ip", "report")]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and has_behavioral

    def test_disk_alerts_in_snapshot_counts(self):
        snapshot = {"disk_alerts": [{"disk": "C:"}], "suspicious_net": [], "suspicious_procs": []}
        alerts = []
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and has_behavioral

    def test_suspicious_net_in_snapshot_counts(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [{"ip": "1.2.3.4"}], "suspicious_procs": []}
        alerts = []
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and has_behavioral

    def test_suspicious_procs_in_snapshot_counts(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": [{"pid": 1, "name": "powershell.exe"}]}
        alerts = []
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and has_behavioral

    def test_all_six_signals_count_as_6(self):
        snapshot = {
            "disk_alerts": [{"disk": "C:"}],
            "suspicious_net": [{"ip": "1.2.3.4"}],
            "suspicious_procs": [{"pid": 1, "name": "powershell.exe"}],
        }
        alerts = [
            ("2026-01-01", "cpu:cpu_spike", "r"),
            ("2026-01-01", "ram:ram_drop", "r"),
            ("2026-01-01", "net:new_external_ip", "r"),
        ]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 6 and has_behavioral

    def test_each_alert_signal_counted_once_max(self):
        """Multiple cpu_spike alerts should only count as 1 signal."""
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [
            ("2026-01-01", "cpu:cpu_spike", "r1"),
            ("2026-01-01", "cpu:cpu_spike", "r2"),
            ("2026-01-01", "cpu:cpu_spike", "r3"),
        ]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 1 and not has_behavioral

    def test_resource_only_noise_no_behavioral(self):
        """S-7: CPU+RAM+disk without net/proc → has_behavioral=False (disk counts as behavioral)."""
        snapshot = {"disk_alerts": [{"disk": "C:"}], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "ram:ram_drop", "r")]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 3 and has_behavioral  # disk is behavioral

    def test_resource_only_no_disk_no_behavioral(self):
        """S-7: CPU+RAM only (no net/proc/disk) → has_behavioral=False."""
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "ram:ram_drop", "r")]
        count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
        assert count == 2 and not has_behavioral


class TestHasLocalTtp:
    def test_no_suspicious_procs(self):
        snapshot = {"suspicious_procs": []}
        assert has_local_ttp(snapshot) is False

    def test_procs_without_cmdline(self):
        snapshot = {"suspicious_procs": [{"pid": 1, "name": "powershell.exe", "cmdline": ""}]}
        assert has_local_ttp(snapshot) is False

    def test_procs_with_clean_cmdline(self):
        with patch("services.cmdline_analyzer.analyze_cmdline", return_value=[]):
            snapshot = {"suspicious_procs": [{"pid": 1, "name": "powershell.exe", "cmdline": "Get-Process"}]}
            assert has_local_ttp(snapshot) is False

    def test_procs_with_ttp_match_high_score(self):
        mock_match = MagicMock()
        mock_match.suggested_score = 90
        with patch("services.cmdline_analyzer.analyze_cmdline", return_value=[mock_match]):
            snapshot = {"suspicious_procs": [{"pid": 1, "name": "powershell.exe", "cmdline": "-enc SGVsbG8="}]}
            assert has_local_ttp(snapshot) is True

    def test_procs_with_ttp_match_low_score_ignored(self):
        """Score < 70 should NOT trigger TTP override (low confidence)."""
        mock_match = MagicMock()
        mock_match.suggested_score = 50
        with patch("services.cmdline_analyzer.analyze_cmdline", return_value=[mock_match]):
            snapshot = {"suspicious_procs": [{"pid": 1, "name": "powershell.exe", "cmdline": "something"}]}
            assert has_local_ttp(snapshot) is False


class TestComputeBehavioralClamp:
    BASE_CLAMP = 0.4

    def test_zero_anomalies_returns_base_clamp(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = []
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=False):
            result = compute_behavioral_clamp(snapshot, alerts, 0.8, self.BASE_CLAMP)
        assert result == self.BASE_CLAMP

    def test_two_anomalies_returns_elevated_clamp(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "ram:ram_drop", "r")]
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=False):
            result = compute_behavioral_clamp(snapshot, alerts, 0.8, self.BASE_CLAMP)
        assert result == _BEHAVIORAL_CLAMP_2_3

    def test_four_anomalies_returns_dispatch_clamp(self):
        snapshot = {
            "disk_alerts": [{"disk": "C:"}],
            "suspicious_net": [{"ip": "1.2.3.4"}],
            "suspicious_procs": [],
        }
        alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "net:new_external_ip", "r")]
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=False):
            result = compute_behavioral_clamp(snapshot, alerts, 0.8, self.BASE_CLAMP)
        assert result == _BEHAVIORAL_CLAMP_4_PLUS

    def test_ttp_match_returns_full_override(self):
        """MITRE TTP match overrides everything — even with 0 anomalies."""
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = []
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=True):
            result = compute_behavioral_clamp(snapshot, alerts, 0.8, self.BASE_CLAMP)
        assert result == _BEHAVIORAL_CLAMP_TTP

    def test_ttp_overrides_even_with_zero_anomalies(self):
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = []
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=True):
            result = compute_behavioral_clamp(snapshot, alerts, 0.5, self.BASE_CLAMP)
        assert result == 1.0

    def test_three_anomalies_still_elevated_not_dispatch(self):
        """3 anomalies = elevated (0.50), NOT dispatch (0.70)."""
        snapshot = {"disk_alerts": [], "suspicious_net": [], "suspicious_procs": []}
        alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "ram:ram_drop", "r"), ("ts", "net:new_external_ip", "r")]
        with patch("services.behavioral_escape_hatch.has_local_ttp", return_value=False):
            result = compute_behavioral_clamp(snapshot, alerts, 0.8, self.BASE_CLAMP)
        assert result == _BEHAVIORAL_CLAMP_2_3
