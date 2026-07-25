# tests/test_process_analyzer.py
"""Tests for analyze_process_event — Sysmon-enriched wrapper.

Phase 1 (this file): base wrapper + parent anomaly (T1059.005).
Phase 2-4: hash, integrity, unsigned — added in subsequent commits.

None-handling is the critical contract: every Sysmon-enriched check
must skip gracefully when its field is None, falling back to
analyze_cmdline results alone. These tests pin that behavior.
"""

from __future__ import annotations

import pytest

from services.cmdline_analyzer import CmdlineMatch
from services.process_analyzer import _check_parent_anomaly, analyze_process_event
from services.process_event import ProcessEvent

# ── Base wrapper: always runs analyze_cmdline ──


class TestBaseWrapper:
    """analyze_process_event always runs analyze_cmdline, even on psutil path."""

    def test_clean_cmdline_returns_empty(self):
        ev = ProcessEvent(pid=1, name="notepad.exe", cmdline="notepad.exe")
        matches = analyze_process_event(ev)
        assert matches == []

    def test_powershell_encoded_command_detected(self):
        """The base regex engine must still fire on psutil path."""
        # base64 must be 20+ chars to match _ENCODED_FLAGS regex
        ev = ProcessEvent(pid=1, name="powershell.exe", cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
        matches = analyze_process_event(ev)
        assert len(matches) > 0
        # Should have T1059.001 from the regex engine
        techniques = [m.technique_id for m in matches]
        assert "T1059.001" in techniques

    def test_empty_cmdline_does_not_crash(self):
        ev = ProcessEvent(pid=4, name="System", cmdline="")
        matches = analyze_process_event(ev)
        assert matches == []

    def test_results_sorted_by_score_descending(self):
        """Matches should be sorted by suggested_score descending."""
        ev = ProcessEvent(
            pid=1,
            name="powershell.exe",
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            source="sysmon",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        if len(matches) >= 2:
            scores = [m.suggested_score for m in matches]
            assert scores == sorted(scores, reverse=True)

    def test_returns_list_of_cmdlinematch(self):
        ev = ProcessEvent(pid=1, name="x", cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
        matches = analyze_process_event(ev)
        for m in matches:
            assert isinstance(m, CmdlineMatch)


# ── Parent anomaly (T1059.005) ──


class TestParentAnomaly:
    """T1059.005 — suspicious parent→child chain."""

    def test_office_spawning_cmd_detected(self):
        """winword.exe → cmd.exe is classic macro dropper."""
        ev = ProcessEvent(
            pid=1234,
            name="cmd.exe",
            cmdline="cmd /c echo hacked",
            source="sysmon",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" in techniques

    def test_office_spawning_powershell_detected(self):
        ev = ProcessEvent(
            pid=1234,
            name="powershell.exe",
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            source="sysmon",
            parent_image=r"C:\Program Files\Microsoft Office\excel.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" in techniques

    def test_browser_spawning_powershell_detected(self):
        ev = ProcessEvent(
            pid=1234,
            name="powershell.exe",
            cmdline="powershell",
            source="sysmon",
            parent_image=r"C:\Program Files\Google\Chrome\chrome.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" in techniques

    def test_legitimate_parent_not_flagged(self):
        """explorer.exe → cmd.exe is normal user behavior, not anomalous."""
        ev = ProcessEvent(
            pid=1234,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            parent_image=r"C:\Windows\explorer.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques

    def test_office_spawning_legitimate_child_not_flagged(self):
        """winword.exe → some_other.exe (not in forbidden set) — no anomaly."""
        ev = ProcessEvent(
            pid=1234,
            name="some_other.exe",
            cmdline="some_other.exe",
            source="sysmon",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques


# ── None-handling: the critical contract ──


class TestNoneHandling:
    """Every Sysmon check must skip when its field is None."""

    def test_psutil_path_no_parent_check(self):
        """psutil event (parent_image=None) must not crash, must not
        produce T1059.005 (cannot check parent without parent_image)."""
        ev = ProcessEvent(
            pid=1234,
            name="cmd.exe",
            cmdline="cmd /c echo test",
            source="psutil",
            parent_image=None,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques

    def test_sysmon_with_none_parent_image_skips_check(self):
        """Sysmon event but parent_image is None (orphan) — must skip."""
        ev = ProcessEvent(
            pid=1234,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            parent_image=None,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques

    def test_sysmon_with_empty_parent_image_skips_check(self):
        """parent_image="" (Sysmon returned '-') — must skip."""
        ev = ProcessEvent(
            pid=1234,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            parent_image="",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques

    def test_psutil_path_still_gets_cmdline_analysis(self):
        """psutil path must still get analyze_cmdline results — the
        wrapper doesn't skip the base engine when Sysmon fields are None."""
        ev = ProcessEvent(
            pid=1,
            name="powershell.exe",
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            source="psutil",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.001" in techniques  # base engine still fired

    def test_empty_name_does_not_crash_parent_check(self):
        """name="" — parent check should skip (child name unknown)."""
        ev = ProcessEvent(
            pid=1,
            name="",
            cmdline="x",
            source="sysmon",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        # Should not crash, should not produce T1059.005 (no child name to match)
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1059.005" not in techniques


# ── _check_parent_anomaly unit tests ──


class TestCheckParentAnomalyUnit:
    """Direct tests on the parent anomaly check function."""

    def test_returns_none_when_parent_image_none(self):
        ev = ProcessEvent(pid=1, name="cmd.exe", cmdline="cmd", parent_image=None)
        assert _check_parent_anomaly(ev) is None

    def test_returns_match_for_suspicious_pair(self):
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        result = _check_parent_anomaly(ev)
        assert result is not None
        assert result.technique_id == "T1059.005"
        assert result.suggested_score == 75

    def test_returns_none_for_legitimate_parent(self):
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            parent_image=r"C:\Windows\explorer.exe",
        )
        assert _check_parent_anomaly(ev) is None

    def test_parent_path_case_insensitive(self):
        """WINWORD.EXE (uppercase) should match winword.exe in table."""
        ev = ProcessEvent(
            pid=1,
            name="CMD.EXE",
            cmdline="cmd",
            parent_image=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        )
        result = _check_parent_anomaly(ev)
        assert result is not None
        assert result.technique_id == "T1059.005"

    def test_forward_slash_path_handled(self):
        """Paths with forward slashes (rare but possible) — normalize."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            parent_image="C:/Program Files/Microsoft Office/winword.exe",
        )
        result = _check_parent_anomaly(ev)
        assert result is not None
