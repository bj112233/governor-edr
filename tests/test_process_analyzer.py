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
from services.process_analyzer import (
    _KNOWN_BAD_HASHES,
    _check_hash_reputation,
    _check_integrity_level,
    _check_parent_anomaly,
    _check_unsigned_masquerading,
    _integrity_rank,
    analyze_process_event,
    register_malicious_hash,
)
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


# ── Hash reputation (T1027) ──


class TestHashReputation:
    """T1027 — known-malicious file hash check."""

    def setup_method(self):
        """Clear the known-bad set before each test (module-level state)."""
        _KNOWN_BAD_HASHES.clear()

    def teardown_method(self):
        _KNOWN_BAD_HASHES.clear()

    def test_known_bad_hash_detected(self):
        register_malicious_hash("a" * 64)
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            sha256="a" * 64,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1027" in techniques

    def test_clean_hash_not_flagged(self):
        register_malicious_hash("a" * 64)
        ev = ProcessEvent(
            pid=1,
            name="clean.exe",
            cmdline="clean.exe",
            source="sysmon",
            sha256="b" * 64,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1027" not in techniques

    def test_none_sha256_skips_check(self):
        """psutil path (sha256=None) must skip hash check."""
        register_malicious_hash("a" * 64)
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="psutil",
            sha256=None,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1027" not in techniques

    def test_known_bad_hash_score_is_90(self):
        """Known-bad hash should score 90 (auto-block threshold)."""
        register_malicious_hash("a" * 64)
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            sha256="a" * 64,
        )
        matches = analyze_process_event(ev)
        hash_matches = [m for m in matches if m.technique_id == "T1027"]
        assert len(hash_matches) == 1
        assert hash_matches[0].suggested_score == 90

    def test_register_normalizes_to_lowercase(self):
        """register_malicious_hash should lowercase the hash."""
        register_malicious_hash("A" * 64)
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            sha256="a" * 64,  # lowercase in event
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1027" in techniques  # matched despite register uppercase

    def test_register_rejects_wrong_length(self):
        """Non-64-char strings should not be added to known-bad set."""
        register_malicious_hash("a" * 63)  # too short
        register_malicious_hash("a" * 65)  # too long
        assert len(_KNOWN_BAD_HASHES) == 0

    def test_empty_known_bad_set_no_false_positives(self):
        """Empty known-bad set (no feeds loaded) → no hash matches."""
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            sha256="a" * 64,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1027" not in techniques


# ── Integrity level (T1548.002) ──


class TestIntegrityLevel:
    """T1548.002 — UAC bypass via integrity level escalation."""

    def test_high_integrity_from_office_parent_flagged(self):
        """Office app (Medium) spawning High-integrity child = UAC bypass."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            integrity_level="High",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" in techniques

    def test_medium_integrity_not_flagged(self):
        """Medium integrity is normal — no escalation."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            integrity_level="Medium",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_none_integrity_skips_check(self):
        """psutil path (integrity_level=None) must skip."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="psutil",
            integrity_level=None,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_high_integrity_legitimate_parent_not_flagged(self):
        """High integrity from explorer.exe (can elevate via UAC consent)
        — not flagged (parent not in suspicious table)."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            integrity_level="High",
            parent_image=r"C:\Windows\explorer.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_high_integrity_no_parent_not_flagged(self):
        """High integrity with no parent info — can't determine escalation,
        don't flag (avoid false positive)."""
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            integrity_level="High",
            parent_image=None,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_system_integrity_from_browser_flagged(self):
        """System integrity from browser = definitely UAC bypass."""
        ev = ProcessEvent(
            pid=1,
            name="powershell.exe",
            cmdline="powershell",
            source="sysmon",
            integrity_level="System",
            parent_image=r"C:\Program Files\Google\Chrome\chrome.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" in techniques

    def test_unknown_integrity_string_skips_check(self):
        """Unknown integrity level string — skip, don't crash."""
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            integrity_level="AppContainer",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_empty_string_integrity_skips_check(self):
        """Empty string integrity_level — _integrity_rank returns -1."""
        assert _integrity_rank("") == -1
        # Also verify via the full pipeline
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            integrity_level="",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques

    def test_low_integrity_not_flagged(self):
        """Low integrity is de-escalation, not escalation — not flagged."""
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            integrity_level="Low",
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1548.002" not in techniques


# ── Unsigned masquerading (T1036) ──


class TestUnsignedMasquerading:
    """T1036 — unsigned binary in Windows system directory."""

    def test_unsigned_in_system32_flagged(self):
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            image=r"C:\Windows\System32\evil.exe",
            signed=False,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" in techniques

    def test_signed_in_system32_not_flagged(self):
        ev = ProcessEvent(
            pid=1,
            name="cmd.exe",
            cmdline="cmd",
            source="sysmon",
            image=r"C:\Windows\System32\cmd.exe",
            signed=True,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" not in techniques

    def test_none_signed_skips_check(self):
        """Event 1 doesn't carry signature info — signed is always None.
        This check must skip (cannot determine unsigned status)."""
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            image=r"C:\Windows\System32\evil.exe",
            signed=None,  # Event 1 — no signature info
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" not in techniques

    def test_unsigned_outside_windows_dir_not_flagged(self):
        """Unsigned binary in user dir is not masquerading — just unsigned."""
        ev = ProcessEvent(
            pid=1,
            name="myapp.exe",
            cmdline="myapp.exe",
            source="sysmon",
            image=r"C:\Users\user\myapp.exe",
            signed=False,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" not in techniques

    def test_unsigned_in_syswow64_flagged(self):
        """SysWOW64 is also a Windows system directory."""
        ev = ProcessEvent(
            pid=1,
            name="evil.dll",
            cmdline="evil.dll",
            source="sysmon",
            image=r"C:\Windows\SysWOW64\evil.dll",
            signed=False,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" in techniques

    def test_none_image_skips_check(self):
        """No image path — cannot check directory, skip."""
        ev = ProcessEvent(
            pid=1,
            name="x",
            cmdline="x",
            source="sysmon",
            image=None,
            signed=False,
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" not in techniques

    def test_psutil_path_skips_check(self):
        """psutil path (signed=None) must skip."""
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="psutil",
            image=r"C:\Windows\System32\evil.exe",
        )
        matches = analyze_process_event(ev)
        techniques = [m.technique_id for m in matches]
        assert "T1036" not in techniques

    def test_unsigned_masquerading_score_is_85(self):
        """Auto-block threshold."""
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            image=r"C:\Windows\System32\evil.exe",
            signed=False,
        )
        matches = analyze_process_event(ev)
        t1036 = [m for m in matches if m.technique_id == "T1036"]
        assert len(t1036) == 1
        assert t1036[0].suggested_score == 85
