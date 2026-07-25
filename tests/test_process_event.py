# tests/test_process_event.py
"""Boundary tests for ProcessEvent None-handling.

Covers every `is None` branch that `analyze_process_event` will eventually
rely on. These tests pin the contract BEFORE the wrapper exists, so the
wrapper's None-skips are guaranteed by failing tests, not by code review.

Two source classes tested:
  - psutil path: every Sysmon field is None (default)
  - Sysmon path partial: some Sysmon fields None (e.g. hash timeout,
    signature unavailable on unsigned binary, integrity level missing)
"""

from __future__ import annotations

import pytest

from services.process_event import ProcessEvent

# ── Construction: psutil path (all Sysmon fields default to None) ──


class TestPsutilPathDefaults:
    """psutil-derived event has only pid/name/cmdline; everything else None."""

    def test_minimal_construction_only_required_fields(self):
        ev = ProcessEvent(pid=1234, name="cmd.exe", cmdline="cmd /c echo hi")
        assert ev.pid == 1234
        assert ev.name == "cmd.exe"
        assert ev.cmdline == "cmd /c echo hi"

    @pytest.mark.parametrize(
        "field",
        [
            "image",
            "parent_pid",
            "parent_image",
            "sha256",
            "signed",
            "integrity_level",
            "user",
        ],
    )
    def test_sysmon_field_is_none_by_default(self, field):
        ev = ProcessEvent(pid=1, name="x", cmdline="x")
        assert getattr(ev, field) is None, (
            f"psutil path must leave {field}=None so analyze_process_event "
            f"can detect 'Sysmon field unavailable' and skip the check"
        )

    def test_source_defaults_to_psutil(self):
        ev = ProcessEvent(pid=1, name="x", cmdline="x")
        assert ev.source == "psutil"

    def test_is_sysmon_sourced_false_for_psutil(self):
        ev = ProcessEvent(pid=1, name="x", cmdline="x")
        assert ev.is_sysmon_sourced is False


# ── Construction: Sysmon full path ──


class TestSysmonFullPath:
    """Sysmon-derived event with all fields populated."""

    def test_all_fields_set(self):
        ev = ProcessEvent(
            pid=5678,
            name="powershell.exe",
            cmdline="powershell -enc SGVsbG8=",
            source="sysmon",
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_pid=4321,
            parent_image=r"C:\Program Files\Microsoft Office\winword.exe",
            sha256="a" * 64,
            signed=True,
            integrity_level="High",
            user=r"DOMAIN\user",
        )
        assert ev.is_sysmon_sourced is True
        assert ev.parent_image.endswith("winword.exe")
        assert ev.sha256 == "a" * 64
        assert ev.signed is True
        assert ev.integrity_level == "High"


# ── Construction: Sysmon partial (field unavailable) ──
# These are the dangerous cases — Sysmon ran but a specific field couldn't
# be computed. The wrapper must skip ONLY that check, not the whole event.


class TestSysmonPartialFields:
    """Sysmon event where some enriched fields are None (real-world cases)."""

    def test_hash_timeout_leaves_sha256_none(self):
        """Large binary / hash timeout — sha256 is None but other fields present."""
        ev = ProcessEvent(
            pid=1,
            name="big.exe",
            cmdline="big.exe",
            source="sysmon",
            image=r"D:\big.exe",
            parent_pid=2,
            parent_image=r"C:\Windows\explorer.exe",
            sha256=None,  # hash computation timed out
            signed=True,
            integrity_level="Medium",
        )
        assert ev.is_sysmon_sourced is True
        assert ev.sha256 is None
        # Other Sysmon fields are still present — wrapper must not skip them
        assert ev.parent_image is not None
        assert ev.signed is not None

    def test_unsigned_binary_leaves_signed_none_or_false(self):
        """Unsigned binary — signed is False (or None if Sysmon didn't check)."""
        ev = ProcessEvent(
            pid=1,
            name="evil.exe",
            cmdline="evil.exe",
            source="sysmon",
            signed=False,
        )
        assert ev.signed is False

    def test_missing_integrity_level(self):
        """Older Sysmon config or legacy process — integrity_level is None."""
        ev = ProcessEvent(
            pid=1, name="x", cmdline="x", source="sysmon", integrity_level=None
        )
        assert ev.integrity_level is None
        assert ev.is_sysmon_sourced is True

    def test_orphan_process_no_parent(self):
        """Process whose parent already exited — parent_pid/parent_image None."""
        ev = ProcessEvent(
            pid=1,
            name="orphan.exe",
            cmdline="orphan.exe",
            source="sysmon",
            parent_pid=None,
            parent_image=None,
        )
        assert ev.parent_pid is None
        assert ev.parent_image is None


# ── Edge cases on required fields ──


class TestRequiredFieldEdges:
    """Required fields (pid, name, cmdline) edge cases."""

    def test_empty_cmdline_is_allowed(self):
        """Some processes have empty cmdline (kernel threads, system process)."""
        ev = ProcessEvent(pid=4, name="System", cmdline="")
        assert ev.cmdline == ""

    def test_pid_zero(self):
        """PID 0 is the System Idle Process — valid, must not be rejected."""
        ev = ProcessEvent(pid=0, name="Idle", cmdline="")
        assert ev.pid == 0

    def test_whitespace_only_cmdline(self):
        ev = ProcessEvent(pid=1, name="x", cmdline="   ")
        assert ev.cmdline == "   "

    def test_name_with_path(self):
        """Sysmon Image field is a full path; name may be basename or full."""
        ev = ProcessEvent(
            pid=1,
            name=r"C:\Windows\System32\cmd.exe",
            cmdline="cmd",
            source="sysmon",
        )
        # We don't normalize — store as-is, normalization is the consumer's job
        assert ev.name.endswith("cmd.exe")


# ── is_sysmon_sourced boundary ──


class TestSourceBoundary:
    """source field is the trust-tier discriminator — boundary cases."""

    @pytest.mark.parametrize("source", ["sysmon", "Sysmon", "SYSMON"])
    def test_source_string_comparison_is_case_sensitive(self, source):
        """source must be exactly 'sysmon' (lowercase) for is_sysmon_sourced.

        If the XML adapter ever passes 'Sysmon' with capital S, the event
        would silently be treated as psutil-tier — losing all enriched checks.
        This test pins the exact spelling the adapter must use.
        """
        ev = ProcessEvent(pid=1, name="x", cmdline="x", source=source)
        # Only exact lowercase 'sysmon' counts
        assert ev.is_sysmon_sourced == (source == "sysmon")

    def test_unknown_source_string_treated_as_not_sysmon(self):
        """Defensive: typos like 'sysmon2' or 'etw' don't accidentally match."""
        ev = ProcessEvent(pid=1, name="x", cmdline="x", source="etw")
        assert ev.is_sysmon_sourced is False
