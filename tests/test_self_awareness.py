# tests/test_self_awareness.py
"""Tests for self-awareness baseline — prevents agent from detecting itself.

Covers:
1. Self-whitelist (self_whitelist.py) — filter Sentinel/KoboldCpp processes
2. Load muting (threat_hunter.is_hunt_active + ZScore detector)
3. Domain validation (ioc_extractor + intel_enricher._is_valid_domain)
"""

import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Fix 1: Self-whitelist ──


class TestSelfWhitelist:
    def test_koboldcpp_with_valid_path_is_self(self):
        from services.self_whitelist import _pid_cache, is_self_process

        _pid_cache.clear()
        with (
            patch("services.self_whitelist._get_proc_exe", return_value="c:/tactical_bot/koboldcpp.exe"),
            patch("services.self_whitelist._verify_lineage", return_value=True),
            patch("services.self_whitelist._verify_hash", return_value=True),
        ):
            assert is_self_process(999, "koboldcpp.exe") is True

    def test_koboldcpp_with_no_exe_path_rejected(self):
        """Can't verify path → fail-open to False (don't whitelist unknown)."""
        from services.self_whitelist import _pid_cache, is_self_process

        _pid_cache.clear()
        with patch("services.self_whitelist._get_proc_exe", return_value=None):
            assert is_self_process(999, "koboldcpp.exe") is False

    def test_python_in_sentinel_dir_is_self(self):
        from services.self_whitelist import _pid_cache, is_self_process

        _pid_cache.clear()
        with patch(
            "services.self_whitelist._get_proc_exe", return_value="c:/users/user/tactical_bot/.venv/python.exe"
        ):
            assert is_self_process(1234, "python.exe") is True

    def test_python_outside_sentinel_not_self(self):
        from services.self_whitelist import _pid_cache, is_self_process

        _pid_cache.clear()
        with patch("services.self_whitelist._get_proc_exe", return_value="c:/other_project/python.exe"):
            assert is_self_process(5678, "python.exe") is False

    def test_other_process_not_self(self):
        from services.self_whitelist import is_self_process

        assert is_self_process(1234, "chrome.exe") is False

    def test_none_pid_not_self(self):
        from services.self_whitelist import is_self_process

        assert is_self_process(None, "python.exe") is False

    def test_is_self_process_by_name_koboldcpp(self):
        from services.self_whitelist import is_self_process_by_name

        assert is_self_process_by_name("koboldcpp.exe") is True

    def test_is_self_process_by_name_python_not_matched(self):
        """python.exe is NOT matched by name-only (can't verify path)."""
        from services.self_whitelist import is_self_process_by_name

        assert is_self_process_by_name("python.exe") is False

    # ── is_self_cmdline: PowerShell self-blindspot (T1059.001 false positive) ──

    def test_is_self_cmdline_sentinel_project_path(self):
        """PowerShell launching a Sentinel sensor script → self."""
        from services.self_whitelist import is_self_cmdline

        assert (
            is_self_cmdline(
                "powershell -NoProfile -ExecutionPolicy Bypass -File c:/Users/user/tactical_bot/tmp_poll.ps1"
            )
            is True
        )

    def test_is_self_cmdline_windows_backslash_path(self):
        """Windows backslash path form → self."""
        from services.self_whitelist import is_self_cmdline

        assert (
            is_self_cmdline(
                r"powershell -NoProfile -NonInteractive -Command cd C:\Users\user\tactical_bot; .\.venv\Scripts\python.exe -m pytest"
            )
            is True
        )

    def test_is_self_cmdline_sentinel_fragment(self):
        """'sentinel' path fragment → self."""
        from services.self_whitelist import is_self_cmdline

        assert is_self_cmdline("powershell -File c:/projects/sentinel/hunt.ps1") is True

    def test_is_self_cmdline_external_powershell_not_self(self):
        """PowerShell running an unrelated script → NOT self."""
        from services.self_whitelist import is_self_cmdline

        assert is_self_cmdline("powershell -NoProfile -ExecutionPolicy Bypass -File c:/malware/payload.ps1") is False

    def test_is_self_cmdline_empty(self):
        """Empty cmdline → not self (no path to match)."""
        from services.self_whitelist import is_self_cmdline

        assert is_self_cmdline("") is False
        assert is_self_cmdline("   ") is False

    def test_is_self_cmdline_case_insensitive(self):
        """Path fragment match is case-insensitive (TACTICAL_BOT)."""
        from services.self_whitelist import is_self_cmdline

        assert is_self_cmdline("powershell -File C:/USERS/USER/TACTICAL_BOT/run.ps1") is True

    def test_filter_self_connections(self):
        from services.self_whitelist import _pid_cache, filter_self_connections

        _pid_cache.clear()
        conns = [
            ("8.8.8.8", 443, 100, "chrome.exe"),
            ("1.2.3.4", 443, 200, "koboldcpp.exe"),
            ("9.9.9.9", 80, 300, "python.exe"),
        ]

        def mock_exe(pid):
            if pid == 200:
                return "c:/tactical_bot/koboldcpp.exe"
            if pid == 300:
                return "c:/tactical_bot/.venv/python.exe"
            return None

        with (
            patch("services.self_whitelist._get_proc_exe", side_effect=mock_exe),
            patch("services.self_whitelist._verify_lineage", return_value=True),
            patch("services.self_whitelist._verify_hash", return_value=True),
        ):
            filtered = filter_self_connections(conns)
        # koboldcpp (PID 200) + python (PID 300) both filtered (verified self)
        assert len(filtered) == 1
        assert filtered[0][3] == "chrome.exe"


class TestProcessLineage:
    """Verify process lineage defeats masquerading attacks."""

    def test_koboldcpp_with_sentinel_parent_is_self(self):
        from services.self_whitelist import _pid_cache, is_self_process, set_sentinel_pid

        _pid_cache.clear()
        set_sentinel_pid(5000)
        with (
            patch("services.self_whitelist._get_proc_exe", return_value="c:/tactical_bot/koboldcpp.exe"),
            patch("services.self_whitelist._get_proc_parent_pid", return_value=5000),
            patch("services.self_whitelist._verify_hash", return_value=True),
        ):
            assert is_self_process(6000, "koboldcpp.exe") is True

    def test_koboldcpp_with_wrong_parent_not_self(self):
        """Masquerading: koboldcpp.exe NOT spawned by Sentinel → rejected."""
        from services.self_whitelist import _pid_cache, is_self_process, set_sentinel_pid

        _pid_cache.clear()
        set_sentinel_pid(5000)
        with (
            patch("services.self_whitelist._get_proc_exe", return_value="c:/tactical_bot/koboldcpp.exe"),
            patch("services.self_whitelist._get_proc_parent_pid", return_value=9999),
            patch("services.self_whitelist._verify_hash", return_value=True),
        ):
            assert is_self_process(6000, "koboldcpp.exe") is False

    def test_koboldcpp_lineage_fail_open_without_sentinel_pid(self):
        """No sentinel PID registered → lineage fails open (path check still applies)."""
        from services.self_whitelist import _pid_cache, _sentinel_pid, is_self_process

        _pid_cache.clear()
        # Simulate no sentinel PID set
        import services.self_whitelist as sw

        original = sw._sentinel_pid
        sw._sentinel_pid = None
        try:
            with (
                patch("services.self_whitelist._get_proc_exe", return_value="c:/tactical_bot/koboldcpp.exe"),
                patch("services.self_whitelist._verify_hash", return_value=True),
            ):
                assert is_self_process(6000, "koboldcpp.exe") is True
        finally:
            sw._sentinel_pid = original


class TestHashVerification:
    """Verify SHA256 hash verification defeats binary replacement attacks."""

    def test_hash_mismatch_rejected(self):
        """Executable hash doesn't match registered → rejected (masquerading detected)."""
        import tempfile

        from services.self_whitelist import _known_good_hashes, _pid_cache, is_self_process, register_self_hash

        _pid_cache.clear()
        _known_good_hashes.clear()

        # Create a temp file and register its hash
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"legitimate_binary")
            f.flush()
            register_self_hash(f.name)

        # Now modify the file (simulating binary replacement)
        with open(f.name, "wb") as f2:
            f2.write(b"malicious_binary_replacement")

        try:
            with patch("services.self_whitelist._get_proc_exe", return_value=f.name.lower()):
                with patch("services.self_whitelist._verify_lineage", return_value=True):
                    result = is_self_process(7000, "koboldcpp.exe")
            assert result is False  # hash mismatch → rejected
        finally:
            os.unlink(f.name)

    def test_hash_match_accepted(self):
        """Executable hash matches registered → accepted."""
        import tempfile

        from services.self_whitelist import _known_good_hashes, _pid_cache, is_self_process, register_self_hash

        _pid_cache.clear()
        _known_good_hashes.clear()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"legitimate_binary")
            f.flush()
            exe_path = os.path.abspath(f.name).lower()
            register_self_hash(f.name)

        try:
            with patch("services.self_whitelist._get_proc_exe", return_value=exe_path):
                with patch("services.self_whitelist._verify_lineage", return_value=True):
                    result = is_self_process(7000, "koboldcpp.exe")
            assert result is True
        finally:
            os.unlink(f.name)

    def test_no_hash_registered_fail_open(self):
        """No hash registered for path → fail open (path check still applies)."""
        from services.self_whitelist import _known_good_hashes, _pid_cache, is_self_process

        _pid_cache.clear()
        _known_good_hashes.clear()
        with (
            patch("services.self_whitelist._get_proc_exe", return_value="c:/tactical_bot/koboldcpp.exe"),
            patch("services.self_whitelist._verify_lineage", return_value=True),
        ):
            assert is_self_process(7000, "koboldcpp.exe") is True


# ── Fix 2: Load muting ──


class TestLoadMuting:
    def test_is_hunt_active_idle(self):
        from services.threat_hunter import _HUNT_STATUS, is_hunt_active

        _HUNT_STATUS.state = "IDLE"
        assert is_hunt_active() is False

    def test_is_hunt_active_scanning(self):
        from services.threat_hunter import _HUNT_STATUS, is_hunt_active

        _HUNT_STATUS.state = "SCANNING"
        assert is_hunt_active() is True

    def test_is_hunt_active_analyzing(self):
        from services.threat_hunter import _HUNT_STATUS, is_hunt_active

        _HUNT_STATUS.state = "ANALYZING"
        assert is_hunt_active() is True

    def test_is_hunt_active_cooldown(self):
        from services.threat_hunter import _HUNT_STATUS, is_hunt_active

        _HUNT_STATUS.state = "COOLDOWN"
        assert is_hunt_active() is False

    @pytest.mark.asyncio
    async def test_cpu_spike_absorbed_by_koboldcpp_subtraction(self):
        """CPU spike fully explained by KoboldCpp → no alert (subtraction absorbs it)."""
        from services.monitor_analyzer import SustainedZScoreDetector

        detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1, metrics=("cpu",))
        snapshot = {"cpu": 95.0}
        baseline = MagicMock()
        baseline.get_stats.return_value = (10.0, 5.0)  # mean=10, std=5

        # Total CPU=95%, KoboldCpp=85% → residual=10% → z=0 (within normal)
        with patch("services.threat_hunter.is_hunt_active", return_value=True):
            with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=85.0):
                with patch.object(detector, "_extract_value", return_value=95.0):
                    events = await detector.detect(snapshot, baseline)

        assert len(events) == 0  # residual 10% is within baseline

    @pytest.mark.asyncio
    async def test_cpu_spike_emitted_when_residual_still_high(self):
        """CPU spike NOT fully explained by KoboldCpp → alert emitted (real anomaly).

        Total=95%, KoboldCpp=30% → residual=65% → z=11 (massive spike).
        This catches ransomware/miner running during a hunt.
        """
        from services.monitor_analyzer import SustainedZScoreDetector

        detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1, metrics=("cpu",))
        snapshot = {"cpu": 95.0}
        baseline = MagicMock()
        baseline.get_stats.return_value = (10.0, 5.0)

        with patch("services.threat_hunter.is_hunt_active", return_value=True):
            with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=30.0):
                with patch.object(detector, "_extract_value", return_value=95.0):
                    events = await detector.detect(snapshot, baseline)

        assert len(events) == 1
        assert events[0].metric == "cpu_spike"

    @pytest.mark.asyncio
    async def test_cpu_spike_emitted_when_not_hunting(self):
        """CPU spike when NOT hunting should still be emitted (no subtraction)."""
        from services.monitor_analyzer import SustainedZScoreDetector

        detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1, metrics=("cpu",))
        snapshot = {"cpu": 95.0}
        baseline = MagicMock()
        baseline.get_stats.return_value = (10.0, 5.0)

        with patch("services.threat_hunter.is_hunt_active", return_value=False):
            with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=0.0):
                with patch.object(detector, "_extract_value", return_value=95.0):
                    events = await detector.detect(snapshot, baseline)

        assert len(events) == 1
        assert events[0].metric == "cpu_spike"

    @pytest.mark.asyncio
    async def test_toctou_ema_smooths_transient_misalignment(self):
        """Single misaligned sample (TOCTOU) absorbed by EMA + required_cycles.

        Cycle 1: KoboldCpp=80% but sampled as 10% (TOCTOU) → residual=85% → spike
        But required_cycles=3 means 1 cycle isn't enough → no alert.
        Cycle 2-3: EMA catches up, subtraction correct → residual normal.
        """
        from services.monitor_analyzer import SustainedZScoreDetector

        detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=3, metrics=("cpu",))
        baseline = MagicMock()
        baseline.get_stats.return_value = (10.0, 5.0)

        # Cycle 1: TOCTOU misalignment — KoboldCpp reads low
        with patch("services.threat_hunter.is_hunt_active", return_value=True):
            with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=10.0):
                with patch.object(detector, "_extract_value", return_value=95.0):
                    events1 = await detector.detect({"cpu": 95.0}, baseline)
        assert len(events1) == 0  # 1 cycle not enough

        # Cycle 2: EMA catches up (0.3*80 + 0.7*10 = 31%)
        with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=80.0):
            with patch.object(detector, "_extract_value", return_value=95.0):
                events2 = await detector.detect({"cpu": 95.0}, baseline)
        # residual = 95 - 31 = 64, z = 10.8 → still spikes, but cycle_count=2
        assert len(events2) == 0  # 2 cycles not enough

        # Cycle 3: EMA further smooths (0.3*80 + 0.7*31 = 47.7%)
        with patch("services.self_whitelist.get_koboldcpp_cpu_percent", return_value=80.0):
            with patch.object(detector, "_extract_value", return_value=95.0):
                events3 = await detector.detect({"cpu": 95.0}, baseline)
        # residual = 95 - 47.7 = 47.3, z = 7.5 → still spikes, cycle_count=3 → alert
        # This is CORRECT: 3 sustained cycles means it's NOT a TOCTOU transient
        assert len(events3) == 1
        assert events3[0].metric == "cpu_spike"


class TestReloadHashes:
    """Verify hot-reload of SHA256 hashes without downtime."""

    def test_reload_hashes_updates_changed_binary(self):
        """After binary update, reload_hashes() picks up new hash."""
        import tempfile

        from services.self_whitelist import (
            _known_good_hashes,
            _pid_cache,
            register_self_hash,
            reload_hashes,
        )

        _pid_cache.clear()
        _known_good_hashes.clear()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"v1_binary")
            f.flush()
            register_self_hash(f.name)
            old_hash = _known_good_hashes.get(os.path.abspath(f.name).lower())

        # Update the binary (simulating koboldcpp upgrade)
        with open(f.name, "wb") as f2:
            f2.write(b"v2_binary_updated")

        try:
            results = reload_hashes()
            new_hash = _known_good_hashes.get(os.path.abspath(f.name).lower())
            assert old_hash != new_hash  # hash changed
            assert "ok" in list(results.values())[0]  # reload succeeded
        finally:
            os.unlink(f.name)

    def test_reload_hashes_clears_pid_cache(self):
        """reload_hashes() must clear PID cache so processes get re-verified."""
        from services.self_whitelist import _pid_cache, reload_hashes

        _pid_cache[999] = (True, 0.0)
        assert len(_pid_cache) > 0
        reload_hashes()
        assert len(_pid_cache) == 0

    @pytest.mark.asyncio
    async def test_c2_reload_hashes_command_requires_2fa(self):
        """C2 dispatch 'reload_hashes' now requires 2FA (step-up auth)."""
        from services.web_c2_commands import dispatch_command

        gateway = MagicMock()
        gateway.send_message = AsyncMock(return_value=True)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", "123456"),
        ):
            result = await dispatch_command("reload_hashes")
        assert result["status"] == "pending_2fa"
        assert "challenge_id" in result


# ── Fix 3: Domain validation ──


class TestDomainValidation:
    def test_valid_domain_accepted(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("evil.com") is True
        assert _is_valid_domain("sub.example.org") is True
        assert _is_valid_domain("a.co") is True

    def test_version_number_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("9.2") is False
        assert _is_valid_domain("0.5") is False
        assert _is_valid_domain("3.2") is False
        assert _is_valid_domain("20.3") is False

    def test_decimal_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("1.2.3") is False  # looks like IP fragment

    def test_empty_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("") is False
        assert _is_valid_domain("   ") is False

    def test_no_dot_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("localhost") is False

    def test_numeric_tld_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("example.123") is False

    def test_single_char_tld_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("example.x") is False


class TestIOCExtractorDomainFilter:
    """Verify ioc_extractor filters out version-number domains."""

    def test_version_number_not_extracted(self):
        from services.ioc_extractor import extract_all

        result = extract_all("version 9.2 released")
        assert "9.2" not in result["domains"]

    def test_decimal_not_extracted(self):
        from services.ioc_extractor import extract_all

        result = extract_all("score 0.5 threshold 2.1")
        for d in result["domains"]:
            assert d not in ("0.5", "2.1", "9.2")

    def test_valid_domain_still_extracted(self):
        from services.ioc_extractor import extract_all

        result = extract_all("connect to evil.com and 8.8.8.8")
        assert "evil.com" in result["domains"]

    def test_mixed_valid_and_invalid(self):
        from services.ioc_extractor import extract_all

        result = extract_all("v9.2 update at example.com and bad.2")
        assert "example.com" in result["domains"]
        assert "9.2" not in result["domains"]
        assert "bad.2" not in result["domains"]
