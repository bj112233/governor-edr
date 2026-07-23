# tests/test_fail_safe_e2e.py
"""Comprehensive Fail-Safe layer tests — remediation_engine, firewall, two_factor.

All tests use mocks — NO real OS actions (no psutil kills, no netsh, no subprocess).
Covers:
  1. remediation_engine: _is_local_ip, kill_process, block_ip_in_firewall
  2. action_tools/firewall: block_ip, unblock_ip, _add_rule, _del_rule_rollback
  3. two_factor: verify_challenge, _check_lockout
"""

import os
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ═══════════════════════════════════════════════════════════════════════════
# Fixture: clear two_factor in-memory state before/after each test
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture(autouse=True)
def clear_two_factor_state():
    """Reset two_factor module-level dicts/lists to prevent cross-test leakage."""
    from services import two_factor

    two_factor._challenges.clear()
    two_factor._lockout_log.clear()
    two_factor._otp_generation_log.clear()
    yield
    two_factor._challenges.clear()
    two_factor._lockout_log.clear()
    two_factor._otp_generation_log.clear()


# ═══════════════════════════════════════════════════════════════════════════
# Section 1: remediation_engine._is_local_ip
# ═══════════════════════════════════════════════════════════════════════════


class TestIsLocalIp:
    """_is_local_ip — all private ranges, loopback, public IPs."""

    def test_private_192_168_range(self):
        from services.remediation_engine import _is_local_ip

        for ip in ("192.168.0.1", "192.168.1.100", "192.168.255.255"):
            assert _is_local_ip(ip) is True, f"{ip} should be local"

    def test_private_10_range(self):
        from services.remediation_engine import _is_local_ip

        for ip in ("10.0.0.1", "10.1.2.3", "10.255.255.255"):
            assert _is_local_ip(ip) is True, f"{ip} should be local"

    def test_private_172_16_to_31_range(self):
        from services.remediation_engine import _is_local_ip

        for i in range(16, 32):
            assert _is_local_ip(f"172.{i}.0.1") is True, f"172.{i}.0.1 should be local"
        # 172.32+ is NOT private
        assert _is_local_ip("172.32.0.1") is False
        # 172.160 should not match (prefix "172.16." != "172.160.")
        assert _is_local_ip("172.160.0.1") is False

    def test_ipv6_link_local_fe80(self):
        from services.remediation_engine import _is_local_ip

        assert _is_local_ip("fe80::1") is True
        assert _is_local_ip("fe80::1234:5678") is True

    def test_ipv6_ula_fc00_fd00(self):
        from services.remediation_engine import _is_local_ip

        assert _is_local_ip("fc00::1") is True
        assert _is_local_ip("fd00::1234") is True

    def test_loopback_ipv4(self):
        from services.remediation_engine import _is_local_ip

        assert _is_local_ip("127.0.0.1") is True

    def test_loopback_ipv6(self):
        from services.remediation_engine import _is_local_ip

        assert _is_local_ip("::1") is True

    def test_public_ips_return_false(self):
        from services.remediation_engine import _is_local_ip

        for ip in ("8.8.8.8", "1.1.1.1", "203.0.113.1", "172.32.0.1", "2001:db8::1"):
            assert _is_local_ip(ip) is False, f"{ip} should NOT be local"


# ═══════════════════════════════════════════════════════════════════════════
# Section 2: remediation_engine.kill_process
# ═══════════════════════════════════════════════════════════════════════════


class TestKillProcess:
    """kill_process — by-name path, PID path, whitelist, exceptions."""

    def test_kill_by_name_success(self):
        """pid=None, single matching process found and killed → True."""
        from services.remediation_engine import kill_process

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "malware.exe"}
        mock_target = MagicMock()
        with (
            patch("services.remediation_engine.psutil.process_iter", return_value=[mock_proc]),
            patch("services.remediation_engine.psutil.Process", return_value=mock_target),
        ):
            ok, msg = kill_process(pid=None, proc_name="malware.exe")
        assert ok is True
        assert "terminated" in msg.lower()
        mock_target.kill.assert_called_once()

    def test_kill_by_name_not_found(self):
        """pid=None, no matching process → False, 'not found'."""
        from services.remediation_engine import kill_process

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 1234, "name": "other.exe"}
        with patch("services.remediation_engine.psutil.process_iter", return_value=[mock_proc]):
            ok, msg = kill_process(pid=None, proc_name="malware.exe")
        assert ok is False
        assert "not found" in msg.lower()
        mock_proc.kill.assert_not_called()

    def test_kill_by_name_exception(self):
        """pid=None, process_iter raises → False, error message."""
        from services.remediation_engine import kill_process

        with patch("services.remediation_engine.psutil.process_iter", side_effect=RuntimeError("iter failed")):
            ok, msg = kill_process(pid=None, proc_name="malware.exe")
        assert ok is False
        assert "kill by name failed" in msg.lower()

    def test_kill_by_name_ambiguous_refused(self):
        """H7: pid=None, multiple matching processes → refused (collateral damage prevention)."""
        from services.remediation_engine import kill_process

        mock_proc1 = MagicMock()
        mock_proc1.info = {"pid": 1234, "name": "chrome.exe"}
        mock_proc2 = MagicMock()
        mock_proc2.info = {"pid": 5678, "name": "chrome.exe"}
        with patch(
            "services.remediation_engine.psutil.process_iter",
            return_value=[mock_proc1, mock_proc2],
        ):
            ok, msg = kill_process(pid=None, proc_name="chrome.exe")
        assert ok is False
        assert "ambiguous" in msg.lower()
        assert "2" in msg
        mock_proc1.kill.assert_not_called()
        mock_proc2.kill.assert_not_called()

    def test_kill_by_name_skips_system_and_self_pid(self):
        """pid=None, matching process but PID <= 4 or self → skipped, not found."""
        from services.remediation_engine import kill_process

        self_pid = os.getpid()
        mock_proc = MagicMock()
        mock_proc.info = {"pid": self_pid, "name": "malware.exe"}
        with patch("services.remediation_engine.psutil.process_iter", return_value=[mock_proc]):
            ok, msg = kill_process(pid=None, proc_name="malware.exe")
        assert ok is False
        assert "not found" in msg.lower()
        mock_proc.kill.assert_not_called()

    def test_kill_pid_no_such_process(self):
        """PID path, psutil.NoSuchProcess → False, 'not found'."""
        from services.remediation_engine import kill_process

        with patch("services.remediation_engine.psutil.Process", side_effect=psutil.NoSuchProcess(9999)):
            ok, msg = kill_process(pid=9999, proc_name="malware.exe")
        assert ok is False
        assert "not found" in msg.lower()

    def test_kill_pid_generic_exception(self):
        """PID path, generic Exception → False, 'kill failed'."""
        from services.remediation_engine import kill_process

        with patch("services.remediation_engine.psutil.Process", side_effect=RuntimeError("boom")):
            ok, msg = kill_process(pid=9999, proc_name="malware.exe")
        assert ok is False
        assert "kill failed" in msg.lower()

    def test_safe_processes_whitelist_rejected(self):
        """SAFE_PROCESSES names → rejected before any psutil call."""
        from services.remediation_engine import kill_process

        for safe in ("svchost.exe", "explorer.exe", "system", "wininit.exe", "lsass.exe"):
            ok, msg = kill_process(pid=None, proc_name=safe)
            assert ok is False, f"{safe} should be whitelisted"
            assert "whitelisted" in msg.lower()


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: remediation_engine.block_ip_in_firewall
# ═══════════════════════════════════════════════════════════════════════════


class TestBlockIpInFirewall:
    """block_ip_in_firewall — whitelist, success, partial, failure, exception."""

    def test_safe_ips_whitelist(self):
        """127.0.0.1 in SAFE_IPS (and _is_loopback_ip bypassed) → whitelisted rejection.

        M4: _is_loopback_ip is now checked first (not _is_local_ip).
        """
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine._is_loopback_ip", return_value=False):
            ok, msg = block_ip_in_firewall("127.0.0.1")
        assert ok is False
        assert "whitelisted" in msg.lower()

    def test_loopback_always_blocked(self):
        """M4: Loopback IP is always rejected from firewall blocking."""
        from services.remediation_engine import block_ip_in_firewall

        ok, msg = block_ip_in_firewall("127.0.0.1")
        assert ok is False
        assert "loopback" in msg.lower()

    def test_rfc1918_can_be_blocked(self):
        """M4: RFC1918 LAN IPs CAN be blocked (lateral movement defense)."""
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout="Ok."),
                MagicMock(returncode=0, stderr="", stdout="Ok."),
            ]
            ok, msg = block_ip_in_firewall("192.168.1.50")
        assert ok is True
        assert "blocked" in msg.lower()

    def test_outbound_and_inbound_success(self):
        """Both netsh calls return rc=0 → True, 'blocked'."""
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout="Ok."),
                MagicMock(returncode=0, stderr="", stdout="Ok."),
            ]
            ok, msg = block_ip_in_firewall("8.8.8.8")
        assert ok is True
        assert "blocked" in msg.lower()
        assert mock_run.call_count == 2

    def test_partial_inbound_failure(self):
        """Outbound rc=0, inbound rc!=0 → False, partial warning."""
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stderr="", stdout="Ok."),
                MagicMock(returncode=1, stderr="inbound error", stdout=""),
            ]
            ok, msg = block_ip_in_firewall("8.8.8.8")
        assert ok is False
        assert "inbound failed" in msg.lower()

    def test_netsh_outbound_failure(self):
        """Outbound rc!=0 → False, 'netsh failed' (inbound not attempted)."""
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="netsh error", stdout="")
            ok, msg = block_ip_in_firewall("8.8.8.8")
        assert ok is False
        assert "netsh failed" in msg.lower()
        assert mock_run.call_count == 1

    def test_generic_exception(self):
        """subprocess.run raises Exception → False, 'block failed'."""
        from services.remediation_engine import block_ip_in_firewall

        with patch("services.remediation_engine.subprocess.run", side_effect=RuntimeError("crash")):
            ok, msg = block_ip_in_firewall("8.8.8.8")
        assert ok is False
        assert "block failed" in msg.lower()


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: firewall.block_ip
# ═══════════════════════════════════════════════════════════════════════════


def _make_proc(returncode=0, stdout=b"Ok.", stderr=b"", timeout=False):
    """Build a mock subprocess proc for asyncio.create_subprocess_exec."""
    mock_proc = MagicMock()
    if timeout:
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()
        mock_proc.returncode = None
    else:
        mock_proc.communicate = AsyncMock(return_value=(stdout, stderr))
        mock_proc.returncode = returncode
    return mock_proc


class TestFirewallBlockIp:
    """firewall.block_ip — invalid IP, success, both fail, outer exception."""

    async def test_invalid_ip(self):
        """validate_ip returns False → invalid IP message."""
        from services.action_tools.firewall import block_ip

        result = await block_ip("not-an-ip")
        assert "לא תקינה" in result

    async def test_both_directions_success(self):
        """Outbound + inbound both rc=0 → full success message."""
        from services.action_tools.firewall import block_ip

        async def fake_exec(*args, **kwargs):
            return _make_proc(returncode=0, stdout=b"Ok.")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await block_ip("8.8.8.8")
        assert "נחסם" in result
        assert "inbound + outbound" in result

    async def test_both_directions_fail(self):
        """Both rc!=0 → error message, no successes."""
        from services.action_tools.firewall import block_ip

        async def fake_exec(*args, **kwargs):
            return _make_proc(returncode=1, stdout=b"", stderr=b"Error")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await block_ip("8.8.8.8")
        assert "שגיאה" in result
        assert "out" in result and "in" in result

    async def test_generic_exception_outer_try(self):
        """create_subprocess_exec raises → outer except catches, error message."""
        from services.action_tools.firewall import block_ip

        async def fake_exec(*args, **kwargs):
            raise RuntimeError("subprocess crashed")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await block_ip("8.8.8.8")
        assert "שגיאה" in result
        assert "subprocess crashed" in result


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: firewall.unblock_ip
# ═══════════════════════════════════════════════════════════════════════════


class TestFirewallUnblockIp:
    """firewall.unblock_ip — invalid IP, success, partial, timeout, exception."""

    async def test_invalid_ip(self):
        """validate_ip returns False → invalid IP message."""
        from services.action_tools.firewall import unblock_ip

        result = await unblock_ip("not-an-ip")
        assert "לא תקינה" in result

    async def test_success_both_directions(self):
        """Both directions deleted → success with both directions."""
        from services.action_tools.firewall import unblock_ip

        async def fake_exec(*args, **kwargs):
            return _make_proc(returncode=0, stdout=b"Deleted.")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await unblock_ip("8.8.8.8")
        assert "שוחרר" in result
        assert "out" in result and "in" in result

    async def test_partial_success(self):
        """Out deleted, in 'No rules match' → partial, only out direction."""
        from services.action_tools.firewall import unblock_ip

        call_count = {"n": 0}

        async def fake_exec(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _make_proc(returncode=0, stdout=b"Deleted.")
            return _make_proc(returncode=0, stdout=b"No rules match the given criteria.")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await unblock_ip("8.8.8.8")
        assert "שוחרר" in result
        assert "out" in result
        # Only outbound was deleted, not inbound
        assert "out, in" not in result

    async def test_timeout(self):
        """Both directions timeout → no rules deleted, 'not found' message."""
        from services.action_tools.firewall import unblock_ip

        async def fake_exec(*args, **kwargs):
            return _make_proc(timeout=True)

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await unblock_ip("8.8.8.8")
        assert "לא נמצאו" in result or "שגיאה" in result

    async def test_generic_exception(self):
        """create_subprocess_exec raises → outer except, error message."""
        from services.action_tools.firewall import unblock_ip

        async def fake_exec(*args, **kwargs):
            raise RuntimeError("unblock crashed")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await unblock_ip("8.8.8.8")
        assert "שגיאה" in result
        assert "unblock crashed" in result


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: firewall._add_rule / _del_rule_rollback (tested via block_ip)
# ═══════════════════════════════════════════════════════════════════════════


class TestFirewallInnerFunctions:
    """_add_rule success path and _del_rule_rollback success path (closures)."""

    async def test_add_rule_success_path(self):
        """_add_rule with rc=0 appends to successes → full block success."""
        from services.action_tools.firewall import block_ip

        call_count = {"n": 0}

        async def fake_exec(*args, **kwargs):
            call_count["n"] += 1
            # Both calls are _add_rule (out, in) with rc=0
            return _make_proc(returncode=0, stdout=b"Ok.")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await block_ip("8.8.8.8")
        # _add_rule called twice (out + in), both succeeded
        assert call_count["n"] == 2
        assert "inbound + outbound" in result

    async def test_del_rule_rollback_success_path(self):
        """Partial failure → _del_rule_rollback called and succeeds (3rd call)."""
        from services.action_tools.firewall import block_ip

        call_count = {"n": 0}

        async def fake_exec(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # _add_rule out → success
                return _make_proc(returncode=0, stdout=b"Ok.")
            elif call_count["n"] == 2:
                # _add_rule in → fail
                return _make_proc(returncode=1, stdout=b"", stderr=b"Error")
            else:
                # _del_rule_rollback out → success (delete)
                return _make_proc(returncode=0, stdout=b"Deleted.")

        with patch("services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_exec):
            result = await block_ip("8.8.8.8")
        # 3 calls: add out, add in, delete out (rollback)
        assert call_count["n"] == 3
        assert "חלקית" in result or "כשלונות" in result


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: two_factor.verify_challenge
# ═══════════════════════════════════════════════════════════════════════════


class TestVerifyChallenge:
    """verify_challenge — success, max attempts lockout, attempt increment."""

    def test_success_path(self):
        """Correct OTP → True, challenge consumed and deleted from _challenges."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        challenge_id, otp_code = initiate_challenge("reload_hashes")
        assert challenge_id in _challenges

        result = verify_challenge(challenge_id, otp_code)
        assert result is True
        assert challenge_id not in _challenges  # consumed + deleted

    def test_max_attempts_lockout_log(self):
        """3 wrong OTPs → lockout_log entry, challenge deleted, all return False."""
        from services.two_factor import _challenges, _lockout_log, initiate_challenge, verify_challenge

        challenge_id, otp_code = initiate_challenge("reload_hashes")
        wrong_otp = "999999" if otp_code != "999999" else "000000"

        # First two attempts: wrong, challenge stays
        assert verify_challenge(challenge_id, wrong_otp) is False
        assert verify_challenge(challenge_id, wrong_otp) is False
        assert len(_lockout_log) == 0
        assert challenge_id in _challenges

        # Third attempt: max reached → lockout logged, challenge deleted
        assert verify_challenge(challenge_id, wrong_otp) is False
        assert len(_lockout_log) == 1
        assert _lockout_log[0][0] == "reload_hashes"
        assert challenge_id not in _challenges

    def test_attempt_counter_increment(self):
        """One wrong OTP → attempts=1, challenge still active."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        challenge_id, otp_code = initiate_challenge("reload_hashes")
        wrong_otp = "999999" if otp_code != "999999" else "000000"

        result = verify_challenge(challenge_id, wrong_otp)
        assert result is False
        assert challenge_id in _challenges
        assert _challenges[challenge_id].attempts == 1

    def test_unknown_challenge_id(self):
        """Unknown challenge_id → False, no crash."""
        from services.two_factor import verify_challenge

        assert verify_challenge("nonexistent_id", "123456") is False

    def test_already_consumed_challenge(self):
        """Consumed challenge → False on second verify attempt."""
        from services.two_factor import initiate_challenge, verify_challenge

        challenge_id, otp_code = initiate_challenge("reload_hashes")
        assert verify_challenge(challenge_id, otp_code) is True
        # Second attempt: already consumed (but deleted, so unknown)
        assert verify_challenge(challenge_id, otp_code) is False


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: two_factor._check_lockout
# ═══════════════════════════════════════════════════════════════════════════


class TestCheckLockout:
    """_check_lockout — no lockout, recent lockout blocks, expired cleaned."""

    def test_no_recent_lockout(self):
        """Empty _lockout_log → no exception raised."""
        from services.two_factor import _check_lockout

        # Should not raise
        _check_lockout("reload_hashes")

    def test_recent_lockout_blocks(self):
        """Recent lockout entry → OTPRateLimitError raised."""
        from services.two_factor import OTPRateLimitError, _check_lockout, _lockout_log

        _lockout_log.append(("reload_hashes", time.monotonic()))
        with pytest.raises(OTPRateLimitError, match="lockout"):
            _check_lockout("reload_hashes")

    def test_expired_entries_cleaned(self):
        """Expired lockout entry (> _LOCKOUT_COOLDOWN) → no raise, entry removed."""
        from services.two_factor import _LOCKOUT_COOLDOWN, _check_lockout, _lockout_log

        _lockout_log.append(("reload_hashes", time.monotonic() - _LOCKOUT_COOLDOWN - 10))
        # Should not raise (expired)
        _check_lockout("reload_hashes")
        # Entry should be cleaned from _lockout_log
        assert len(_lockout_log) == 0

    def test_lockout_for_different_operation_does_not_block(self):
        """Lockout for operation A does not block operation B."""
        from services.two_factor import _check_lockout, _lockout_log

        _lockout_log.append(("other_op", time.monotonic()))
        # Should not raise for "reload_hashes" (different operation)
        _check_lockout("reload_hashes")
