# tests/test_kill_block_fail_safe.py
"""Security tests: Kill/Block + Bypass Handlers fail-safe behavior.

מבחני אבטחה למנגנוני Kill/Block:
- Process Kill: PID recycling, AccessDenied, protected PIDs/names, NoSuchProcess
- IP Block: timeout (outbound/inbound), partial failure rollback, local IP rejection
- Callback/HITL: PID recycling, already-dead, action-not-found, already-executed
- DEGRADED Mode: B1 (remediation_engine), B2 (callbacks) bypass fixes

All tests use mocks — NO real OS actions (no psutil, no netsh, no subprocess).
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import psutil
import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ═══════════════════════════════════════════════════════════════════════════
# Process Kill Fail-Safe — services/system_intel.py terminate_process
# ═══════════════════════════════════════════════════════════════════════════


class TestTerminateProcess:
    """בדיקות עבור system_intel.terminate_process — הגנה מפני PID recycling ותהליכי מערכת."""

    def test_terminate_process_pid_recycling(self):
        """create_time mismatch → reject (PID recycling detected)."""
        from services.system_intel import terminate_process

        mock_proc = MagicMock()
        mock_proc.create_time.return_value = 1000.0
        mock_proc.name.return_value = "malware.exe"
        with patch("services.system_intel.psutil.Process", return_value=mock_proc):
            result = terminate_process(pid=1234, expected_create_time=5000.0)
        assert "BLOCKED" in result
        assert "recycled" in result.lower()
        mock_proc.terminate.assert_not_called()

    def test_terminate_process_access_denied(self):
        """psutil.AccessDenied → graceful error, no crash."""
        from services.system_intel import terminate_process

        with patch("services.system_intel.psutil.Process", side_effect=psutil.AccessDenied(1234)):
            result = terminate_process(pid=1234)
        assert "ERROR" in result
        assert "Access denied" in result

    def test_terminate_process_protected_pids(self):
        """PID 0 and 4 → rejected before any psutil call."""
        from services.system_intel import terminate_process

        with patch("services.system_intel.psutil.Process") as mock_proc_cls:
            result0 = terminate_process(pid=0)
            result4 = terminate_process(pid=4)
        assert "BLOCKED" in result0
        assert "pid" in result0.lower()
        assert "BLOCKED" in result4
        assert "pid" in result4.lower()
        mock_proc_cls.assert_not_called()

    def test_terminate_process_protected_names(self):
        """lsass.exe, svchost.exe, system → rejected by name."""
        from services.system_intel import terminate_process

        for protected_name in ("lsass.exe", "svchost.exe", "system"):
            mock_proc = MagicMock()
            mock_proc.create_time.return_value = 1000.0
            mock_proc.name.return_value = protected_name
            with patch("services.system_intel.psutil.Process", return_value=mock_proc):
                result = terminate_process(pid=999)
            assert "BLOCKED" in result, f"Expected BLOCKED for {protected_name}: {result}"
            assert "protected" in result.lower()
            mock_proc.terminate.assert_not_called()

    def test_terminate_process_no_such_process(self):
        """psutil.NoSuchProcess → graceful error."""
        from services.system_intel import terminate_process

        with patch("services.system_intel.psutil.Process", side_effect=psutil.NoSuchProcess(1234)):
            result = terminate_process(pid=1234)
        assert "ERROR" in result
        assert "does not exist" in result


# ═══════════════════════════════════════════════════════════════════════════
# Process Kill by Name — services/os_module.py kill_process_by_name
# ═══════════════════════════════════════════════════════════════════════════


class TestKillProcessByName:
    """בדיקות עבור os_module.kill_process_by_name — blacklist וטיפול בשגיאות."""

    async def test_kill_process_by_name_protected_blacklist(self):
        """explorer.exe, svchost.exe → rejected by PROTECTED_PROCESSES blacklist."""
        from services.os_module import kill_process_by_name

        for protected in ("explorer.exe", "svchost.exe"):
            result = await kill_process_by_name(protected)
            assert "נחסמה" in result or "blocked" in result.lower(), f"Expected block for {protected}: {result}"

    async def test_kill_process_by_name_no_such_process(self):
        """Process not found → graceful message, no crash."""
        from services.os_module import kill_process_by_name

        with patch("services.os_module.psutil.process_iter", return_value=[]):
            result = await kill_process_by_name("nonexistent_process.exe")
        assert "לא נמצא" in result or "not found" in result.lower()

    @pytest.mark.xfail(
        reason="B7 (LOW): kill_process_by_name uses asyncio.to_thread(proc.kill) "
        "without a timeout — proc.kill() could hang on unresponsive processes. "
        "Fix deferred: changing kill semantics (e.g. asyncio.wait_for on to_thread) "
        "doesn't actually cancel the OS-level kill, so the fix is risky without "
        "understanding the full impact on process cleanup."
    )
    async def test_kill_process_by_name_kill_timeout(self):
        """B7: proc.kill() should have a timeout to prevent hangs (xfail — not yet fixed)."""
        from services.os_module import kill_process_by_name

        mock_proc = MagicMock()
        mock_proc.info = {"pid": 999, "name": "target.exe"}
        # Simulate a hanging kill — asyncio.to_thread would block indefinitely.
        # Sleep must be short enough to finish within the pytest-timeout window
        # so the leaked worker thread doesn't hang event-loop teardown.
        mock_proc.kill = MagicMock(side_effect=lambda: __import__("time").sleep(3))

        with patch("services.os_module.psutil.process_iter", return_value=[mock_proc]):
            result = await asyncio.wait_for(kill_process_by_name("target.exe"), timeout=0.5)
        assert "חוסלו" in result


# ═══════════════════════════════════════════════════════════════════════════
# Remediation Engine Kill — services/remediation_engine.py kill_process
# ═══════════════════════════════════════════════════════════════════════════


class TestRemediationKillProcess:
    """בדיקות עבור remediation_engine.kill_process — PID guards ואימות שם."""

    def test_remediation_kill_process_pid_le_4(self):
        """PID 1,2,3,4 → rejected as system processes."""
        from services.remediation_engine import kill_process

        for pid in (1, 2, 3, 4):
            ok, msg = kill_process(pid, "test.exe")
            assert not ok, f"PID {pid} should be rejected"
            assert "system" in msg.lower() or "cannot be killed" in msg.lower()

    def test_remediation_kill_process_self_pid(self):
        """os.getpid() → rejected (cannot kill Sentinel itself)."""
        from services.remediation_engine import kill_process

        self_pid = os.getpid()
        ok, msg = kill_process(self_pid, "test.exe")
        assert not ok
        assert "sentinel" in msg.lower() or "itself" in msg.lower()

    def test_remediation_kill_process_name_mismatch(self):
        """proc_name doesn't match actual process name → rejected."""
        from services.remediation_engine import kill_process

        mock_proc = MagicMock()
        mock_proc.name.return_value = "actual.exe"
        with patch("services.remediation_engine.psutil.Process", return_value=mock_proc):
            ok, msg = kill_process(999, "expected.exe")
        assert not ok
        assert "mismatch" in msg.lower()
        mock_proc.kill.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# IP Block Fail-Safe — services/action_tools/firewall.py block_ip/unblock_ip
# ═══════════════════════════════════════════════════════════════════════════


class TestBlockIpFirewall:
    """בדיקות עבור firewall.block_ip — timeout, partial failure, rollback."""

    async def test_block_ip_timeout_outbound(self):
        """mock subprocess timeout on outbound → proc.kill() called, error reported."""
        from services.action_tools import firewall

        async def fake_create_subprocess_exec(*args, **kwargs):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
            mock_proc.kill = MagicMock()
            mock_proc.wait = AsyncMock()
            mock_proc.returncode = None
            return mock_proc

        with patch(
            "services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec
        ):
            result = await firewall.block_ip("8.8.8.8")
        assert "שגיאה" in result or "timeout" in result.lower() or "כשלונות" in result

    async def test_block_ip_timeout_inbound(self):
        """outbound OK, inbound timeout → partial state reported (with rollback)."""
        from services.action_tools import firewall

        call_count = {"n": 0}

        async def fake_create_subprocess_exec(*args, **kwargs):
            call_count["n"] += 1
            mock_proc = MagicMock()
            if call_count["n"] == 1:
                # outbound succeeds
                mock_proc.communicate = AsyncMock(return_value=(b"Ok.", b""))
                mock_proc.returncode = 0
            elif call_count["n"] == 2:
                # inbound times out
                mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
                mock_proc.kill = MagicMock()
                mock_proc.wait = AsyncMock()
                mock_proc.returncode = None
            else:
                # rollback delete (call 3)
                mock_proc.communicate = AsyncMock(return_value=(b"Deleted.", b""))
                mock_proc.returncode = 0
            return mock_proc

        with patch(
            "services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec
        ):
            result = await firewall.block_ip("8.8.8.8")
        assert "חלקית" in result or "כשלונות" in result or "שגיאה" in result

    async def test_block_ip_partial_failure(self):
        """B3 FIX: outbound succeeds, inbound fails → rollback outbound rule (unblock outbound)."""
        from services.action_tools import firewall

        call_count = {"n": 0}
        rollback_called = {"v": False}

        async def fake_create_subprocess_exec(*args, **kwargs):
            call_count["n"] += 1
            mock_proc = MagicMock()
            # calls: 1=add out (ok), 2=add in (fail), 3=delete out (rollback)
            if call_count["n"] == 1:
                mock_proc.communicate = AsyncMock(return_value=(b"Ok.", b""))
                mock_proc.returncode = 0
            elif call_count["n"] == 2:
                mock_proc.communicate = AsyncMock(return_value=(b"", b"Error"))
                mock_proc.returncode = 1
            elif call_count["n"] == 3:
                # rollback delete
                rollback_called["v"] = True
                mock_proc.communicate = AsyncMock(return_value=(b"Deleted.", b""))
                mock_proc.returncode = 0
            return mock_proc

        with patch(
            "services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec
        ):
            result = await firewall.block_ip("8.8.8.8")
        # rollback should have been called (3rd subprocess call = delete outbound)
        assert rollback_called["v"], "Expected rollback (delete outbound) to be called on partial failure"
        assert "חלקית" in result or "כשלונות" in result

    async def test_unblock_ip_no_rules_match(self):
        """netsh returns 'No rules match' → graceful, not error."""
        from services.action_tools import firewall

        async def fake_create_subprocess_exec(*args, **kwargs):
            mock_proc = MagicMock()
            mock_proc.communicate = AsyncMock(return_value=(b"No rules match the given criteria.", b""))
            mock_proc.returncode = 0
            return mock_proc

        with patch(
            "services.action_tools.firewall.asyncio.create_subprocess_exec", side_effect=fake_create_subprocess_exec
        ):
            result = await firewall.unblock_ip("8.8.8.8")
        assert "לא נמצאו" in result or "not found" in result.lower() or "לא היה" in result


# ═══════════════════════════════════════════════════════════════════════════
# IP Block Fail-Safe — services/remediation_engine.py block_ip_in_firewall
# ═══════════════════════════════════════════════════════════════════════════


class TestBlockIpInFirewall:
    """בדיקות עבור remediation_engine.block_ip_in_firewall — local IP rejection, timeout."""

    def test_block_ip_loopback_rejection(self):
        """127.0.0.1 → rejected by block_ip_in_firewall (loopback breaks host).

        RFC1918 IPs (192.168.x.x, 10.x.x.x) are intentionally NOT rejected —
        they can be blocked for lateral movement defense (HITL-approved).
        """
        from services.remediation_engine import block_ip_in_firewall

        ok, msg = block_ip_in_firewall("127.0.0.1")
        assert not ok
        assert "loopback" in msg.lower()

    def test_block_ip_in_firewall_timeout(self):
        """subprocess.TimeoutExpired → graceful error."""
        import subprocess as sp

        from services.remediation_engine import block_ip_in_firewall

        with patch(
            "services.remediation_engine.subprocess.run", side_effect=sp.TimeoutExpired(cmd="netsh", timeout=15)
        ):
            ok, msg = block_ip_in_firewall("8.8.8.8")
        assert not ok
        assert "timed out" in msg.lower() or "timeout" in msg.lower()


# ═══════════════════════════════════════════════════════════════════════════
# Callback / HITL — services/telegram/callbacks.py
# ═══════════════════════════════════════════════════════════════════════════


class TestCallbackHitl:
    """בדיקות עבור callbacks._handle_auto_kill/_handle_auto_block — HITL fail-safe."""

    async def test_auto_kill_pid_recycling(self):
        """PID changed between queue and execute → rejected, marked ABORTED."""
        from services.telegram.callbacks import _handle_auto_kill

        action = {
            "id": 1,
            "status": "PENDING_APPROVAL",
            "target": "1234|malware.exe",
        }
        mock_proc = MagicMock()
        mock_proc.name.return_value = "benign.exe"  # Different name → recycling

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("psutil.Process", return_value=mock_proc),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})

        assert not ok
        assert "RECYCLING" in text or "recycl" in text.lower() or "ABORT" in text
        # Should be marked ABORTED
        mock_update.assert_called()
        call_args = mock_update.call_args
        assert call_args[0][1] == "ABORTED" or call_args.kwargs.get("status") == "ABORTED"

    async def test_auto_kill_process_already_dead(self):
        """NoSuchProcess at execute → ALREADY_DEAD status."""
        import psutil

        from services.telegram.callbacks import _handle_auto_kill

        action = {
            "id": 2,
            "status": "PENDING_APPROVAL",
            "target": "5678|malware.exe",
        }

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("psutil.Process", side_effect=psutil.NoSuchProcess(5678)),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 2})

        assert ok  # already dead is "ok" — nothing to do
        assert "already dead" in text.lower() or "ALREADY_DEAD" in text or "dead" in text.lower()
        mock_update.assert_called_with(2, "ALREADY_DEAD")

    async def test_auto_block_action_not_found(self):
        """pending action missing → graceful error."""
        from services.telegram.callbacks import _handle_auto_block

        with patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=None):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 999})

        assert not ok
        assert "not found" in text.lower()

    async def test_auto_block_already_executed(self):
        """action status already APPROVED → no re-execute."""
        from services.telegram.callbacks import _handle_auto_block

        action = {
            "id": 3,
            "status": "APPROVED",
            "target": "8.8.8.8",
        }

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("services.telegram.callbacks.block_ip_in_firewall") as mock_block,
        ):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 3})

        assert not ok
        assert "already" in text.lower()
        mock_block.assert_not_called()
        mock_update.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# DEGRADED Mode Interaction — B1 + B2 FIXES
# ═══════════════════════════════════════════════════════════════════════════


class TestDegradedModeInteraction:
    """בדיקות DEGRADED mode — וידוא שפעולות הרסניות נחסמות כשה-Critic מחוץ לרשת."""

    def test_remediation_kill_process_respects_degraded(self):
        """B1: kill_process in remediation_engine must check DEGRADED mode and refuse."""
        from services.remediation_engine import kill_process

        ok, msg = kill_process(999, "malware.exe", degraded_mode=True)
        assert not ok, "kill_process should refuse in DEGRADED mode"
        assert "DEGRADED" in msg or "degraded" in msg.lower()

    def test_remediation_kill_process_normal_mode_works(self):
        """B1 regression: normal mode (degraded_mode=False) still works."""
        from services.remediation_engine import kill_process

        mock_proc = MagicMock()
        mock_proc.name.return_value = "malware.exe"
        with patch("services.remediation_engine.psutil.Process", return_value=mock_proc):
            ok, msg = kill_process(999, "malware.exe", degraded_mode=False)
        assert ok, f"Normal mode kill should work: {msg}"
        mock_proc.kill.assert_called_once()

    async def test_callback_auto_kill_respects_degraded(self):
        """B2: _handle_auto_kill must check DEGRADED and refuse."""
        from services.telegram.callbacks import _handle_auto_kill

        action = {
            "id": 10,
            "status": "PENDING_APPROVAL",
            "target": "1234|malware.exe",
        }

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("services.telegram.callbacks._is_degraded_mode", return_value=True),
            patch("services.telegram.callbacks.kill_process") as mock_kill,
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 10})

        assert not ok, "Auto-kill should refuse in DEGRADED mode"
        assert "DEGRADED" in text or "degraded" in text.lower()
        mock_kill.assert_not_called()
        mock_update.assert_called_with(10, "FAILED")

    async def test_callback_auto_block_respects_degraded(self):
        """B2: _handle_auto_block must check DEGRADED and refuse."""
        from services.telegram.callbacks import _handle_auto_block

        action = {
            "id": 11,
            "status": "PENDING_APPROVAL",
            "target": "8.8.8.8",
        }

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("services.telegram.callbacks._is_degraded_mode", return_value=True),
            patch("services.telegram.callbacks.block_ip_in_firewall") as mock_block,
        ):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 11})

        assert not ok, "Auto-block should refuse in DEGRADED mode"
        assert "DEGRADED" in text or "degraded" in text.lower()
        mock_block.assert_not_called()
        mock_update.assert_called_with(11, "FAILED")
