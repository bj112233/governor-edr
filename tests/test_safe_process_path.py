# tests/test_safe_process_path.py
"""C4 fix: SAFE_PROCESSES path verification — malware masquerading defense.

Attack scenario: attacker drops C:\\Temp\\svchost.exe (malware).
Old code: name match → whitelisted → kill refused → malware protected.
New code: path check → not in SystemRoot → not safe → kill allowed.
"""

from unittest.mock import MagicMock, patch

import psutil
import pytest

from services.remediation_engine import _is_safe_system_process, kill_process


class TestIsSafeSystemProcess:
    def test_non_whitelisted_name_returns_false(self):
        assert _is_safe_system_process("chrome.exe", pid=1234) is False

    def test_whitelisted_name_no_pid_returns_true(self):
        """No PID = can't verify path, but name matches → name-only fallback."""
        assert _is_safe_system_process("svchost.exe", pid=None) is True

    def test_whitelisted_name_system_pid_returns_true(self):
        """PID <= 4 = kernel process, name-only check is sufficient."""
        assert _is_safe_system_process("system", pid=4) is True

    def test_whitelisted_name_legitimate_path_returns_true(self):
        """svchost.exe from C:\\Windows\\System32 → safe."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\Windows\System32\svchost.exe"
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=500) is True

    def test_whitelisted_name_malware_path_returns_false(self):
        """svchost.exe from C:\\Temp\\ → NOT safe (masquerading detected)."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\Temp\svchost.exe"
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=600) is False

    def test_whitelisted_name_appdata_path_returns_false(self):
        """svchost.exe from %APPDATA% → NOT safe."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\Users\attacker\AppData\svchost.exe"
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=700) is False

    def test_access_denied_returns_false_fail_closed(self):
        """Can't read exe path → fail-closed (don't protect potential malware)."""
        mock_proc = MagicMock()
        mock_proc.exe.side_effect = psutil.AccessDenied()
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=800) is False

    def test_no_such_process_returns_false(self):
        mock_proc = MagicMock()
        mock_proc.exe.side_effect = psutil.NoSuchProcess(999)
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=999) is False

    def test_empty_exe_path_returns_false(self):
        """Empty exe path → fail-closed."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = ""
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=1000) is False

    def test_syswow64_path_returns_true(self):
        """32-bit system process from SysWOW64 → safe."""
        mock_proc = MagicMock()
        mock_proc.exe.return_value = r"C:\Windows\SysWOW64\svchost.exe"
        with patch("psutil.Process", return_value=mock_proc):
            assert _is_safe_system_process("svchost.exe", pid=1100) is True


class TestKillProcessPathVerification:
    def test_malware_svchost_in_temp_is_killed(self):
        """Malware named svchost.exe in C:\\Temp → kill succeeds (not protected)."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "svchost.exe"
        mock_proc.exe.return_value = r"C:\Temp\svchost.exe"
        mock_proc.kill = MagicMock()
        with patch("psutil.Process", return_value=mock_proc):
            result, msg = kill_process(pid=600, proc_name="svchost.exe")
        assert result is True
        assert "terminated" in msg.lower()

    def test_legitimate_svchost_in_system32_is_protected(self):
        """Real svchost.exe from System32 → kill refused."""
        mock_proc = MagicMock()
        mock_proc.name.return_value = "svchost.exe"
        mock_proc.exe.return_value = r"C:\Windows\System32\svchost.exe"
        with patch("psutil.Process", return_value=mock_proc):
            result, msg = kill_process(pid=500, proc_name="svchost.exe")
        assert result is False
        assert "whitelisted" in msg.lower()
