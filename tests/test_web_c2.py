import base64
import logging
import os
from subprocess import CompletedProcess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.web_c2 import C2DashboardServer
from services.web_c2_auth import check_basic_auth, client_ip_allowed
from services.web_c2_data import extract_reason, get_gpu_vram_stats, get_health, parse_trigger


class TestClientIpAllowed:
    """Layer 3: IP-based access control tests."""

    def test_loopback_ipv4(self):
        assert client_ip_allowed("127.0.0.1") is True

    def test_loopback_ipv6(self):
        assert client_ip_allowed("::1") is True

    def test_rfc1918_class_a(self):
        assert client_ip_allowed("10.0.0.5") is True

    def test_rfc1918_class_b(self):
        assert client_ip_allowed("172.20.1.100") is True

    def test_rfc1918_class_c(self):
        assert client_ip_allowed("192.168.1.100") is True

    def test_ipv6_link_local(self):
        assert client_ip_allowed("fe80::1") is True

    def test_external_ip_blocked(self):
        assert client_ip_allowed("8.8.8.8") is False

    def test_none_blocked(self):
        assert client_ip_allowed(None) is False

    def test_empty_string_blocked(self):
        assert client_ip_allowed("") is False

    def test_ipv6_mapped_loopback(self):
        assert client_ip_allowed("::ffff:127.0.0.1") is True

    def test_ipv6_mapped_rfc1918(self):
        assert client_ip_allowed("::ffff:192.168.1.5") is True

    def test_invalid_ip_blocked(self):
        assert client_ip_allowed("not-an-ip") is False

    def test_public_ipv6_blocked(self):
        assert client_ip_allowed("2001:4860:4860::8888") is False


class TestCheckBasicAuth:
    """Layer 7: HTTP Basic Auth tests."""

    @patch("services.web_c2_auth.WEB_C2_AUTH_PASSWORD", "secret123")
    @patch("services.web_c2_auth.WEB_C2_AUTH_USER", "admin")
    def test_valid_credentials(self):
        creds = base64.b64encode(b"admin:secret123").decode()
        assert check_basic_auth(f"Basic {creds}") is True

    @patch("services.web_c2_auth.WEB_C2_AUTH_PASSWORD", "secret123")
    @patch("services.web_c2_auth.WEB_C2_AUTH_USER", "admin")
    def test_invalid_password(self):
        creds = base64.b64encode(b"admin:wrong").decode()
        assert check_basic_auth(f"Basic {creds}") is False

    @patch("services.web_c2_auth.WEB_C2_AUTH_PASSWORD", "secret123")
    @patch("services.web_c2_auth.WEB_C2_AUTH_USER", "admin")
    def test_invalid_user(self):
        creds = base64.b64encode(b"root:secret123").decode()
        assert check_basic_auth(f"Basic {creds}") is False

    @patch("services.web_c2_auth.WEB_C2_AUTH_PASSWORD", "")
    def test_no_password_configured(self):
        creds = base64.b64encode(b"admin:secret123").decode()
        assert check_basic_auth(f"Basic {creds}") is False

    def test_missing_header(self):
        assert check_basic_auth(None) is False

    def test_malformed_header(self):
        assert check_basic_auth("Bearer token123") is False

    def test_bad_base64(self):
        assert check_basic_auth("Basic !!!notvalid!!!") is False

    def test_no_colon_in_decoded(self):
        creds = base64.b64encode(b"nocolonhere").decode()
        assert check_basic_auth(f"Basic {creds}") is False


class TestC2DashboardServer:
    """C2DashboardServer initialization and host selection."""

    def test_default_host_is_loopback(self, monkeypatch):
        monkeypatch.delenv("WEB_C2_HOST", raising=False)
        srv = C2DashboardServer()
        assert srv.host == "127.0.0.1"

    @patch.dict(os.environ, {"WEB_C2_HOST": "0.0.0.0", "WEB_C2_LAN_ALLOWED": "true"})
    def test_env_override(self):
        srv = C2DashboardServer()
        # 0.0.0.0 requires explicit opt-in (S-11) — IP whitelist + Session 0 boundary.
        assert srv.host == "0.0.0.0"

    @patch.dict(os.environ, {"WEB_C2_HOST": "0.0.0.0", "WEB_C2_LAN_ALLOWED": ""})
    def test_lan_binding_requires_opt_in(self):
        """S-11: 0.0.0.0 without WEB_C2_LAN_ALLOWED=true must raise."""
        with pytest.raises(ValueError, match="explicit opt-in"):
            C2DashboardServer()

    def test_explicit_host_param(self):
        srv = C2DashboardServer(host="192.168.1.1")
        assert srv.host == "192.168.1.1"

    @patch.dict(os.environ, {"WEB_C2_HOST": "0.0.0.0", "WEB_C2_LAN_ALLOWED": "true"})
    def test_explicit_param_overrides_env(self):
        srv = C2DashboardServer(host="127.0.0.1")
        assert srv.host == "127.0.0.1"

    @patch.dict(os.environ, {}, clear=False)
    @patch("config.WEB_C2_AUTH_PASSWORD", "")
    def test_empty_password_logs_error(self, caplog, monkeypatch):
        monkeypatch.delenv("WEB_C2_HOST", raising=False)
        monkeypatch.delenv("WEB_C2_LAN_ALLOWED", raising=False)
        with caplog.at_level(logging.ERROR, logger="services.web_c2"):
            C2DashboardServer()
        assert "WEB_C2_AUTH_PASSWORD is empty" in caplog.text


class TestInitiate2FA:
    """_initiate_2fa: generic 2FA challenge initiation for sensitive ops."""

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._send_otp_via_telegram", new_callable=AsyncMock)
    @patch("services.two_factor.initiate_challenge")
    async def test_success(self, mock_initiate, mock_send_otp):
        from services.web_c2_commands import _initiate_2fa

        mock_initiate.return_value = ("challenge-abc-123", "123456")
        result = await _initiate_2fa("reload_hashes")

        assert result["status"] == "pending_2fa"
        assert result["code"] == 202
        assert result["challenge_id"] == "challenge-abc-123"
        mock_send_otp.assert_awaited_once_with("reload_hashes", "challenge-abc-123", "123456")

    @pytest.mark.asyncio
    @patch("services.two_factor.initiate_challenge")
    async def test_rate_limited(self, mock_initiate):
        from services.two_factor import OTPRateLimitError
        from services.web_c2_commands import _initiate_2fa

        mock_initiate.side_effect = OTPRateLimitError(30.0, "cooldown")
        result = await _initiate_2fa("reload_hashes")

        assert result["status"] == "error"
        assert result["code"] == 429
        assert "cooldown" in result["error"]
        assert result["retry_after"] == 30

    @pytest.mark.asyncio
    @patch("services.two_factor.initiate_challenge")
    async def test_initiation_failed(self, mock_initiate):
        from services.web_c2_commands import _initiate_2fa

        mock_initiate.return_value = None
        result = await _initiate_2fa("reload_hashes")

        assert result["status"] == "error"
        assert result["code"] == 500
        assert "2FA initiation failed" in result["error"]


class TestVerify2FA:
    """_verify_2fa: OTP verification gate."""

    def test_missing_otp_code(self):
        from services.web_c2_commands import _verify_2fa

        result = _verify_2fa("reload_hashes", None, "challenge-123")
        assert result is not None
        assert result["status"] == "error"
        assert result["code"] == 403
        assert "OTP code required" in result["error"]

    @patch("services.two_factor.verify_challenge", return_value=False)
    def test_wrong_code(self, mock_verify):
        from services.web_c2_commands import _verify_2fa

        result = _verify_2fa("reload_hashes", "wrong", "challenge-123")
        assert result is not None
        assert result["status"] == "error"
        assert result["code"] == 403
        assert "2FA verification failed" in result["error"]

    @patch("services.two_factor.verify_challenge", return_value=True)
    def test_success(self, mock_verify):
        from services.web_c2_commands import _verify_2fa

        result = _verify_2fa("reload_hashes", "123456", "challenge-123")
        assert result is None


class TestDispatchSensitive:
    """_dispatch_sensitive: full 2FA flow orchestration."""

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._initiate_2fa", new_callable=AsyncMock)
    async def test_no_challenge_id_initiates_2fa(self, mock_initiate):
        from services.web_c2_commands import _dispatch_sensitive

        mock_initiate.return_value = {"status": "pending_2fa", "code": 202}
        result = await _dispatch_sensitive("reload_hashes", None, None, None)

        assert result["status"] == "pending_2fa"
        mock_initiate.assert_awaited_once_with("reload_hashes")

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._verify_2fa")
    async def test_verify_fails_returns_error(self, mock_verify):
        from services.web_c2_commands import _dispatch_sensitive

        mock_verify.return_value = {"status": "error", "code": 403}
        result = await _dispatch_sensitive("reload_hashes", None, "wrong", "challenge-123")

        assert result["status"] == "error"
        assert result["code"] == 403

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._verify_2fa", return_value=None)
    async def test_no_handler_registered(self, mock_verify):
        from services.web_c2_commands import _dispatch_sensitive

        result = await _dispatch_sensitive("unknown_sensitive", None, "123456", "challenge-123")
        assert result["status"] == "error"
        assert result["code"] == 500

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._verify_2fa", return_value=None)
    async def test_handler_executed_after_2fa(self, mock_verify):
        from services.web_c2_commands import _dispatch_sensitive

        result = await _dispatch_sensitive("reload_hashes", None, "123456", "challenge-123")
        assert result["status"] == "ok"
        assert "Reloaded" in result["message"]


class TestDispatchCommand:
    """dispatch_command: generic 2FA gate routing."""

    @pytest.mark.asyncio
    async def test_empty_cmd(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._dispatch_kill_process", new_callable=AsyncMock)
    async def test_kill_process_routed(self, mock_kill):
        from services.web_c2_commands import dispatch_command

        mock_kill.return_value = {"status": "ok"}
        result = await dispatch_command("kill_process", target="1234")
        mock_kill.assert_awaited_once_with("1234")

    @pytest.mark.asyncio
    @patch("services.web_c2_commands._dispatch_sensitive", new_callable=AsyncMock)
    async def test_sensitive_cmd_routed_to_2fa(self, mock_sensitive):
        from services.web_c2_commands import dispatch_command

        mock_sensitive.return_value = {"status": "pending_2fa", "code": 202}
        result = await dispatch_command("reload_hashes")

        assert result["status"] == "pending_2fa"
        mock_sensitive.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unknown_cmd(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("bogus")
        assert result["status"] == "error"
        assert "Unknown command" in result["error"]


class TestParseTrigger:
    """Trigger string parsing utility."""

    def test_cpu_metric(self):
        cat, val = parse_trigger("cpu:78.5%")
        assert cat == "cpu"
        assert val == 78.5

    def test_ram_metric(self):
        cat, val = parse_trigger("ram:92.0%")
        assert cat == "ram"
        assert val == 92.0

    def test_net_metric_no_value(self):
        cat, val = parse_trigger("net:new_external_ip")
        assert cat == "net"
        assert val is None

    def test_proc_metric_no_value(self):
        cat, val = parse_trigger("proc:new_heavy_process")
        assert cat == "proc"
        assert val is None

    def test_unknown_format(self):
        cat, val = parse_trigger("garbage")
        assert cat is None
        assert val is None

    def test_none_input(self):
        cat, val = parse_trigger(None)
        assert cat is None
        assert val is None


class TestExtractReason:
    """Report reason extraction utility."""

    def test_strips_header_prefixes(self):
        report = "\U0001f7e0 warn\n\u2501\u2501\u2501\u2501\u2501\n\u05d4\u05ea\u05e8\u05d0\u05ea Sentinel [WARN]\n\u05e7\u05d8\u05d2\u05d5\u05e8\u05d9\u05d4: CPU\n\u05de\u05d3\u05d3: cpu_spike\nPayload text here"
        reason = extract_reason(report)
        assert "Payload text here" in reason

    def test_empty_report(self):
        assert extract_reason(None) == ""

    def test_plain_report(self):
        assert extract_reason("simple message") == "simple message"


class TestGpuVramStats:
    """VRAM probe via Windows Performance Counters (GPU Adapter Memory)."""

    @pytest.mark.asyncio
    async def test_no_gpu_on_non_windows(self):
        """Non-Windows platform → vram_status=no_gpu."""
        with patch("services.web_c2_data.os.name", "posix"):
            result = await get_gpu_vram_stats()
        assert result["vram_status"] == "no_gpu"
        assert result["used_gb"] == 0.0

    @pytest.mark.asyncio
    async def test_offline_when_powershell_fails(self):
        """PowerShell returns non-zero exit → vram_status=offline."""
        mock_result = CompletedProcess(args=[], returncode=1, stdout="", stderr="Get-Counter: not found")
        with (
            patch("services.web_c2_data.os.name", "nt"),
            patch("services.web_c2_data.subprocess.run", return_value=mock_result),
        ):
            result = await get_gpu_vram_stats()
        assert result["vram_status"] == "offline"

    @pytest.mark.asyncio
    async def test_no_gpu_when_counters_empty(self):
        """PowerShell returns no GPU instances → vram_status=no_gpu."""
        mock_result = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with (
            patch("services.web_c2_data.os.name", "nt"),
            patch("services.web_c2_data.subprocess.run", return_value=mock_result),
        ):
            result = await get_gpu_vram_stats()
        assert result["vram_status"] == "no_gpu"

    @pytest.mark.asyncio
    async def test_ok_with_counter_values(self):
        """Valid counter output → correct GB conversion and percentage."""
        # Simulate: primary GPU with 4.635 GB dedicated, 6.973 GB committed
        # PowerShell output: "instance|value" lines, dedicated first then committed
        stdout = (
            "luid_0x00000000_0x0000bc01_phys_0|4976402432\n"
            "luid_0x00000000_0x0000df37_phys_0|0\n"
            "luid_0x00000000_0x0000bc01_phys_0|7486988288\n"
            "luid_0x00000000_0x0000df37_phys_0|770048\n"
        )
        mock_result = CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with (
            patch("services.web_c2_data.os.name", "nt"),
            patch("services.web_c2_data.subprocess.run", return_value=mock_result),
        ):
            result = await get_gpu_vram_stats()
        assert result["vram_status"] == "ok"
        assert result["total_gb"] == pytest.approx(6.97, abs=0.05)
        assert result["used_gb"] == pytest.approx(4.63, abs=0.05)
        assert result["percent"] == pytest.approx(66.4, abs=1.0)


class TestGetHealthVramIntegration:
    """get_health() merges VRAM without clobbering main status."""

    @pytest.mark.asyncio
    async def test_health_includes_vram_keys_when_offline(self):
        """Even when VRAM probe fails, health dict has vram_* keys."""
        with patch("services.web_c2_data.get_gpu_vram_stats", new_callable=AsyncMock) as mock_vram:
            mock_vram.return_value = {
                "used_gb": 0.0,
                "total_gb": 0.0,
                "percent": 0.0,
                "vram_status": "offline",
            }
            with (
                patch("psutil.cpu_percent", return_value=45.0),
                patch("psutil.virtual_memory") as mock_ram,
                patch("psutil.disk_usage") as mock_disk,
            ):
                mock_ram.return_value = MagicMock(percent=50.0, total=16 * 1024**3, available=8 * 1024**3)
                mock_disk.return_value = MagicMock(percent=60.0, free=100 * 1024**3)
                data = await get_health()
        assert data["status"] == "ok"
        assert data["vram_status"] == "offline"
        assert "used_gb" in data
        assert "total_gb" in data
        assert "percent" in data

    @pytest.mark.asyncio
    async def test_health_status_not_clobbered_by_vram(self):
        """Main health status stays 'ok' even if VRAM reports 'offline'."""
        with patch("services.web_c2_data.get_gpu_vram_stats", new_callable=AsyncMock) as mock_vram:
            mock_vram.return_value = {
                "used_gb": 0.0,
                "total_gb": 0.0,
                "percent": 0.0,
                "vram_status": "offline",
            }
            with (
                patch("psutil.cpu_percent", return_value=30.0),
                patch("psutil.virtual_memory") as mock_ram,
                patch("psutil.disk_usage") as mock_disk,
            ):
                mock_ram.return_value = MagicMock(percent=40.0, total=16 * 1024**3, available=10 * 1024**3)
                mock_disk.return_value = MagicMock(percent=50.0, free=200 * 1024**3)
                data = await get_health()
        assert data["status"] == "ok"
        assert data["vram_status"] == "offline"
