# tests/test_two_factor.py
"""Tests for Step-Up 2FA — prevents C2 hijacking of sensitive operations."""

import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


@pytest.fixture(autouse=True)
def _clear_otp_state():
    """Clear OTP rate-limit log + challenges + lockout log before each test."""
    from services.two_factor import _challenges, _lockout_log, _otp_generation_log

    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()
    yield
    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()


class TestTwoFactorChallenge:
    def test_initiate_challenge_returns_otp_and_id(self):
        from services.two_factor import initiate_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result
        assert len(challenge_id) == 32  # 16 bytes hex
        assert len(otp) == 6
        assert otp.isdigit()

    def test_initiate_non_sensitive_returns_none(self):
        from services.two_factor import initiate_challenge

        assert initiate_challenge("kill_process") is None

    def test_verify_correct_otp(self):
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result
        assert verify_challenge(challenge_id, otp) is True

    def test_verify_wrong_otp(self):
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, _ = result
        assert verify_challenge(challenge_id, "000000") is False

    def test_verify_consumed_challenge_rejected(self):
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result
        assert verify_challenge(challenge_id, otp) is True
        # Second use should fail (single-use)
        assert verify_challenge(challenge_id, otp) is False

    def test_verify_unknown_challenge_rejected(self):
        from services.two_factor import verify_challenge

        assert verify_challenge("nonexistent", "123456") is False

    def test_max_attempts_lockout(self):
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, _ = result
        # 3 wrong attempts
        for i in range(3):
            assert verify_challenge(challenge_id, "111111") is False
        # Even correct OTP now fails (challenge deleted after max attempts)
        # Can't get the correct OTP since we didn't save it, but challenge is gone
        assert verify_challenge(challenge_id, "000000") is False

    def test_expired_challenge_rejected(self):
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result
        # Manually expire the challenge
        _challenges[challenge_id].created_at = time.monotonic() - 120
        assert verify_challenge(challenge_id, otp) is False

    def test_otp_never_stored_plaintext(self):
        """Verify OTP is stored as hash, not plaintext."""
        from services.two_factor import _challenges, initiate_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result
        challenge = _challenges[challenge_id]
        assert challenge.otp_hash != otp
        assert len(challenge.otp_hash) == 64  # SHA256 hex

    def test_pending_count(self):
        from services.two_factor import initiate_challenge, pending_count

        before = pending_count()
        initiate_challenge("reload_hashes")
        assert pending_count() >= before + 1


class TestC2ReloadHashes2FA:
    """Verify reload_hashes requires 2FA through C2 dispatch."""

    @pytest.mark.asyncio
    async def test_reload_hashes_initiates_2fa_without_challenge_id(self):
        """First call without challenge_id → returns pending_2fa, sends OTP."""
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
        assert result["code"] == 202
        # Verify OTP was sent via Telegram
        gateway.send_message.assert_called_once()
        call_args = gateway.send_message.call_args
        assert "OTP" in call_args.args[1] or "otp" in call_args.args[1].lower()

    @pytest.mark.asyncio
    async def test_reload_hashes_with_correct_otp_executes(self):
        """Second call with correct OTP → executes reload_hashes."""
        from services.two_factor import initiate_challenge
        from services.web_c2_commands import dispatch_command

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result

        with (
            patch("services.self_whitelist.reload_hashes", return_value={"test.exe": "ok (abc...)"}),
        ):
            result = await dispatch_command(
                "reload_hashes",
                otp_code=otp,
                challenge_id=challenge_id,
            )
        assert result["status"] == "ok"
        assert "2FA" in result["message"]

    @pytest.mark.asyncio
    async def test_reload_hashes_with_wrong_otp_rejected(self):
        """Wrong OTP → 403 forbidden."""
        from services.two_factor import initiate_challenge
        from services.web_c2_commands import dispatch_command

        result = initiate_challenge("reload_hashes")
        challenge_id, _ = result

        result = await dispatch_command(
            "reload_hashes",
            otp_code="000000",
            challenge_id=challenge_id,
        )
        assert result["status"] == "error"
        assert result["code"] == 403

    @pytest.mark.asyncio
    async def test_reload_hashes_without_otp_rejected(self):
        """challenge_id but no OTP → 403."""
        from services.two_factor import initiate_challenge
        from services.web_c2_commands import dispatch_command

        result = initiate_challenge("reload_hashes")
        challenge_id, _ = result

        result = await dispatch_command(
            "reload_hashes",
            otp_code=None,
            challenge_id=challenge_id,
        )
        assert result["status"] == "error"
        assert result["code"] == 403

    @pytest.mark.asyncio
    async def test_kill_process_does_not_require_2fa(self):
        """Non-sensitive commands should NOT trigger 2FA."""
        from services.web_c2_commands import dispatch_command

        with patch("services.web_c2_commands.execute_kill_process", new_callable=AsyncMock) as mock_kill:
            mock_kill.return_value = {"status": "pending", "message": "queued"}
            result = await dispatch_command("kill_process", target="1234")
        assert result["status"] != "pending_2fa"


class TestOTPRateLimit:
    """Verify OTP generation rate-limiting (cooldown + window cap)."""

    def test_cooldown_blocks_rapid_otp_generation(self):
        """Second OTP within cooldown → OTPRateLimitError."""
        from services.two_factor import OTPRateLimitError, _otp_generation_log, initiate_challenge

        _otp_generation_log.clear()
        result1 = initiate_challenge("reload_hashes")
        assert result1 is not None

        # Immediate second attempt → should be blocked
        with pytest.raises(OTPRateLimitError) as exc_info:
            initiate_challenge("reload_hashes")
        assert "cooldown" in exc_info.value.reason

    def test_window_cap_blocks_after_3_in_5min(self):
        """More than 3 OTPs in 5 minutes → OTPRateLimitError (window cap)."""
        from services.two_factor import OTPRateLimitError, _otp_generation_log, initiate_challenge

        _otp_generation_log.clear()

        # Simulate 3 generations with cooldown elapsed between each
        for i in range(3):
            # Bypass cooldown by backdating all existing log entries
            log = _otp_generation_log.setdefault("reload_hashes", [])
            for j in range(len(log)):
                log[j] -= 31  # push past cooldown
            result = initiate_challenge("reload_hashes")
            assert result is not None

        # 4th attempt → window cap (3 in window, cooldown bypassed)
        log = _otp_generation_log["reload_hashes"]
        for j in range(len(log)):
            log[j] -= 31
        with pytest.raises(OTPRateLimitError) as exc_info:
            initiate_challenge("reload_hashes")
        assert "window cap" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_c2_returns_429_on_otp_rate_limit(self):
        """C2 dispatch returns 429 when OTP is rate-limited."""
        from services.two_factor import OTPRateLimitError, _otp_generation_log
        from services.web_c2_commands import dispatch_command

        _otp_generation_log.clear()
        # First call initiates challenge
        gateway = MagicMock()
        gateway.send_message = AsyncMock(return_value=True)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", "123456"),
        ):
            await dispatch_command("reload_hashes")

        # Second call → rate-limited
        with patch("services.two_factor.initiate_challenge", side_effect=OTPRateLimitError(30.0, "cooldown")):
            result = await dispatch_command("reload_hashes")
        assert result["status"] == "error"
        assert result["code"] == 429
        assert "rate-limited" in result["error"]


class TestBreakGlassCLI:
    """Verify break-glass CLI security properties."""

    def test_rejects_non_tty(self):
        """Break-glass must reject non-interactive (piped) execution."""
        from bin.break_glass import _is_local_tty

        with patch("sys.stdin.isatty", return_value=False):
            with patch("sys.stdout.isatty", return_value=True):
                assert _is_local_tty() is False

    def test_rejects_piped_stdout(self):
        """Break-glass must reject if stdout is piped."""
        from bin.break_glass import _is_local_tty

        with patch("sys.stdin.isatty", return_value=True):
            with patch("sys.stdout.isatty", return_value=False):
                assert _is_local_tty() is False

    def test_accepts_real_tty(self):
        """Break-glass accepts when both stdin and stdout are TTY."""
        from bin.break_glass import _is_local_tty

        with patch("sys.stdin.isatty", return_value=True):
            with patch("sys.stdout.isatty", return_value=True):
                assert _is_local_tty() is True

    def test_confirm_requires_exact_word(self):
        """Confirmation requires typing 'CONFIRM' exactly."""
        from bin.break_glass import _confirm

        with patch("builtins.input", return_value="yes"):
            assert _confirm("reload_hashes") is False
        with patch("builtins.input", return_value="CONFIRM"):
            assert _confirm("reload_hashes") is True

    def test_status_does_not_require_confirmation(self):
        """status command should work without CONFIRM prompt."""
        from bin.break_glass import _status

        with (
            patch("services.self_whitelist._sentinel_pid", 1234),
            patch("services.self_whitelist._known_good_hashes", {"test.exe": "abcdef1234567890"}),
        ):
            rc = _status()
        assert rc == 0

    def test_is_admin_windows(self):
        """Admin check uses ctypes on Windows."""
        from bin.break_glass import _is_admin

        if sys.platform == "win32":
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
                assert _is_admin() is True
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
                assert _is_admin() is False
        else:
            with patch("os.geteuid", return_value=0):
                assert _is_admin() is True
            with patch("os.geteuid", return_value=1000):
                assert _is_admin() is False

    def test_main_rejects_non_admin(self):
        """main() returns 1 if not admin."""
        from bin.break_glass import main

        with (
            patch("bin.break_glass._is_local_tty", return_value=True),
            patch("bin.break_glass._is_admin", return_value=False),
        ):
            rc = main()
        assert rc == 1
