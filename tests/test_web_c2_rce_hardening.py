# tests/test_web_c2_rce_hardening.py
"""Security hardening tests for Web C2 hidden network commands.

Covers rate limiter, command whitelist/injection, PID validation (B4),
info-leak prevention (B5), auth bypass, and 2FA bypass attempts.
"""

import json
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_rate_store():
    """Clear the C2 rate-limit store before and after each test."""
    from services.web_c2_routes import _c2_rate_store

    _c2_rate_store.clear()
    yield
    _c2_rate_store.clear()


@pytest.fixture(autouse=True)
def _clear_2fa_state():
    """Clear 2FA challenge + OTP generation + lockout state."""
    from services.two_factor import _challenges, _lockout_log, _otp_generation_log

    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()
    yield
    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()


def _make_request(payload_dict=None, *, remote="127.0.0.1", json_body=None, raw_body=None):
    """Build a mock aiohttp Request for /api/command."""
    req = MagicMock()
    req.remote = remote
    req.path = "/api/command"
    req.query = {}

    if raw_body is not None:
        req.json = AsyncMock(side_effect=raw_body)
    elif json_body is not None:
        req.json = AsyncMock(return_value=json_body)
    elif payload_dict is not None:
        req.json = AsyncMock(return_value=payload_dict)
    else:
        req.json = AsyncMock(return_value={})

    return req


# ── Rate Limiter ──────────────────────────────────────────────────────


class TestRateLimiter:
    """C2 rate limiter: 10 req/min per IP, per-IP isolation, window expiry."""

    def test_rate_limit_allows_10_per_minute(self):
        from services.web_c2_routes import _check_c2_rate_limit

        for _ in range(10):
            assert _check_c2_rate_limit("10.0.0.1") is True

    def test_rate_limit_blocks_11th(self):
        from services.web_c2_routes import _check_c2_rate_limit

        for _ in range(10):
            assert _check_c2_rate_limit("10.0.0.2") is True
        # 11th request → blocked
        assert _check_c2_rate_limit("10.0.0.2") is False

    def test_rate_limit_window_expiry(self):
        from services.web_c2_routes import _C2_RATE_WINDOW, _c2_rate_store, _check_c2_rate_limit

        # Exhaust the limit
        for _ in range(10):
            assert _check_c2_rate_limit("10.0.0.3") is True
        assert _check_c2_rate_limit("10.0.0.3") is False

        # Simulate window expiry: backdate all timestamps past the window
        expired = time.time() - _C2_RATE_WINDOW - 1
        _c2_rate_store["10.0.0.3"] = [expired] * 10

        # After window expiry, new request should be allowed (counter resets)
        assert _check_c2_rate_limit("10.0.0.3") is True

    def test_rate_limit_per_ip_isolation(self):
        from services.web_c2_routes import _check_c2_rate_limit

        # Exhaust IP A
        for _ in range(10):
            assert _check_c2_rate_limit("10.0.0.10") is True
        assert _check_c2_rate_limit("10.0.0.10") is False

        # IP B should still be allowed
        assert _check_c2_rate_limit("10.0.0.11") is True

    @pytest.mark.asyncio
    async def test_rate_limit_audit_log_on_block(self):
        """429 response path writes an audit log entry."""
        from services.web_c2_routes import _check_c2_rate_limit, api_command

        # Exhaust the limit
        for _ in range(10):
            _check_c2_rate_limit("127.0.0.1")

        with patch("services.web_c2_routes.async_save_audit_log", new_callable=AsyncMock) as mock_audit:
            req = _make_request({"command": "kill_process", "target": "1234"}, remote="127.0.0.1")
            resp = await api_command(req)

        assert resp.status == 429
        mock_audit.assert_called_once()
        call_kwargs = mock_audit.call_args.kwargs
        assert call_kwargs.get("result") == "REJECTED: rate limit exceeded"


# ── Command Whitelist / Injection ─────────────────────────────────────


class TestCommandWhitelist:
    """Command whitelist enforcement and injection prevention."""

    @pytest.mark.asyncio
    async def test_unknown_command_rejected(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("exec_shell")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_command_name_injection(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process; rm -rf /")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_command_case_sensitive(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("KILL_PROCESS")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_empty_command(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_missing_command_field(self):
        """None command → 400 (missing cmd)."""
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command(None)
        assert result["status"] == "error"
        assert result["code"] == 400


# ── Target / PID Validation (B4 FIX) ──────────────────────────────────


class TestPidValidation:
    """B4: int(target) must validate bounds and catch non-numeric input."""

    @pytest.mark.asyncio
    async def test_target_negative_pid(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="-1")
        assert result["status"] == "error"
        assert result["code"] == 400
        assert "range" in result["error"].lower() or "out of range" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_target_overflow(self):
        """Absurdly large PID → 400, not a crash."""
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="999999999999999999999")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_target_non_numeric(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="abc")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_target_injection_chars(self):
        """Target with shell metacharacters → int() fails → 400."""
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="1234; whoami")
        assert result["status"] == "error"
        assert result["code"] == 400

    @pytest.mark.asyncio
    async def test_target_protected_pid_zero(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="0")
        assert result["status"] == "error"
        assert result["code"] == 403

    @pytest.mark.asyncio
    async def test_target_protected_pid_four(self):
        from services.web_c2_commands import dispatch_command

        result = await dispatch_command("kill_process", target="4")
        assert result["status"] == "error"
        assert result["code"] == 403

    @pytest.mark.asyncio
    async def test_target_valid_pid(self):
        """Valid PID → queued for HITL (pending status)."""
        from services.web_c2_commands import dispatch_command

        mock_proc = MagicMock()
        mock_proc.name.return_value = "notepad.exe"
        with (
            patch("psutil.Process", return_value=mock_proc),
            patch("services.pending_actions.set_pending", new_callable=AsyncMock) as mock_set,
        ):
            result = await dispatch_command("kill_process", target="1234")

        assert result["status"] == "pending"
        mock_set.assert_called_once()


# ── Auth Bypass ───────────────────────────────────────────────────────


class TestAuthBypass:
    """Verify the security middleware enforces auth + IP before dispatch."""

    @pytest.mark.asyncio
    async def test_dispatch_rejects_when_auth_missing(self):
        """security_middleware returns 401 when check_basic_auth fails."""
        from services.web_c2 import security_middleware

        req = MagicMock()
        req.remote = "127.0.0.1"
        req.path = "/api/command"
        req.headers = {}

        handler = AsyncMock()

        with (
            patch("services.web_c2.client_ip_allowed", return_value=True),
            patch("services.web_c2.check_basic_auth", return_value=False),
        ):
            resp = await security_middleware(req, handler)

        assert resp.status == 401
        handler.assert_not_called()  # dispatch never reached

    @pytest.mark.asyncio
    async def test_dispatch_rejects_external_ip(self):
        """security_middleware returns 403 for external IP."""
        from services.web_c2 import security_middleware

        req = MagicMock()
        req.remote = "8.8.8.8"
        req.path = "/api/command"
        req.headers = {}

        handler = AsyncMock()

        with (
            patch("services.web_c2.client_ip_allowed", return_value=False),
            patch("services.web_c2.check_basic_auth", return_value=True),
        ):
            resp = await security_middleware(req, handler)

        assert resp.status == 403
        handler.assert_not_called()  # dispatch never reached


# ── Error Handling / Info Leakage (B5 FIX) ────────────────────────────


class TestInfoLeakage:
    """B5: exception messages must not leak to the client."""

    @pytest.mark.asyncio
    async def test_exception_message_not_leaked(self):
        from services.web_c2_routes import api_command

        with patch("services.web_c2_routes.dispatch_command", new_callable=AsyncMock) as mock_dispatch:
            mock_dispatch.side_effect = Exception("internal secret db password")
            with patch("services.web_c2_routes.async_save_audit_log", new_callable=AsyncMock):
                req = _make_request({"command": "kill_process", "target": "1234"})
                resp = await api_command(req)

        body = json.loads(resp.text)
        assert resp.status == 500
        assert "internal secret" not in resp.text
        assert "internal secret" not in json.dumps(body)
        assert body["error"] == "internal error"

    @pytest.mark.asyncio
    async def test_malformed_json_payload(self):
        """Invalid JSON body → 400, no stack trace leaked."""
        from services.web_c2_routes import api_command

        with patch("services.web_c2_routes.async_save_audit_log", new_callable=AsyncMock):
            req = _make_request(raw_body=json.JSONDecodeError("Expecting value", "doc", 0))
            resp = await api_command(req)

        assert resp.status == 400
        body = json.loads(resp.text)
        assert "malformed" in body["error"].lower()

    @pytest.mark.asyncio
    async def test_oversized_payload_rejected(self):
        """Payload > 64KB → rejected (413 or 400)."""
        from services.web_c2_routes import api_command

        # Build a huge payload dict — oversized target fails int() → 400
        huge_value = "A" * (70 * 1024)
        huge_payload = {"command": "kill_process", "target": huge_value}

        with patch("services.web_c2_routes.async_save_audit_log", new_callable=AsyncMock):
            req = _make_request(huge_payload)
            resp = await api_command(req)

        # The oversized target fails int() in dispatch_command → 400
        assert resp.status in (400, 413)


# ── 2FA Bypass Attempts ───────────────────────────────────────────────


class TestTwoFactorBypass:
    """2FA challenge enumeration, brute force, replay, and expiry."""

    def test_challenge_id_enumeration(self):
        from services.two_factor import verify_challenge

        # Random/invalid challenge_id → False
        assert verify_challenge("deadbeef" * 8, "123456") is False
        assert verify_challenge("nonexistent_id", "000000") is False

    def test_otp_brute_force_lockout(self):
        """3 wrong OTPs → challenge deleted; 4th attempt rejected.

        B6 (cooldown after lockout) is owned by Phase 4 (two_factor.py).
        This test asserts the SECURE behavior: after 3 fails the challenge
        is gone, so a 4th attempt cannot succeed. If a future B6 fix adds
        a cooldown on new challenge creation, that's tested separately.
        """
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, correct_otp = result

        # 3 wrong attempts
        for i in range(3):
            assert verify_challenge(challenge_id, "111111") is False

        # Challenge is deleted after max attempts
        assert challenge_id not in _challenges

        # 4th attempt (even with correct OTP) → rejected (challenge gone)
        assert verify_challenge(challenge_id, correct_otp) is False

    def test_consumed_challenge_replay(self):
        """Successful verify → second verify with same OTP → False."""
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result

        assert verify_challenge(challenge_id, otp) is True
        # Replay attack: same OTP again → False
        assert verify_challenge(challenge_id, otp) is False

    def test_expired_challenge_reuse(self):
        """Challenge older than 60s → verify returns False."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        challenge_id, otp = result

        # Manually expire the challenge
        _challenges[challenge_id].created_at = time.monotonic() - 120

        assert verify_challenge(challenge_id, otp) is False
