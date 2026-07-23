# tests/test_tier3_auth.py
"""Tests for Tier 3 Commit 2: M6 (token exchange) + M7 (brute-force) + M9 (backoff).

M6: Session token exchange — Basic Auth only at /api/auth/login
M7: Brute-force lockout — 10 failed attempts → 15 min lockout
M9: Exponential backoff — 3 lockouts → 1h, 5 → 24h
"""

import time
from unittest.mock import patch

import pytest

from services.web_c2_sessions import (
    create_session,
    get_lockout_remaining,
    is_ip_locked_out,
    record_failed_auth,
    record_successful_auth,
    reset_all,
    validate_session,
)

# ── M6: Session token exchange ──────────────────────────────────────


class TestSessionTokens:
    def setup_method(self):
        reset_all()

    def test_create_session_returns_token(self):
        token = create_session()
        assert isinstance(token, str)
        assert len(token) > 20

    def test_validate_active_session(self):
        token = create_session()
        assert validate_session(token) is True

    def test_validate_invalid_token(self):
        assert validate_session("invalid-token") is False

    def test_validate_none_token(self):
        assert validate_session(None) is False

    def test_validate_empty_token(self):
        assert validate_session("") is False

    def test_revoke_session(self):
        from services.web_c2_sessions import revoke_session

        token = create_session()
        assert revoke_session(token) is True
        assert validate_session(token) is False

    def test_revoke_nonexistent_session(self):
        from services.web_c2_sessions import revoke_session

        assert revoke_session("nonexistent") is False

    def test_expired_session_rejected(self):
        """Session past TTL is rejected and cleaned up."""
        token = create_session()
        # Simulate expiry by patching time
        with patch("services.web_c2_sessions.time.time", return_value=time.time() + 28801):
            assert validate_session(token) is False


# ── M7: Brute-force lockout ─────────────────────────────────────────


class TestBruteForceLockout:
    def setup_method(self):
        reset_all()

    def test_single_failed_attempt_no_lockout(self):
        assert record_failed_auth("10.0.0.1") is False
        assert is_ip_locked_out("10.0.0.1") is False

    def test_ten_failed_attempts_trigger_lockout(self):
        ip = "10.0.0.1"
        for _ in range(10):
            result = record_failed_auth(ip)
        assert result is True
        assert is_ip_locked_out(ip) is True

    def test_nine_failed_attempts_no_lockout(self):
        ip = "10.0.0.2"
        for _ in range(9):
            record_failed_auth(ip)
        assert is_ip_locked_out(ip) is False

    def test_successful_auth_clears_failures(self):
        ip = "10.0.0.3"
        for _ in range(5):
            record_failed_auth(ip)
        record_successful_auth(ip)
        # 5 more attempts should not trigger (counter reset)
        for _ in range(5):
            result = record_failed_auth(ip)
        assert result is False
        assert is_ip_locked_out(ip) is False

    def test_lockout_has_remaining_time(self):
        ip = "10.0.0.4"
        for _ in range(10):
            record_failed_auth(ip)
        remaining = get_lockout_remaining(ip)
        assert remaining > 0
        assert remaining <= 900  # 15 min

    def test_different_ips_tracked_separately(self):
        for _ in range(9):
            record_failed_auth("10.0.0.5")
        record_failed_auth("10.0.0.6")
        assert is_ip_locked_out("10.0.0.5") is False
        assert is_ip_locked_out("10.0.0.6") is False


# ── M9: Exponential backoff for OTP lockouts ────────────────────────


class TestOTPExponentialBackoff:
    def setup_method(self):
        from services.two_factor import _challenges, _consecutive_lockouts, _lockout_log, _otp_generation_log

        _challenges.clear()
        _lockout_log.clear()
        _consecutive_lockouts.clear()
        _otp_generation_log.clear()

    def test_three_consecutive_lockouts_escalate_to_1h(self):
        """M9: After 3 consecutive lockouts, cooldown becomes 1 hour."""
        from services.two_factor import (
            _BACKOFF_DURATION_1,
            _BACKOFF_THRESHOLD_1,
            OTPRateLimitError,
            _check_lockout,
            _consecutive_lockouts,
        )

        operation = "reload_hashes"
        # Simulate 3 consecutive lockouts
        now = time.monotonic()
        _consecutive_lockouts[operation] = [now, now, now]
        # Add a lockout log entry (just happened)
        from services.two_factor import _lockout_log

        _lockout_log.append((operation, now))

        with pytest.raises(OTPRateLimitError) as exc_info:
            _check_lockout(operation)
        # Should be ~3600 seconds (1 hour), not 60 seconds
        assert exc_info.value.retry_after > 3500  # close to 1h
        assert "backoff" in exc_info.value.reason.lower()

    def test_five_consecutive_lockouts_escalate_to_24h(self):
        """M9: After 5 consecutive lockouts, cooldown becomes 24 hours."""
        from services.two_factor import (
            OTPRateLimitError,
            _check_lockout,
            _consecutive_lockouts,
            _lockout_log,
        )

        operation = "reload_hashes"
        now = time.monotonic()
        _consecutive_lockouts[operation] = [now, now, now, now, now]
        _lockout_log.append((operation, now))

        with pytest.raises(OTPRateLimitError) as exc_info:
            _check_lockout(operation)
        assert exc_info.value.retry_after > 80000  # close to 24h
        assert "24h" in exc_info.value.reason

    def test_single_lockout_uses_base_cooldown(self):
        """M9: Single lockout uses base 60s cooldown (no escalation)."""
        from services.two_factor import (
            OTPRateLimitError,
            _check_lockout,
            _consecutive_lockouts,
            _lockout_log,
        )

        operation = "reload_hashes"
        now = time.monotonic()
        _consecutive_lockouts[operation] = [now]  # just 1
        _lockout_log.append((operation, now))

        with pytest.raises(OTPRateLimitError) as exc_info:
            _check_lockout(operation)
        assert exc_info.value.retry_after < 70  # ~60s base
        assert "cooldown" in exc_info.value.reason.lower()
        assert "backoff" not in exc_info.value.reason.lower()
