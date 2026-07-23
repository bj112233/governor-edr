# services/web_c2_sessions.py
"""Session token management for Web C2 — M6 fix (token exchange pattern).

Basic Auth is accepted ONLY at /api/auth/login. All other endpoints
require a Bearer token with 8-hour TTL. This ensures that even if a
Basic Auth header is stolen, it cannot be used for ongoing access —
the attacker must exchange it for a token, and tokens expire.
"""

from __future__ import annotations

import logging
import secrets
import time

logger = logging.getLogger(__name__)

# Session token TTL: 8 hours (stolen tokens die within this window)
_SESSION_TTL = 8 * 3600  # 28800 seconds

# In-memory session store: token → (expires_at, created_at)
# Single-process bot, no need for Redis
_sessions: dict[str, float] = {}

# M7: Failed auth attempt tracking — brute-force protection for LAN
_failed_attempts: dict[str, list[float]] = {}
_MAX_FAILED_ATTEMPTS = 10  # per IP
_FAILED_WINDOW = 900  # 15 min rolling window
_LOCKOUT_DURATION = 900  # 15 min lockout after threshold

# M7: Active lockouts: IP → lockout_expires_at
_lockouts: dict[str, float] = {}


def create_session() -> str:
    """Create a new session token with 8-hour TTL.

    Returns the opaque token string. Old sessions are cleaned up.
    """
    _cleanup_sessions()
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + _SESSION_TTL
    _sessions[token] = expires_at
    logger.info("[WebC2-Session] Created session token (expires in %dh)", _SESSION_TTL // 3600)
    return token


def validate_session(token: str | None) -> bool:
    """Validate a Bearer token. Returns True if valid and not expired."""
    if not token:
        return False
    _cleanup_sessions()
    expires_at = _sessions.get(token)
    if expires_at is None:
        return False
    if time.time() > expires_at:
        del _sessions[token]
        logger.info("[WebC2-Session] Token expired and removed")
        return False
    return True


def revoke_session(token: str | None) -> bool:
    """Revoke a session token (logout). Returns True if token existed."""
    if not token:
        return False
    existed = token in _sessions
    _sessions.pop(token, None)
    if existed:
        logger.info("[WebC2-Session] Session revoked")
    return existed


def _cleanup_sessions() -> None:
    """Remove expired sessions to prevent unbounded growth."""
    now = time.time()
    expired = [t for t, exp in _sessions.items() if now > exp]
    for t in expired:
        del _sessions[t]


# ── M7: Brute-force protection ─────────────────────────────────────


def is_ip_locked_out(client_ip: str) -> bool:
    """M7: Check if an IP is currently locked out due to failed auth attempts."""
    now = time.time()
    # Cleanup expired lockouts
    expired = [ip for ip, exp in _lockouts.items() if now > exp]
    for ip in expired:
        del _lockouts[ip]
    return client_ip in _lockouts


def record_failed_auth(client_ip: str) -> bool:
    """M7: Record a failed auth attempt. Returns True if IP is now locked out.

    After _MAX_FAILED_ATTEMPTS (10) in _FAILED_WINDOW (15 min), the IP
    is locked out for _LOCKOUT_DURATION (15 min).
    """
    now = time.time()
    # Filter to current window
    attempts = _failed_attempts.get(client_ip, [])
    attempts = [t for t in attempts if now - t < _FAILED_WINDOW]
    attempts.append(now)
    _failed_attempts[client_ip] = attempts

    if len(attempts) >= _MAX_FAILED_ATTEMPTS:
        _lockouts[client_ip] = now + _LOCKOUT_DURATION
        logger.warning(
            "[WebC2-Auth] IP %s locked out for %ds (%d failed attempts)",
            client_ip,
            _LOCKOUT_DURATION,
            len(attempts),
        )
        # Clear failed attempts — lockout is now active
        _failed_attempts.pop(client_ip, None)
        return True
    return False


def record_successful_auth(client_ip: str) -> None:
    """M7: Clear failed attempts on successful auth."""
    _failed_attempts.pop(client_ip, None)


def get_lockout_remaining(client_ip: str) -> float:
    """Return seconds remaining in lockout (0 if not locked out)."""
    exp = _lockouts.get(client_ip)
    if exp is None:
        return 0.0
    remaining = exp - time.time()
    return max(0.0, remaining)


def reset_all() -> None:
    """Reset all state — for testing only."""
    _sessions.clear()
    _failed_attempts.clear()
    _lockouts.clear()
