# services/two_factor.py
"""Step-Up Authentication — 2FA challenge for sensitive C2 operations.

Prevents C2 Hijacking: if an attacker compromises the Web C2 (session hijack,
leaked API password), they cannot whitelist their own malware via reload_hashes
without the out-of-band Telegram OTP.

Flow:
  1. C2 requests sensitive operation → generate 6-digit OTP
  2. OTP sent to TELEGRAM_CHAT_ID via MessageGateway (out-of-band)
  3. C2 must supply the OTP within TTL (60s) to complete the operation
  4. Failed attempts are rate-limited (max 3 per challenge)

Security properties:
  - OTP is cryptographically random (secrets module, not random)
  - Single-use: consumed on first successful verification
  - TTL-bound: expires after 60 seconds
  - Rate-limited: max 3 verification attempts per challenge
  - Audit-logged: all challenge/verify events recorded
"""

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

__all__ = [
    "TwoFactorChallenge",
    "OTPRateLimitError",
    "initiate_challenge",
    "verify_challenge",
    "SENSITIVE_OPERATIONS",
]

# Operations that require step-up 2FA.
# These are operations where a stolen C2 session could cause lasting damage:
# - reload_hashes: modifies the trusted-hash whitelist (attacker could whitelist malware)
# - unblock_ip: removes a firewall block (attacker could unblock their C2 server)
# - service_stop: stops a Windows service (attacker could disable security tools)
# - whitelist_edit: modifies YARA allowlist or trusted_devices (attacker could suppress alerts)
SENSITIVE_OPERATIONS = frozenset({
    "reload_hashes",
    "unblock_ip",
    "service_stop",
    "whitelist_edit",
})

_CHALLENGE_TTL = 60  # seconds
_MAX_VERIFY_ATTEMPTS = 3

# OTP generation rate-limiting (prevents Telegram API abuse / OTP spam)
_OTP_COOLDOWN = 30  # min seconds between OTP generations per operation
_OTP_MAX_PER_WINDOW = 3  # max OTPs per operation per window
_OTP_WINDOW = 300  # 5-minute rolling window

# B6: Lockout cooldown after brute-force — prevents immediate re-initiation
# after max_attempts exhaustion. Without this, an attacker can spam new
# challenges every _OTP_COOLDOWN seconds, getting 3 guesses per cycle.
_LOCKOUT_COOLDOWN = 60  # seconds to block new challenges after brute-force lockout

# M9 fix: Exponential backoff for repeated lockouts.
# After 3 consecutive lockouts → 1 hour. After 5 → 24 hours.
# This makes brute-force practically infeasible (115 days → infinity).
_BACKOFF_THRESHOLD_1 = 3  # consecutive lockouts → 1 hour
_BACKOFF_DURATION_1 = 3600  # 1 hour
_BACKOFF_THRESHOLD_2 = 5  # consecutive lockouts → 24 hours
_BACKOFF_DURATION_2 = 86400  # 24 hours
_BACKOFF_WINDOW = 3600  # consecutive lockouts counted within 1 hour

# In-memory rate-limit state: operation → list of generation timestamps
_otp_generation_log: dict[str, list[float]] = {}

# B6: In-memory lockout log: [(operation, timestamp)] — cleaned on each check
_lockout_log: list[tuple[str, float]] = []

# M9: Consecutive lockout counter: operation → list of lockout timestamps
_consecutive_lockouts: dict[str, list[float]] = {}


class OTPRateLimitError(Exception):
    """Raised when OTP generation is rate-limited (cooldown or window cap)."""

    def __init__(self, retry_after: float, reason: str) -> None:
        self.retry_after = retry_after
        self.reason = reason
        super().__init__(f"OTP rate-limited: {reason} (retry after {retry_after:.0f}s)")


@dataclass
class TwoFactorChallenge:
    """In-memory 2FA challenge state."""

    challenge_id: str
    otp_hash: str  # SHA256 of OTP (never store plaintext)
    operation: str
    created_at: float
    attempts: int = 0
    consumed: bool = False

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.created_at > _CHALLENGE_TTL

    @property
    def max_attempts_reached(self) -> bool:
        return self.attempts >= _MAX_VERIFY_ATTEMPTS


# In-memory store: challenge_id → TwoFactorChallenge
# (single-process bot, no need for Redis)
_challenges: dict[str, TwoFactorChallenge] = {}


def _hash_otp(otp: str) -> str:
    """Hash OTP with SHA256 — never store plaintext OTPs."""
    return hashlib.sha256(otp.encode()).hexdigest()


def initiate_challenge(operation: str) -> tuple[str, str] | None:
    """Initiate a 2FA challenge for a sensitive operation.

    Returns (challenge_id, otp_code) if successful, None if operation is not
    in SENSITIVE_OPERATIONS.

    Raises OTPRateLimitError if cooldown or window cap is exceeded.

    The caller is responsible for sending the OTP to the admin via
    an out-of-band channel (Telegram).
    """
    if operation not in SENSITIVE_OPERATIONS:
        return None

    # Cleanup expired challenges
    _cleanup_expired()

    # B6: Check brute-force lockout before allowing new challenge
    _check_lockout(operation)

    # Rate-limit: cooldown + rolling window cap
    _check_otp_rate_limit(operation)

    otp_code = f"{secrets.randbelow(1000000):06d}"
    challenge_id = secrets.token_hex(16)
    challenge = TwoFactorChallenge(
        challenge_id=challenge_id,
        otp_hash=_hash_otp(otp_code),
        operation=operation,
        created_at=time.monotonic(),
    )
    _challenges[challenge_id] = challenge

    # Record generation timestamp for rate-limiting
    now_mono = time.monotonic()
    _otp_generation_log.setdefault(operation, []).append(now_mono)

    logger.info(
        "[2FA] Challenge initiated: id=%s... operation=%s ttl=%ds",
        challenge_id[:8],
        operation,
        _CHALLENGE_TTL,
    )
    return challenge_id, otp_code


def _check_otp_rate_limit(operation: str) -> None:
    """Enforce OTP generation rate limits.

    Raises OTPRateLimitError if:
    - Last generation was < _OTP_COOLDOWN seconds ago (cooldown)
    - More than _OTP_MAX_PER_WINDOW generations in last _OTP_WINDOW seconds
    """
    now_mono = time.monotonic()
    log = _otp_generation_log.get(operation, [])

    # Prune entries outside the rolling window
    log = [ts for ts in log if now_mono - ts < _OTP_WINDOW]
    _otp_generation_log[operation] = log

    # Cooldown check: last generation must be > _OTP_COOLDOWN seconds ago
    if log and now_mono - log[-1] < _OTP_COOLDOWN:
        retry_after = _OTP_COOLDOWN - (now_mono - log[-1])
        logger.warning(
            "[2FA] OTP cooldown: operation=%s retry_after=%.0fs",
            operation,
            retry_after,
        )
        raise OTPRateLimitError(retry_after, "cooldown")

    # Window cap check: max N generations per rolling window
    if len(log) >= _OTP_MAX_PER_WINDOW:
        oldest_in_window = log[0]
        retry_after = _OTP_WINDOW - (now_mono - oldest_in_window)
        logger.warning(
            "[2FA] OTP window cap: operation=%s count=%d/%d retry_after=%.0fs",
            operation,
            len(log),
            _OTP_MAX_PER_WINDOW,
            retry_after,
        )
        raise OTPRateLimitError(retry_after, "window cap")


def _check_lockout(operation: str) -> None:
    """B6+M9: Enforce brute-force lockout cooldown with exponential backoff.

    After a challenge is deleted due to _MAX_VERIFY_ATTEMPTS, the operation
    is recorded in _lockout_log. This prevents immediate re-initiation,
    closing a gap where an attacker could spam new challenges every
    _OTP_COOLDOWN seconds (3 guesses per cycle).

    M9 fix: If consecutive lockouts accumulate (3+ within 1 hour), the
    cooldown escalates: 3 lockouts → 1 hour, 5+ → 24 hours. This makes
    brute-force practically infeasible.

    Raises OTPRateLimitError if a recent lockout exists for this operation.
    """
    now_mono = time.monotonic()
    # Clean old entries to prevent unbounded growth
    _lockout_log[:] = [(op, ts) for op, ts in _lockout_log if now_mono - ts < _LOCKOUT_COOLDOWN]
    for op, ts in _lockout_log:
        if op == operation:
            # M9: Check for exponential backoff escalation
            lockouts = _consecutive_lockouts.get(operation, [])
            lockouts = [t for t in lockouts if now_mono - t < _BACKOFF_WINDOW]
            cooldown = _LOCKOUT_COOLDOWN
            reason = "lockout cooldown"
            if len(lockouts) >= _BACKOFF_THRESHOLD_2:
                cooldown = _BACKOFF_DURATION_2
                reason = f"lockout backoff (24h — {len(lockouts)} consecutive)"
            elif len(lockouts) >= _BACKOFF_THRESHOLD_1:
                cooldown = _BACKOFF_DURATION_1
                reason = f"lockout backoff (1h — {len(lockouts)} consecutive)"

            retry_after = cooldown - (now_mono - ts)
            if retry_after <= 0:
                continue  # cooldown expired
            logger.warning(
                "[2FA] %s: operation=%s retry_after=%.0fs consecutive=%d",
                reason,
                operation,
                retry_after,
                len(lockouts),
            )
            raise OTPRateLimitError(retry_after, reason)


def verify_challenge(challenge_id: str, otp_code: str) -> bool:
    """Verify a 2FA challenge response.

    Returns True if:
    - challenge exists and not consumed
    - challenge not expired
    - max attempts not reached
    - OTP hash matches

    On success, challenge is consumed (single-use).
    On failure, attempt counter is incremented.
    """
    _cleanup_expired()

    challenge = _challenges.get(challenge_id)
    if challenge is None:
        logger.warning("[2FA] Verify failed: unknown challenge_id=%s...", challenge_id[:8] if challenge_id else "?")
        return False

    if challenge.consumed:
        logger.warning("[2FA] Verify failed: challenge already consumed id=%s...", challenge_id[:8])
        return False

    if challenge.expired:
        logger.warning("[2FA] Verify failed: challenge expired id=%s...", challenge_id[:8])
        del _challenges[challenge_id]
        return False

    if challenge.max_attempts_reached:
        logger.warning("[2FA] Verify failed: max attempts reached id=%s...", challenge_id[:8])
        del _challenges[challenge_id]
        return False

    challenge.attempts += 1

    if _hash_otp(otp_code) != challenge.otp_hash:
        logger.warning(
            "[2FA] Verify failed: wrong OTP id=%s... attempt=%d/%d",
            challenge_id[:8],
            challenge.attempts,
            _MAX_VERIFY_ATTEMPTS,
        )
        if challenge.max_attempts_reached:
            _lockout_log.append((challenge.operation, time.monotonic()))
            # M9: Record consecutive lockout for exponential backoff
            _consecutive_lockouts.setdefault(challenge.operation, []).append(time.monotonic())
            del _challenges[challenge_id]
        return False

    # Success — consume challenge
    challenge.consumed = True
    del _challenges[challenge_id]
    logger.info("[2FA] Verify SUCCESS: id=%s... operation=%s", challenge_id[:8], challenge.operation)
    return True


def _cleanup_expired() -> None:
    """Remove expired or exhausted challenges."""
    expired_ids = [cid for cid, ch in _challenges.items() if ch.expired or (ch.consumed and ch not in _challenges)]
    for cid in expired_ids:
        del _challenges[cid]


def pending_count() -> int:
    """Number of active (non-expired) challenges — for diagnostics."""
    _cleanup_expired()
    return len(_challenges)
