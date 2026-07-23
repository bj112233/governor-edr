"""Web C2 command dispatch — remediation actions with HITL approval."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def execute_kill_process(pid: int) -> dict[str, Any]:
    """Queue a kill_process command for HITL approval.

    Args:
        pid: Process ID to kill

    Returns:
        Dict with status, message, and error (if any)

    Raises:
        ValueError: If PID is invalid or protected
        ProcessError: If process lookup fails
    """
    try:
        import psutil

        from services.pending_actions import set_pending
        from services.system_intel import _PROTECTED_NAMES, _PROTECTED_PIDS

        if pid in _PROTECTED_PIDS:
            return {
                "status": "error",
                "error": f"PID {pid} is a protected kernel process.",
                "code": 403,
            }

        p = psutil.Process(pid)
        name = p.name()
        if name.lower() in _PROTECTED_NAMES:
            return {
                "status": "error",
                "error": f"'{name}' is a protected system process.",
                "code": 403,
            }

        # HITL: queue for approval instead of immediate kill
        await set_pending(
            {
                "action": "kill_process",
                "target": pid,
                "reason": f"Kill {name} (PID {pid}) via Web C2",
            }
        )
        logger.warning(
            "[WebC2] COMMAND QUEUED: Kill PID %d (%s) pending HITL approval",
            pid,
            name,
        )
        return {
            "status": "pending",
            "message": f"Kill {name} (PID {pid}) queued for approval. Use /approve to execute.",
        }
    except ValueError as e:
        logger.warning("[WebC2] Invalid PID %s: %s", pid, e)
        return {"status": "error", "error": str(e), "code": 400}
    except Exception as e:
        logger.error("[WebC2] Command execution failed: %s", e)
        return {"status": "error", "error": str(e), "code": 500}


def _validate_kill_process_target(target: str | None) -> tuple[int | None, dict[str, Any] | None]:
    """Validate kill_process target — returns (pid, error_dict).

    pid is None on error; error_dict is None on success.
    """
    if not target:
        return None, {"status": "error", "error": "missing target", "code": 400}
    try:
        pid = int(target)
    except (ValueError, TypeError):
        return None, {"status": "error", "error": f"Invalid PID: {target}", "code": 400}
    if pid < 0 or pid > 4194304:  # 4194304 = max PID on Windows
        return None, {"status": "error", "error": "PID out of range", "code": 400}
    return pid, None


async def _initiate_reload_hashes_2fa() -> dict[str, Any]:
    """Step 1 of reload_hashes: initiate 2FA challenge and send OTP via Telegram."""
    from services.interfaces import get_message_gateway
    from services.two_factor import OTPRateLimitError, initiate_challenge

    try:
        result = initiate_challenge("reload_hashes")
    except OTPRateLimitError as exc:
        return {
            "status": "error",
            "error": f"OTP rate-limited: {exc.reason}",
            "retry_after": round(exc.retry_after),
            "code": 429,
        }
    if result is None:
        return {"status": "error", "error": "2FA initiation failed", "code": 500}
    new_challenge_id, otp = result

    # Send OTP out-of-band via Telegram (MessageGateway)
    gateway = get_message_gateway()
    if gateway is not None:
        from config import TELEGRAM_CHAT_ID

        if TELEGRAM_CHAT_ID:
            await gateway.send_message(
                TELEGRAM_CHAT_ID,
                f"🔐 **Step-Up Authentication Required**\n\n"
                f"Operation: `reload_hashes` (hash hot-reload)\n"
                f"Challenge ID: `{new_challenge_id[:8]}...`\n"
                f"OTP Code: `{otp}`\n\n"
                f"⏱️ Expires in 60 seconds. Use this code in the C2 to complete the operation.",
            )
        else:
            logger.warning("[WebC2] TELEGRAM_CHAT_ID not set — OTP cannot be delivered out-of-band")
    else:
        logger.warning("[WebC2] No message gateway — OTP cannot be delivered out-of-band")

    return {
        "status": "pending_2fa",
        "message": "2FA challenge initiated. Check Telegram for OTP code.",
        "challenge_id": new_challenge_id,
        "code": 202,
    }


async def _dispatch_kill_process(target: str | None) -> dict[str, Any]:
    """Handle kill_process command with target validation."""
    pid, err = _validate_kill_process_target(target)
    if err is not None:
        return err
    return await execute_kill_process(pid)


async def _dispatch_reload_hashes(
    otp_code: str | None, challenge_id: str | None
) -> dict[str, Any]:
    """Handle reload_hashes command with 2FA step-up authentication."""
    from services.self_whitelist import reload_hashes
    from services.two_factor import verify_challenge

    # Step 1: If no challenge_id → initiate 2FA, send OTP via Telegram
    if challenge_id is None:
        return await _initiate_reload_hashes_2fa()

    # Step 2: challenge_id provided → verify OTP, then execute
    if otp_code is None:
        return {
            "status": "error",
            "error": "OTP code required for reload_hashes",
            "challenge_id": challenge_id,
            "code": 403,
        }

    if not verify_challenge(challenge_id, otp_code):
        return {
            "status": "error",
            "error": "2FA verification failed (wrong code, expired, or max attempts reached)",
            "challenge_id": challenge_id,
            "code": 403,
        }

    # 2FA verified — execute the reload
    results = reload_hashes()
    logger.info("[WebC2] reload_hashes executed after 2FA verification (challenge=%s...)", challenge_id[:8])
    return {
        "status": "ok",
        "message": f"Reloaded {len(results)} hash(es) after 2FA verification",
        "details": results,
    }


async def dispatch_command(
    cmd: str,
    target: str | None = None,
    otp_code: str | None = None,
    challenge_id: str | None = None,
) -> dict[str, Any]:
    """Dispatch a C2 command.

    Args:
        cmd: Command name (e.g. "kill_process", "reload_hashes")
        target: Command target (e.g. PID as string)
        otp_code: 2FA code (required for sensitive operations)
        challenge_id: 2FA challenge ID (required for sensitive operation verification)

    Returns:
        Dict with status and result/error
    """
    if not cmd:
        return {"status": "error", "error": "missing cmd", "code": 400}

    if cmd == "kill_process":
        return await _dispatch_kill_process(target)

    if cmd == "reload_hashes":
        return await _dispatch_reload_hashes(otp_code, challenge_id)

    return {"status": "error", "error": f"Unknown command: {cmd}", "code": 400}


__all__ = [
    "execute_kill_process",
    "dispatch_command",
]
