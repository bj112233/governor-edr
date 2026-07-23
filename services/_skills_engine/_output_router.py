# services/_skills_engine/_output_router.py
"""Exit-code → user-facing message routing.

Extracted from executor.py (SRP): maps process return codes to
structured user messages, separating routing logic from execution.
"""

from services._winutil import _decode_oem


def route_success(stdout_b: bytes) -> str:
    """Decode + return success output (empty → success message)."""
    out = _decode_oem(stdout_b)
    return out or "✅ Command executed successfully"


def route_failure(
    stdout_b: bytes,
    stderr_b: bytes,
    returncode: int,
) -> str:
    """Route non-zero exit codes to user-facing error messages.

    Exit 1-2: argument/usage errors → "fix and retry" guidance.
    Other codes: generic exit-code report.
    """
    err = _decode_oem(stderr_b)[:800] if stderr_b else ""
    stdout_err = _decode_oem(stdout_b)[:800] if stdout_b and returncode != 0 else ""
    error_msg = err or stdout_err or "(no error output)"

    if returncode in (1, 2):
        return f"❌ Command failed. Reason:\n{error_msg.strip()}\n\nFix the arguments and try again."

    return f"❌ Exit code {returncode}: {error_msg.strip()}"


def timeout_message(timeout: int) -> str:
    """User-facing timeout message."""
    return (
        f"⏱️ Command timed out (>{timeout}s). "
        f"The skill may need a simpler input or the data is too large. "
        f"Try a different command or provide a smaller input."
    )
