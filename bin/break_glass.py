#!/usr/bin/env python3
# ruff: noqa: E402
# bin/break_glass.py
"""Break-glass CLI — execute sensitive admin operations from local console.

Trust Zone: local terminal = highest trust (physical access).
Bypasses 2FA OTP requirement because the operator is physically present.

Usage:
    .\\.venv\\Scripts\\python.exe bin\break_glass.py reload_hashes
    .\\.venv\\Scripts\\python.exe bin\break_glass.py status

Security:
    - Only runs if stdin is a TTY (not piped/redirected — prevents remote injection)
    - Requires Administrator/root privileges (prevents unprivileged user hijacking)
    - Logs to audit log with "BREAK_GLASS" prefix
    - Requires explicit confirmation prompt before execution
"""

import os
import sys


def _is_admin() -> bool:
    """Check if running with Administrator (Windows) or root (Linux/Mac) privileges."""
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return hasattr(os, "geteuid") and os.geteuid() == 0


def _is_local_tty() -> bool:
    """Verify we're running in an interactive local terminal, not piped."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _confirm(operation: str) -> bool:
    """Require explicit y/N confirmation."""
    print(f"\n⚠️  BREAK-GLASS: {operation}")
    print("   This bypasses 2FA. Only run from the local console.")
    print("   Audit log will record this action.\n")
    response = input("   Type 'CONFIRM' to proceed: ").strip()
    return response == "CONFIRM"


def _reload_hashes() -> int:
    """Execute reload_hashes without 2FA (local console trust zone)."""
    from services.self_whitelist import reload_hashes

    results = reload_hashes()
    print(f"\n✅ Reloaded {len(results)} hash(es):")
    for path, status in results.items():
        print(f"   {path}: {status}")
    return 0


def _status() -> int:
    """Show current self-whitelist status."""
    from services.self_whitelist import _known_good_hashes, _sentinel_pid

    print(f"Sentinel PID: {_sentinel_pid}")
    print(f"Registered hashes: {len(_known_good_hashes)}")
    for path, sha in _known_good_hashes.items():
        print(f"  {path}: {sha[:16]}...")
    return 0


OPERATIONS = {
    "reload_hashes": _reload_hashes,
    "status": _status,
}


def main() -> int:
    if not _is_local_tty():
        print("ERROR: break_glass requires an interactive TTY (local console).", file=sys.stderr)
        print("Remote execution is denied — use the Web C2 with 2FA instead.", file=sys.stderr)
        return 1

    if not _is_admin():
        print("CRITICAL: Break-Glass protocol requires Administrator/root privileges. Access Denied.", file=sys.stderr)
        return 1

    if len(sys.argv) < 2 or sys.argv[1] not in OPERATIONS:
        print(f"Usage: {sys.argv[0]} <{'|'.join(OPERATIONS)}>", file=sys.stderr)
        return 1

    operation = sys.argv[1]

    # status doesn't need confirmation
    if operation == "status":
        return _status()

    if not _confirm(operation):
        print("Aborted.")
        return 1

    # Add sentinel root to path for imports
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    try:
        return OPERATIONS[operation]()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
