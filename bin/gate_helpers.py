"""Shared helpers for lint-gate — print headers and informational reports.

Extracted from lint-gate.py to keep it under 300 lines.
"""

import subprocess
import sys


def print_header(title: str) -> None:
    """Print a standardized section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_result(title: str, ok: bool) -> None:
    """Print PASS/FAIL status for a gate."""
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {title}")


def run_radon(title: str) -> None:
    """Informational cyclomatic-complexity report (does not gate)."""
    print_header(title)
    cmd = [sys.executable, "-m", "radon", "cc", "services/", "--average", "--min=D", "--show-closures"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    print(f"  [INFO] {title} — report only")
