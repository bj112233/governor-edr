#!/usr/bin/env python3
"""Coverage gate — ratchet-protected (function-level, security-focused).

Replaces the old per-file missing-lines gate with a function-level gate
targeted at security-critical functions. Rationale (lessons.md L4):
file-level 95% on multi-purpose files forces testing irrelevant code;
function-level coverage on security functions is the right granularity.

Two layers of protection:
  1. Total coverage % — hard floor.  FAIL if total drops below baseline.
  2. Security-function missing lines — granular ratchet.  FAIL if any
     security function's missing lines increased (regression).  New
     security functions with missing lines count as new debt.

Reporting layer (non-blocking):
  - Lists security functions below the 95% target (INFO, for tracking).
  - The 95% target is a goal, not an immediate gate — the gate only
    blocks regressions, forcing coverage to ratchet up over time.

Security-function detection is automatic (AST scan) — no manual list.
A function is security-critical if its name matches a security pattern
(kill_*, block_*, terminate_*, verify_challenge, _audit_*, etc.) OR its
body calls a security-specific operation (psutil kill/terminate, netsh,
set_pending, compare_digest, initiate_challenge, etc.).

Ratchet protocol (mirrors cognitive_complexity_gate / mypy baseline):
  - Baseline file: .coverage_baseline.txt
    Format:
      # Coverage baseline — ratchet, do NOT lower.
      # Total: 62.12%
      # Security functions tracked: 49
      services/foo.py::block_ip = 7
      services/two_factor.py::verify_challenge = 8
  - Gate FAILS only on regressions (lower total or more missing lines).
  - After tests are added, regenerate the baseline to lock in improvement.
  - Threshold (total %) is ratcheted UP over time — never lowered.

Usage:
    python bin/coverage_gate.py              # gate (uses baseline)
    python bin/coverage_gate.py --regenerate # rewrite baseline from coverage.json
    python bin/coverage_gate.py --fresh      # force re-run pytest, then gate
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
from pathlib import Path

# Force UTF-8 (see lint-gate.py rationale — emoji/Hebrew on Windows cp1255)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from gate_helpers import print_header, print_result

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
_BASELINE_PATH = _PROJECT_ROOT / ".coverage_baseline.txt"
_COVERAGE_JSON = _PROJECT_ROOT / "coverage.json"
_TOLERANCE = 0.1  # float % tolerance to avoid noise from rounding
_SECURITY_TARGET_PCT = 95.0  # goal for security functions (non-blocking)


# ── Security-function detection (AST-based, automatic) ──────────────────

# A function is security-critical if its name matches these patterns OR
# its body calls one of these operations (last attribute/name segment).
_DANGER_NAME_PREFIXES = ("kill_", "block_", "unblock_", "terminate_", "execute_kill", "execute_block")
_DANGER_NAME_EXACT = {
    "block_ip",
    "unblock_ip",
    "terminate_process",
    "kill_process",
    "block_ip_in_firewall",
    "kill_process_by_name",
    "dispatch_command",
    "execute_kill_process",
    "initiate_challenge",
    "verify_challenge",
    "_check_lockout",
    "_audit_entity_claims",
    "_audit_tool_claims",
    "_audit_ip_claims",
    "_check_entity_audit",
    "_detect_speculation",
    "_apply_speculation_guard",
    "_compute_allowed_tools",
    "_check_degraded_mode",
    "client_ip_allowed",
    "check_basic_auth",
    "_check_c2_rate_limit",
    "_handle_auto_block",
    "_handle_auto_kill",
    "_is_degraded_mode",
    "_execute_remediation_action",
    "approve_pending_action_tool",
    "_verify_mcp_auth",
}
# Last-segment call names that mark a function as security-critical.
# Narrow set — generic subprocess.run removed (GPU/WMI/skills use it).
_DANGER_CALLS = {
    "terminate",
    "kill",
    "set_pending",
    "queue_action",
    "queue_kill_for_ttp",
    "block_ip",
    "unblock_ip",
    "block_ip_in_firewall",
    "netsh",
    "advfirewall",
    "compare_digest",
    "token_hex",
    "randbelow",
    "is_degraded",
    "initiate_challenge",
    "verify_challenge",
    "_audit_entity_claims",
    "_audit_tool_claims",
    "_check_entity_audit",
    "_detect_speculation",
}


def _is_security_func(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function name matches a security pattern OR its body
    calls a security-specific operation (last segment match, precise)."""
    name = func.name
    if name in _DANGER_NAME_EXACT:
        return True
    if any(name.startswith(p) for p in _DANGER_NAME_PREFIXES):
        return True
    for node in ast.walk(func):
        if isinstance(node, ast.Call):
            f = node.func
            call_name = ""
            if isinstance(f, ast.Name):
                call_name = f.id
            elif isinstance(f, ast.Attribute):
                call_name = f.attr  # last segment only — precise
            if call_name in _DANGER_CALLS:
                return True
    return False


def _detect_security_functions() -> dict[str, int]:
    """AST-scan services/ for security-critical functions.

    Returns { "services/path.py::func_name": start_line }.
    """
    found: dict[str, int] = {}
    services_root = _PROJECT_ROOT / "services"
    for py in services_root.rglob("*.py"):
        try:
            tree = ast.parse(py.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _is_security_func(node):
                    key = f"{py.relative_to(_PROJECT_ROOT).as_posix()}::{node.name}"
                    found[key] = node.lineno
    return found


# ── Coverage data extraction ────────────────────────────────────────────


def _run_pytest_cov(*, force: bool = False) -> dict:
    """Run pytest with coverage, return parsed coverage.json data.

    Caching: if coverage.json exists and is <10 min old, reuse it.
    This avoids re-running pytest (100s+) on every pre-commit hook invocation.
    Use force=True or `--fresh` to bypass cache.
    """
    import time

    if not force and _COVERAGE_JSON.exists():
        age = time.time() - _COVERAGE_JSON.stat().st_mtime
        if age < 600:  # 10 minutes
            with open(_COVERAGE_JSON, encoding="utf-8") as f:
                return json.load(f)

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "--cov=services",
        "--cov-report=json:coverage.json",
        "--cov-report=",
        "-q",
        "--tb=no",
        "-p",
        "no:warnings",
    ]
    subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(_PROJECT_ROOT),
    )
    if not _COVERAGE_JSON.exists():
        print("  [FATAL] coverage.json not produced — pytest may have crashed.", file=sys.stderr)
        return {}
    with open(_COVERAGE_JSON, encoding="utf-8") as f:
        return json.load(f)


def _extract_total(data: dict) -> float:
    """Extract total coverage percentage from coverage.json."""
    return data.get("totals", {}).get("percent_covered", 0.0)


def _extract_security_func_missing(data: dict, security_funcs: dict[str, int]) -> dict[str, int]:
    """Extract per-security-function missing line counts from coverage.json.

    security_funcs: { "services/path.py::func_name": start_line } from AST scan.
    Returns { "services/path.py::func_name": missing_lines }.
    """
    out: dict[str, int] = {}
    for key in security_funcs:
        file_rel, func_name = key.rsplit("::", 1)
        # coverage.json uses OS-native separators (backslash on Windows)
        file_key = file_rel.replace("/", "\\")
        file_data = data.get("files", {}).get(file_key)
        if not file_data:
            out[key] = 0  # file not in coverage data — treat as 0 missing (not tracked)
            continue
        funcs = file_data.get("functions", {})
        # coverage.py function names: "ClassName.method" or "func_name"
        # match by exact name OR by suffix (handles nested/qualified names)
        match = funcs.get(func_name)
        if match is None:
            # try qualified: last segment after "." (e.g. block_ip._add_rule)
            for cov_name, cov_data in funcs.items():
                if cov_name.split(".")[-1] == func_name or cov_name == func_name:
                    match = cov_data
                    break
        if match:
            out[key] = match.get("summary", {}).get("missing_lines", 0)
        else:
            out[key] = 0  # function not found in coverage — fully covered or inlined
    return out


def _load_baseline() -> tuple[float, dict[str, int]]:
    """Return (total_pct, {security_func: missing_lines}) from baseline file."""
    if not _BASELINE_PATH.exists():
        return 0.0, {}
    total = 0.0
    missing: dict[str, int] = {}
    for line in _BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "Total:" in stripped:
            try:
                total = float(stripped.split("Total:", 1)[1].strip().rstrip("%"))
            except ValueError:
                pass
            continue
        if stripped.startswith("#"):
            continue
        if "=" in stripped:
            name, val = stripped.rsplit("=", 1)
            try:
                missing[name.strip()] = int(val.strip())
            except ValueError:
                pass
    return total, missing


def _regenerate_baseline(*, force: bool = False) -> int:
    """Write .coverage_baseline.txt from coverage.json.

    By default reuses a cached coverage.json (<10 min old) — the lint-gate
    already produces one, so re-running the full suite is wasteful and can
    hang on slow CI. Pass force=True (via --fresh) to force a pytest re-run.
    """
    data = _run_pytest_cov(force=force)
    if not data:
        print("ERROR: No coverage data — cannot regenerate baseline.", file=sys.stderr)
        return 1
    total = _extract_total(data)
    security_funcs = _detect_security_functions()
    sec_missing = _extract_security_func_missing(data, security_funcs)
    lines = [
        "# Coverage baseline — ratchet, do NOT lower.",
        "# Regenerate after adding tests: python bin/coverage_gate.py --regenerate",
        f"Total: {total:.2f}%",
        f"# Security functions tracked: {len(sec_missing)}",
    ]
    for name in sorted(sec_missing):
        lines.append(f"{name} = {sec_missing[name]}")
    _BASELINE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    below = sum(1 for m in sec_missing.values() if m > 0)
    print(f"Baseline written: {total:.2f}% total, {len(sec_missing)} security functions tracked ({below} below 100%)")
    return 0


def run_gate(title: str, *, force: bool = False) -> bool:
    """Coverage gate — FAIL on regression (lower total or more missing lines
    in security functions).

    Graceful skip: if coverage.json doesn't exist AND pytest can't produce it
    (e.g. during pre-commit stash), print warning and PASS — don't block commit.
    Developer should run `pytest --cov` manually before committing.
    """
    print_header(title)
    data = _run_pytest_cov(force=force)
    if not data:
        print("  [WARN] No coverage data — run 'pytest --cov=services' before committing.")
        print("  [PASS] (skipped — no coverage.json)")
        print_result(title, True)
        return True

    current_total = _extract_total(data)
    security_funcs = _detect_security_functions()
    current_missing = _extract_security_func_missing(data, security_funcs)
    baseline_total, baseline_missing = _load_baseline()

    # Layer 1: Total coverage floor
    if baseline_total == 0.0 and not baseline_missing:
        print("  No baseline found — run with --regenerate first.")
        print_result(title, False)
        return False

    total_ok = current_total >= baseline_total - _TOLERANCE
    print(f"  Total: {current_total:.2f}% (baseline: {baseline_total:.2f}%)  {'✓' if total_ok else '✗ DROP'}")

    # Layer 2: Security-function missing lines regression
    regressions: list[tuple[str, int, int]] = []
    new_funcs: list[tuple[str, int]] = []
    improvements: list[tuple[str, int, int]] = []

    for name, miss in current_missing.items():
        if name in baseline_missing:
            base_miss = baseline_missing[name]
            if miss > base_miss:
                regressions.append((name, miss, base_miss))
            elif miss < base_miss:
                improvements.append((name, miss, base_miss))
        else:
            # New security function with missing lines = new debt
            if miss > 0:
                new_funcs.append((name, miss))

    # Functions removed from baseline = fully covered or deleted (improvement)
    removed = [n for n in baseline_missing if n not in current_missing and n != ""]

    if regressions:
        print(f"  [RATCHET FAIL] {len(regressions)} security functions with MORE missing lines:")
        for name, now, was in regressions[:10]:
            print(f"    {now:4d} (was {was:4d})  {name}")
        if len(regressions) > 10:
            print(f"    ... and {len(regressions) - 10} more")

    if new_funcs:
        print(f"  [RATCHET FAIL] {len(new_funcs)} new security functions with missing lines:")
        for name, miss in new_funcs[:10]:
            print(f"    {miss:4d}  {name}")
        if len(new_funcs) > 10:
            print(f"    ... and {len(new_funcs) - 10} more")

    if not total_ok:
        print(f"  [RATCHET FAIL] Total coverage dropped by {baseline_total - current_total:.2f}%")

    ok = total_ok and not regressions and not new_funcs

    if ok:
        if improvements or removed:
            total_improved = len(improvements) + len(removed)
            print(
                f"  Coverage improved: {total_improved} security functions better "
                f"({len(improvements)} reduced, {len(removed)} cleared)  "
                "(regenerate: python bin/coverage_gate.py --regenerate)"
            )
        print(f"  Security functions tracked: {len(current_missing)} | Missing: {sum(current_missing.values())}")

    # Reporting layer (non-blocking): security functions below 95% target
    below_target: list[tuple[str, float, int, int]] = []
    for name, miss in current_missing.items():
        file_rel, func_name = name.rsplit("::", 1)
        file_key = file_rel.replace("/", "\\")
        file_data = data.get("files", {}).get(file_key)
        if not file_data:
            continue
        funcs = file_data.get("functions", {})
        match = funcs.get(func_name)
        if match is None:
            for cov_name, cov_data in funcs.items():
                if cov_name.split(".")[-1] == func_name or cov_name == func_name:
                    match = cov_data
                    break
        if match:
            s = match.get("summary", {})
            pct = s.get("percent_covered", 100.0)
            stmts = s.get("num_statements", 0)
            if pct < _SECURITY_TARGET_PCT and stmts > 0:
                below_target.append((name, pct, miss, stmts))

    if below_target:
        print(
            f"  [INFO] {len(below_target)} security functions below {_SECURITY_TARGET_PCT:.0f}% target (goal, not gate):"
        )
        for name, pct, miss, stmts in sorted(below_target, key=lambda x: x[1])[:10]:
            print(f"    {pct:5.1f}%  miss={miss:3d}/{stmts:<3d}  {name}")
        if len(below_target) > 10:
            print(f"    ... and {len(below_target) - 10} more")

    print_result(title, ok)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser(description="Coverage gate (ratchet-protected, security-function-level).")
    ap.add_argument("--regenerate", action="store_true", help="Rewrite .coverage_baseline.txt from coverage.json")
    ap.add_argument("--fresh", action="store_true", help="Force re-run pytest (ignore cached coverage.json)")
    args = ap.parse_args()

    if args.regenerate:
        return _regenerate_baseline(force=args.fresh)
    ok = run_gate("Coverage Gate (ratchet)", force=args.fresh)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
