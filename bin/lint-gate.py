#!/usr/bin/env python3
"""Local lint gate — run before commit.

Usage:
    python bin/lint-gate.py

Returns:
    0 if all gates pass
    1 if any gate fails (blocks commit)
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Force UTF-8 on stdout/stderr so emoji in gate output don't crash on legacy
# Windows code pages (e.g. cp1255 → OSError [Errno 22] Invalid argument).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

# Ensure bin/ is importable for sibling modules
_BIN_DIR = str(Path(__file__).parent.resolve())
if _BIN_DIR not in sys.path:
    sys.path.insert(0, _BIN_DIR)

from gate_helpers import print_header, print_result, run_radon


def run_xenon(title: str) -> bool:
    print_header(title)
    # Thresholds: max-absolute=D (blocks at E/F fail), max-average=A, max-modules=C
    # Ratchet: only tighten, never loosen. See .xenon.yml for documentation.
    # Upgraded B→A after cognitive complexity refactor (commit eef99c8).
    cmd = [
        sys.executable,
        "-m",
        "xenon",
        "services/",
        "--max-absolute",
        "D",
        "--max-average",
        "A",
        "--max-modules",
        "C",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    ok = result.returncode == 0
    print_result(title, ok)
    return ok


def run_import_linter(title: str) -> bool:
    print_header(title)
    try:
        from importlinter.cli import lint_imports

        rc = lint_imports(config_filename="pyproject.toml")
        ok = rc == 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        ok = False
    print_result(title, ok)
    return ok


def _build_vulture_whitelist(tmp_dir: Path) -> Path:
    """Generate whitelist from tools_registry.REGISTRY to prevent false-positives
    on handlers consumed dynamically via LLM_TOOL_MAP / _TOOL_REGISTRY."""
    import importlib.util

    project_root = Path(__file__).parent.parent.resolve()
    registry_path = project_root / "services" / "tools_registry.py"

    # Ensure services/ is importable for side-effect imports inside registry
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    spec = importlib.util.spec_from_file_location("tools_registry", registry_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load tools_registry.py spec")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    whitelist = tmp_dir / ".vulture_whitelist.py"
    lines = ["# Auto-generated from tools_registry.REGISTRY — do NOT edit.\n"]
    for tool in mod.REGISTRY.values():
        handler = tool.handler
        if handler is None:
            continue
        # Reference format: module_name.function_name
        mod_name = getattr(handler, "__module__", "")
        func_name = getattr(handler, "__name__", "")
        if not mod_name or not func_name or "<" in func_name:
            # Skip lambdas and unnamed callables — vulture can't reference them
            continue
        lines.append(f"{mod_name}.{func_name}  # vulture: ignore\n")

    whitelist.write_text("".join(lines), encoding="utf-8")
    return whitelist


def run_vulture(title: str) -> bool:
    print_header(title)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        try:
            whitelist = _build_vulture_whitelist(tmp_path)
        except Exception as exc:
            print(f"Error building whitelist: {exc}", file=sys.stderr)
            status = "FAIL"
            print(f"  [{status}] {title}")
            return False

        cmd = [
            sys.executable,
            "-m",
            "vulture",
            ".",
            str(whitelist),
            "--min-confidence",
            "80",
            "--exclude",
            ".venv,.git,node_modules,__pycache__,.pytest_cache",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    ok = result.returncode == 0
    print_result(title, ok)
    return ok


def run_ruff(title: str) -> bool:
    print_header(title)
    cmd = [sys.executable, "-m", "ruff", "check", "services/", "tests/", "main.py", "config.py", "logging_config.py"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    ok = result.returncode == 0
    print_result(title, ok)
    return ok


def run_mypy(title: str) -> bool:
    """Gate on mypy — zero errors enforced project-wide.

    Historical debt was fully eliminated; the baseline ratchet is retired.
    Any type error now blocks the commit immediately.
    """
    print_header(title)
    cmd = [sys.executable, "-m", "mypy", "--no-error-summary"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    errors = [line for line in result.stdout.splitlines() if ": error:" in line]
    if errors:
        print(f"  {len(errors)} type errors:")
        for err in errors:
            print(f"    {err}")
        ok = False
    else:
        print("  0 type errors")
        ok = True

    print_result(title, ok)
    return ok


def run_bandit(title: str) -> bool:
    """Gate on Medium+ severity findings (Low = informational)."""
    print_header(title)
    import json as _json

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        tmp = f.name
    try:
        cmd = [sys.executable, "-m", "bandit", "-r", "services/", "-c", ".bandit.toml", "-f", "json", "-o", tmp]
        result = subprocess.run(cmd, capture_output=True, text=True)
        with open(tmp) as f:
            data = _json.load(f)
        medium_high = [r for r in data.get("results", []) if r.get("issue_severity") in ("MEDIUM", "HIGH")]
        low_count = len([r for r in data.get("results", []) if r.get("issue_severity") == "LOW"])
        if medium_high:
            for r in medium_high:
                loc = f"{r['filename']}:{r['line_number']}"
                print(f"  {r['test_id']} [{r['issue_severity']}] {loc}: {r['issue_text']}")
        print(f"  Medium/High: {len(medium_high)}, Low (info): {low_count}")
        ok = len(medium_high) == 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        ok = False
    finally:
        os.unlink(tmp)
    print_result(title, ok)
    return ok


def run_lock_sync_check(title: str) -> bool:
    """Verify requirements.txt (auto-generated artifact) matches uv.lock."""
    from lock_sync_check import run_gate as _run

    return _run(title)


def run_pip_audit(title: str) -> bool:
    """Report dependency vulnerabilities and block commit on known CVEs.

    Dependencies were upgraded to clear the previous vulnerability set; the gate
    now enforces a clean pip-audit result. If new vulnerabilities appear, fix
    or pin them before committing.
    """
    print_header(title)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    cmd = [sys.executable, "-m", "pip_audit", "--strict"]
    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    vuln_count = result.stdout.count("CVE-") + result.stdout.count("GHSA-") + result.stdout.count("PYSEC-")
    block = True  # Block commits on known dependency vulnerabilities
    if vuln_count > 0:
        print(f"  [WARN] {vuln_count} vulnerabilities found -- upgrade affected packages")
    ok = True if not block else result.returncode == 0
    status = "PASS (warning)" if ok and vuln_count > 0 else ("PASS" if ok else "FAIL")
    print(f"  [{status}] {title}")
    return ok


def run_gitleaks(title: str) -> bool:
    """Secret + PII scan via gitleaks (--no-git on working tree).

    Runs .gitleaks.toml (generic key-format rules, tracked) and, if present,
    .gitleaks-local.toml (personal PII rules, gitignored). The local file
    contains real MAC/chat_id/names and must never be committed.
    Blocks commit on any finding from either config.
    """
    print_header(title)
    project_root = Path(__file__).parent.parent.resolve()
    public_config = project_root / ".gitleaks.toml"
    local_config = project_root / ".gitleaks-local.toml"

    if not public_config.exists():
        print(f"  [FAIL] .gitleaks.toml not found at {public_config}", file=sys.stderr)
        print_result(title, False)
        return False

    ok = True
    for label, cfg in [("public", public_config), ("local", local_config)]:
        if not cfg.exists():
            if label == "local":
                print("  [INFO] .gitleaks-local.toml not found — skipping PII rules (local-only file)")
            continue
        cmd = ["gitleaks", "detect", "--no-git", "--source", ".", "--config", str(cfg)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            print(result.stdout)
        passed = result.returncode == 0
        if not passed:
            ok = False
            if result.stderr:
                for line in result.stderr.splitlines():
                    if "Finding:" in line or "Secret:" in line or "RuleID:" in line or "File:" in line:
                        print(f"  [{label}] {line.strip()}")
        print(f"  [{label}] {'PASS' if passed else 'FAIL'}")

    print_result(title, ok)
    return ok


def run_file_length_gate(title: str, max_lines: int = 300) -> bool:
    """Delegate to file_length_gate module (kept lint-gate.py under 300 lines)."""
    from file_length_gate import run_file_length_gate as _run

    return _run(title, max_lines)


def run_cognitive_complexity_gate(title: str) -> bool:
    """Cognitive Complexity gate — ratchet-protected via .cognitive_baseline.txt.

    Measures nesting-driven understandability (SonarQube metric). Critical for
    ReAct State Machines where deep if/else chains cause attention collapse and
    tool-chain breakage — a failure mode Cyclomatic Complexity cannot detect.
    Gate FAILS only on NEW violations or worsened existing ones (regression guard).
    """
    from cognitive_complexity_gate import run_gate as _run

    return _run(title, max_threshold=15)


def run_coverage_gate(title: str) -> bool:
    """Test coverage gate — ratchet-protected via .coverage_baseline.txt.

    Dual-layer: total % floor + per-file missing lines regression guard.
    Gate FAILS if total coverage drops or any file's missing lines increase.
    New files with missing lines count as new debt (must add tests).
    """
    from coverage_gate import run_gate as _run

    return _run(title)


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Local lint gate — run before commit.")
    ap.add_argument("--fast", action="store_true", help="Skip coverage gate (for pre-commit hook speed)")
    args = ap.parse_args()

    project_root = Path(__file__).parent.parent.resolve()
    if not (project_root / "services").is_dir():
        print(
            f"[FATAL] services/ not found at {project_root}. "
            "Run this script from the repo root (python bin/lint-gate.py).",
            file=sys.stderr,
        )
        return 1
    os.chdir(project_root)

    run_radon("Cyclomatic Complexity Report (radon)")
    results = [
        run_xenon("Cyclomatic Complexity Gate (xenon)"),
        run_import_linter("Architectural Coupling (import-linter)"),
        run_vulture("Dead Code Detection (vulture)"),
        run_ruff("Lint + Format (ruff)"),
        run_mypy("Type Check (mypy, zero-enforced)"),
        run_bandit("Security SAST (bandit)"),
        run_gitleaks("Secret + PII Scan (gitleaks)"),
        run_file_length_gate("File Length Gate (max 300 lines)"),
        run_cognitive_complexity_gate("Cognitive Complexity Gate (ratchet, max 15)"),
        run_coverage_gate("Coverage Gate (ratchet)") if not args.fast else True,
        run_pip_audit("Dependency Audit (pip-audit)"),
        run_lock_sync_check("Lock Sync (uv.lock ↔ requirements.txt)"),
    ]

    print(f"\n{'=' * 60}")
    if all(results):
        print("  ALL GATES PASSED — commit allowed")
        print(f"{'=' * 60}\n")
        return 0
    else:
        print("  SOME GATES FAILED — fix before committing")
        print(f"{'=' * 60}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
