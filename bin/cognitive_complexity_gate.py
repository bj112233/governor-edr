#!/usr/bin/env python3
"""Cognitive Complexity gate — ratchet-protected.

Cognitive Complexity (SonarQube metric) measures how hard control flow is to
*understand*, weighting nesting depth — the exact failure mode of ReAct State
Machines where deep if/else chains cause attention collapse and tool-chain
breakage.  Unlike Cyclomatic Complexity (CC), splitting a function into two
does NOT reduce cognitive complexity if nesting is preserved; conversely a
flat dispatch table drops it sharply.

Ratchet protocol (mirrors file_length_gate / mypy baseline):
  - Baseline file: .cognitive_baseline.txt  (one violation per line:
    "<file>::<func> = <score>")
  - Gate FAILS only on NEW violations above threshold (regression guard).
  - Existing violations are tracked debt; refactor must shrink the baseline.
  - After a refactor reduces violations, regenerate the baseline so the new
    lower count becomes the floor.

Threshold: --max (default 15).  Functions at exactly the threshold pass;
functions above it are violations.  Threshold itself is ratcheted down over
time as debt is paid — never raised.

Usage:
    python bin/cognitive_complexity_gate.py            # gate (uses baseline)
    python bin/cognitive_complexity_gate.py --report   # full report, no gate
    python bin/cognitive_complexity_gate.py --regenerate  # rewrite baseline
"""

from __future__ import annotations

import argparse
import ast
import itertools
import sys
from pathlib import Path

# Force UTF-8 (see lint-gate.py rationale — emoji/Hebrew on Windows cp1255)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from cognitive_complexity.api import get_cognitive_complexity
from gate_helpers import print_header, print_result

_PROJECT_ROOT = Path(__file__).parent.parent.resolve()
_SERVICES_DIR = _PROJECT_ROOT / "services"
_SKILLS_DIR = _PROJECT_ROOT / "skills"
_BASELINE_PATH = _PROJECT_ROOT / ".cognitive_baseline.txt"
DEFAULT_MAX = 15


def _iter_python_files(root: Path):
    """Yield .py files under root, skipping __pycache__ and __init__ noise."""
    for p in root.rglob("*.py"):
        rel = p.relative_to(_PROJECT_ROOT).as_posix()
        if "__pycache__" in rel:
            continue
        if rel.endswith("__init__.py"):
            continue
        yield p


def _scan_file(path: Path) -> list[tuple[str, int]]:
    """Return [(qualified_name, cognitive_score), ...] for every func in file."""
    try:
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except (SyntaxError, UnicodeDecodeError):
        return []
    rel = path.relative_to(_PROJECT_ROOT).as_posix()
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                score = get_cognitive_complexity(node)
            except Exception:
                continue
            out.append((f"{rel}::{node.name}", score))
    return out


def scan_all(max_threshold: int) -> list[tuple[str, int]]:
    """Scan services/ + skills/ — return violations (score > threshold) sorted desc."""
    violations: list[tuple[str, int]] = []
    for f in itertools.chain(_iter_python_files(_SERVICES_DIR), _iter_python_files(_SKILLS_DIR)):
        for name, score in _scan_file(f):
            if score > max_threshold:
                violations.append((name, score))
    violations.sort(key=lambda kv: -kv[1])
    return violations


def _load_baseline() -> set[str]:
    """Return set of violation NAMES (strip ' = <score>' suffix)."""
    if not _BASELINE_PATH.exists():
        return set()
    names: set[str] = set()
    for line in _BASELINE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: "<file>::<func> = <score>" — keep only the name part
        if " = " in line:
            names.add(line.rsplit(" = ", 1)[0])
        else:
            names.add(line)
    return names


def _regenerate_baseline(violations: list[tuple[str, int]]) -> int:
    lines = [
        "# Cognitive Complexity baseline — ratchet, do NOT raise.",
        "# Regenerate after reducing violations: python bin/cognitive_complexity_gate.py --regenerate",
        "# Format: <file>::<func> = <score>",
    ]
    for name, score in violations:
        lines.append(f"{name} = {score}")
    _BASELINE_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(violations)


def run_gate(title: str, max_threshold: int) -> bool:
    print_header(title)
    violations = scan_all(max_threshold)
    baseline = _load_baseline()

    new_violations: list[tuple[str, int]] = []
    known_violations: list[tuple[str, int]] = []
    for name, score in violations:
        # Match by name (score may have changed — that's fine, name is the key)
        if name in baseline:
            known_violations.append((name, score))
        else:
            new_violations.append((name, score))

    print(
        f"  Threshold: >{max_threshold}  |  Total violations: {len(violations)}  "
        f"(known debt: {len(known_violations)}, NEW: {len(new_violations)})"
    )

    if new_violations:
        print("  [RATCHET FAIL] New cognitive complexity violations:")
        for name, score in new_violations[:20]:
            print(f"    {score:3d}  {name}")
        if len(new_violations) > 20:
            print(f"    ... and {len(new_violations) - 20} more")
        ok = False
    else:
        # Detect if a known violation's score got WORSE (regression)
        baseline_scores: dict[str, int] = {}
        if _BASELINE_PATH.exists():
            for line in _BASELINE_PATH.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or " = " not in line:
                    continue
                k, v = line.rsplit(" = ", 1)
                try:
                    baseline_scores[k] = int(v)
                except ValueError:
                    pass
        worsened = [
            (n, s, baseline_scores[n]) for n, s in known_violations if n in baseline_scores and s > baseline_scores[n]
        ]
        if worsened:
            print("  [RATCHET FAIL] Existing violations got WORSE:")
            for name, now, was in worsened[:20]:
                print(f"    {now:3d} (was {was:3d})  {name}")
            ok = False
        else:
            if len(violations) < len(baseline):
                print(
                    f"  Debt reduced: {len(baseline)} -> {len(violations)}  "
                    "(regenerate baseline: python bin/cognitive_complexity_gate.py --regenerate)"
                )
            ok = True

    print_result(title, ok)
    return ok


def run_report(max_threshold: int) -> int:
    print_header("Cognitive Complexity Report")
    violations = scan_all(max_threshold)
    print(f"  Functions with cognitive complexity > {max_threshold}: {len(violations)}")
    print(f"  {'Score':>5}  Function")
    print(f"  {'-----':>5}  {'-' * 60}")
    for name, score in violations:
        print(f"  {score:>5}  {name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Cognitive Complexity gate (ratchet).")
    ap.add_argument(
        "--max",
        type=int,
        default=DEFAULT_MAX,
        help=f"Threshold (default {DEFAULT_MAX}); functions above are violations.",
    )
    ap.add_argument("--report", action="store_true", help="Print full report and exit 0 (no gate).")
    ap.add_argument(
        "--regenerate", action="store_true", help="Rewrite .cognitive_baseline.txt from current violations."
    )
    args = ap.parse_args()

    if args.report:
        return run_report(args.max)
    if args.regenerate:
        violations = scan_all(args.max)
        n = _regenerate_baseline(violations)
        print(f"Baseline written: {n} violations recorded to {_BASELINE_PATH.name}")
        return 0
    ok = run_gate("Cognitive Complexity Gate (ratchet)", args.max)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
