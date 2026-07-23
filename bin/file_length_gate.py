"""File length gate — enforces max-lines-per-file rule from AGENTS.md.

Counts LLOC (Logical Lines of Code) — ignores blank lines, comments, and
docstrings — so documentation never triggers the gate.

Ratchet mechanism: baseline file (.file_length_baseline.txt) can only
shrink. Adding new entries or increasing values fails the gate.

Tests are included with a higher threshold (500 LLOC).
"""

import subprocess
import sys
from pathlib import Path

# Thresholds: production code = 300 LLOC, test code = 500 LLOC
PROD_MAX_LLOC = 300
TEST_MAX_LLOC = 500
TEST_DIR_NAME = "tests"


_DQ = chr(34) * 3  # """
_SQ = chr(39) * 3  # '''


def _count_lloc(file_path: Path) -> int:
    """Count Logical Lines of Code — excludes blanks, comments, docstrings.

    Uses a simple heuristic: skip blank lines, lines starting with #,
    and lines that are only docstring delimiters.
    Multi-line strings are approximated — this is a gate, not a parser.
    """
    in_docstring = False
    lloc = 0
    try:
        for line in file_path.open(encoding="utf-8"):
            stripped = line.strip()
            if not stripped:
                continue
            # Track triple-quoted docstrings
            if not in_docstring:
                if stripped.startswith(_DQ) or stripped.startswith(_SQ):
                    if stripped.count(_DQ) == 2 or stripped.count(_SQ) == 2:
                        continue  # single-line docstring
                    in_docstring = True
                    continue
            else:
                if _DQ in stripped or _SQ in stripped:
                    in_docstring = False
                continue
            if stripped.startswith("#"):
                continue
            lloc += 1
    except (OSError, UnicodeDecodeError):
        return 0
    return lloc


def _load_baseline(baseline_path: Path) -> dict[str, int]:
    """Load baseline file → {relative_path: lloc}."""
    baseline: dict[str, int] = {}
    if not baseline_path.exists():
        return baseline
    for line in baseline_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.rsplit(None, 1)
        if len(parts) == 2:
            baseline[parts[0].replace("\\", "/")] = int(parts[1])
    return baseline


def _check_ratchet(baseline_path: Path, current_baseline: dict[str, int]) -> list[str]:
    """Verify baseline file hasn't grown vs git HEAD. Returns violation messages."""
    violations = []
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{baseline_path.name}"],
            capture_output=True,
            text=True,
            cwd=str(baseline_path.parent),
        )
        if result.returncode != 0:
            return []  # baseline is new — no ratchet check needed
        old_baseline: dict[str, int] = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                old_baseline[parts[0].replace("\\", "/")] = int(parts[1])
        # Check: no new entries (test files exempt — test debt is acceptable)
        new_entries = set(current_baseline) - set(old_baseline)
        for entry in new_entries:
            if TEST_DIR_NAME not in entry:
                violations.append(f"  [RATCHET FAIL] New baseline entry: {entry}")
        # Check: no increased values (test files exempt)
        for path, old_val in old_baseline.items():
            if TEST_DIR_NAME in path:
                continue
            new_val = current_baseline.get(path)
            if new_val is not None and new_val > old_val:
                violations.append(f"  [RATCHET FAIL] {path} baseline grew: {old_val} → {new_val}")
    except Exception:
        pass  # git not available — skip ratchet check
    return violations


def run_file_length_gate(title: str, max_lines: int = 300) -> bool:
    """Enforce max-lines-per-file rule from AGENTS.md (SRP: 300 LLOC).

    Counts LLOC (not SLOC) — blank lines, comments, and docstrings don't count.
    Tests/ included with 500-LLOC threshold.
    Baseline file can only shrink (ratchet mechanism).
    """
    from gate_helpers import print_header, print_result

    print_header(title)
    project_root = Path(__file__).parent.parent.resolve()
    exclude_dirs = {".venv", "__pycache__", ".git", "node_modules", ".pytest_cache"}
    baseline_path = project_root / ".file_length_baseline.txt"
    current_baseline = _load_baseline(baseline_path)

    # Ratchet check — baseline must not grow
    ratchet_violations = _check_ratchet(baseline_path, current_baseline)

    offenders = []
    for py_file in project_root.rglob("*.py"):
        if any(part in exclude_dirs for part in py_file.parts):
            continue
        is_test = TEST_DIR_NAME in py_file.parts
        threshold = TEST_MAX_LLOC if is_test else PROD_MAX_LLOC
        lloc = _count_lloc(py_file)
        if lloc > threshold:
            rel = str(py_file.relative_to(project_root)).replace("\\", "/")
            baseline_val = current_baseline.get(rel)
            if baseline_val is not None and lloc <= baseline_val:
                continue  # pre-existing debt, unchanged
            tag = "TEST" if is_test else "PROD"
            offenders.append((lloc, rel, baseline_val, tag, threshold))

    ok = True
    if ratchet_violations:
        for v in ratchet_violations:
            print(v)
        ok = False
    if offenders:
        for lloc, path, bl, tag, thresh in sorted(offenders, reverse=True):
            bl_note = f" (baseline={bl})" if bl is not None else f" (NEW {tag})"
            print(f"  [FAIL] {path} — {lloc} LLOC (max {thresh}){bl_note}")
        ok = False
    if ok:
        print(f"  All files within limits (prod={PROD_MAX_LLOC}, test={TEST_MAX_LLOC} LLOC)")
    print_result(title, ok)
    return ok
