"""Verify that the committed requirements.txt is in sync with uv.lock.

`requirements.txt` is an auto-generated artifact exported from `uv.lock` via
`uv export --format requirements-txt --output requirements.txt`. It exists as a
fallback for environments without uv (portfolio users who clone and run
`pip install -r requirements.txt`).

Without this check, requirements.txt can drift from uv.lock and become a second
source of truth — defeating the purpose of the lockfile. The gate fails if the
exported output does not match the committed file.

Run via lint-gate, or directly:
    python bin/lock_sync_check.py
"""

import subprocess
import sys
import tempfile
from pathlib import Path

# Force UTF-8 on stdout/stderr so unicode in titles (e.g. ↔) doesn't crash on
# legacy Windows code pages (cp1255). Mirrors lint-gate.py's reconfiguration.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from gate_helpers import print_header, print_result


def run_gate(title: str) -> bool:
    """Fail if `uv export` output differs from the committed requirements.txt."""
    print_header(title)
    project_root = Path(__file__).parent.parent.resolve()
    req_file = project_root / "requirements.txt"

    if not req_file.is_file():
        print(f"  [FAIL] {req_file} not found — run `uv export --format "
              "requirements.txt --no-emit-project --output-file requirements.txt`",
              file=sys.stderr)
        print_result(title, False)
        return False

    # `uv` may not be on PATH in every environment; resolve via the venv's
    # tool directory first, then fall back to a bare `uv` lookup.
    uv_bin = project_root / ".venv" / "Scripts" / "uv.exe"
    uv_cmd: list[str]
    if uv_bin.is_file():
        uv_cmd = [str(uv_bin)]
    else:
        from shutil import which
        found = which("uv")
        if not found:
            print("  [FAIL] uv not found on PATH or in .venv/Scripts/ — "
                  "install uv or run via the project venv.", file=sys.stderr)
            print_result(title, False)
            return False
        uv_cmd = [found]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as tmp:
        tmp_path = Path(tmp.name)

    try:
        # Export ALL groups (runtime + dev) so the fallback requirements.txt
        # is a complete drop-in replacement for the original hand-maintained file.
        result = subprocess.run(
            [*uv_cmd, "export", "--format", "requirements-txt",
             "--no-emit-project", "--output-file", str(tmp_path)],
            capture_output=True, text=True, cwd=str(project_root),
        )
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            print_result(title, False)
            return False

        committed = req_file.read_text(encoding="utf-8").splitlines()
        exported = tmp_path.read_text(encoding="utf-8").splitlines()

        # uv embeds the exact `--output-file <path>` in the autogen header.
        # Normalize both to the canonical relative path so the comparison is
        # path-agnostic (the committed file uses `requirements.txt`).
        import re
        _norm = re.compile(r"--output-file\s+\S+")
        committed = [_norm.sub("--output-file requirements.txt", ln) for ln in committed]
        exported = [_norm.sub("--output-file requirements.txt", ln) for ln in exported]

        if committed == exported:
            print_result(title, True)
            return True

        # Show a compact diff for diagnosis.
        import difflib
        diff = list(difflib.unified_diff(
            committed, exported, fromfile="requirements.txt (committed)",
            tofile="requirements.txt (uv export)", lineterm="",
        ))
        print("  [FAIL] requirements.txt is out of sync with uv.lock.")
        print("  Re-generate with: uv export --format requirements.txt "
              "--no-emit-project --output-file requirements.txt")
        for line in diff[:40]:
            print(f"  {line}")
        if len(diff) > 40:
            print(f"  ... ({len(diff) - 40} more diff lines)")
        print_result(title, False)
        return False
    finally:
        tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(0 if run_gate("Lock Sync Check (uv.lock ↔ requirements.txt)") else 1)
