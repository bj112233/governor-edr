"""Baseline management — save/load/diff persistence snapshots.

Baseline stored as JSON in state/persistence_baseline.json.
Diff returns only NEW or MODIFIED entries (not removed — those are reported separately).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_BASELINE_PATH = Path(__file__).resolve().parent.parent.parent.parent / "state" / "persistence_baseline.json"


def _entry_key(entry: dict[str, Any]) -> str:
    """Stable key for an entry (vector + location + name)."""
    return f"{entry.get('vector', '?')}|{entry.get('location', '?')}|{entry.get('name', '?')}"


def save_baseline(entries: list[dict[str, Any]]) -> str:
    """Save current entries as baseline. Returns status message."""
    _BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {entry.get("name", ""): entry for entry in entries}
    _BASELINE_PATH.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return f"✅ Baseline saved: {len(entries)} entries → {_BASELINE_PATH}"


def load_baseline() -> dict[str, dict[str, Any]]:
    """Load baseline from disk. Returns empty dict if not found."""
    if not _BASELINE_PATH.exists():
        return {}
    try:
        return json.loads(_BASELINE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def diff_against_baseline(current: list[dict[str, Any]]) -> dict[str, list]:
    """Compare current entries against baseline.

    Returns {"new": [...], "modified": [...], "removed": [...]}.
    """
    baseline = load_baseline()
    current_map = {entry.get("name", ""): entry for entry in current}

    new_entries: list[dict] = []
    modified: list[dict] = []
    removed: list[str] = []

    for name, entry in current_map.items():
        if name not in baseline:
            new_entries.append(entry)
        elif (
            baseline[name].get("command", "") != entry.get("command", "")
            and entry.get("vector") != "scheduled_task"
        ):
            # Skip command comparison for scheduled_tasks — their "command" field
            # is actually "Next Run Time" (volatile), not a real command.
            modified.append({
                "name": name,
                "old_command": baseline[name].get("command", ""),
                "new_command": entry.get("command", ""),
                "mitre": entry.get("mitre", ""),
                "mitre_name": entry.get("mitre_name", ""),
            })

    for name in baseline:
        if name not in current_map:
            removed.append(name)

    return {"new": new_entries, "modified": modified, "removed": removed}
