#!/usr/bin/env python3
"""Persistence Hunter — Windows persistence mechanism scanner.

Scans all persistence vectors, filters Microsoft-signed noise,
supports baseline/diff for change detection, tags MITRE ATT&CK.

Commands:
  scan      [--include-ms]  — full scan (non-MS by default)
  baseline                  — save current state as known-good baseline
  diff      [--include-ms]  — show only changes vs baseline

Vectors: Registry Run/RunOnce (T1547.001), Startup folders (T1547.004),
         Scheduled Tasks (T1053.005), WMI Event Subscriptions (T1546.003).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any

from _baseline import diff_against_baseline, load_baseline, save_baseline
from _collectors import collect_all
from _ms_filter import filter_entries

_MAX_DISPLAY = 40  # cap per-scan display to protect 16K token budget


def _format_entries(entries: list[dict[str, Any]], title: str) -> list[str]:
    """Format entries as readable lines grouped by vector."""
    lines = [f"=== {title} ({len(entries)} entries) ==="]
    if not entries:
        lines.append("  (none — clean!)")
        return lines

    # Group by vector
    by_vector: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        by_vector.setdefault(e["vector"], []).append(e)

    for vector, items in by_vector.items():
        lines.append(f"\n**{vector.upper()}** ({len(items)}):")
        for item in items[:_MAX_DISPLAY]:
            lines.append(f"  [{item['mitre']}] {item['name']}")
            lines.append(f"    → {item['command'][:120]}")
        if len(items) > _MAX_DISPLAY:
            lines.append(f"  ... and {len(items) - _MAX_DISPLAY} more")
    return lines


async def cmd_scan(include_ms: bool) -> str:
    """Full scan — all persistence vectors, optionally including MS-signed."""
    entries = await collect_all()
    filtered = filter_entries(entries, include_ms=include_ms)
    lines = _format_entries(filtered, "Persistence Scan")
    if not include_ms:
        ms_count = len(entries) - len(filtered)
        lines.append(f"\n({ms_count} Microsoft-signed entries hidden — use --include-ms to show)")
    return "\n".join(lines)


async def cmd_baseline() -> str:
    """Save current state as baseline."""
    entries = await collect_all()
    filtered = filter_entries(entries, include_ms=False)
    return save_baseline(filtered)


async def cmd_diff(include_ms: bool) -> str:
    """Show changes vs baseline."""
    entries = await collect_all()
    filtered = filter_entries(entries, include_ms=include_ms)
    diff = diff_against_baseline(filtered)

    lines = ["=== Persistence Diff (vs baseline) ==="]

    if diff["new"]:
        lines.append(f"\n**NEW entries ({len(diff['new'])}):**")
        for entry in diff["new"]:
            lines.append(f"  + [{entry['mitre']}] {entry['name']}")
            lines.append(f"    → {entry.get('command', '')[:120]}")

    if diff["modified"]:
        lines.append(f"\n**MODIFIED entries ({len(diff['modified'])}):**")
        for mod in diff["modified"]:
            lines.append(f"  ~ [{mod['mitre']}] {mod['name']}")
            lines.append(f"    old: {mod['old_command'][:100]}")
            lines.append(f"    new: {mod['new_command'][:100]}")

    if diff["removed"]:
        lines.append(f"\n**REMOVED entries ({len(diff['removed'])}):**")
        for name in diff["removed"]:
            lines.append(f"  - {name}")

    if not diff["new"] and not diff["modified"] and not diff["removed"]:
        lines.append("\n  ✅ No changes detected — system matches baseline.")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Persistence Hunter — Windows persistence scanner")
    parser.add_argument("command", choices=["scan", "baseline", "diff"], help="Operation mode")
    parser.add_argument("--include-ms", action="store_true", help="Include Microsoft-signed entries (default: filtered)")
    args = parser.parse_args()

    try:
        if args.command == "scan":
            print(asyncio.run(cmd_scan(args.include_ms)))
        elif args.command == "baseline":
            print(asyncio.run(cmd_baseline()))
        elif args.command == "diff":
            print(asyncio.run(cmd_diff(args.include_ms)))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"❌ Scan error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
