"""Firewall skill list command — parse and display SENTINEL_BLOCK_* rules.

Extracted from firewall_commands.py to reduce cmd_list D(25) complexity.
"""
from __future__ import annotations

import json

from firewall_backends import FirewallBackend
from firewall_state import _RULE_PREFIX


def _parse_powershell_json(out: str) -> str:
    """Parse PowerShell JSON output and format SENTINEL rules by IP."""
    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return f"❌ שגיאה בפרסור תוצאת PowerShell: {out[:200]}"

    sentinel_rules = [
        r for r in data
        if (r.get("DisplayName") or r.get("Name", "")).startswith(_RULE_PREFIX)
    ]
    if not sentinel_rules:
        return "📭 אין חסימות SENTINEL פעילות."

    by_ip: dict[str, list[str]] = {}
    for r in sentinel_rules:
        display = r.get("DisplayName") or r.get("Name", "")
        ip = display[len(_RULE_PREFIX):]
        direction = r.get("Direction", "?")
        by_ip.setdefault(ip, []).append(direction)

    lines = [f"🔥 חסימות SENTINEL פעילות ({len(by_ip)} IPs):", ""]
    for ip, dirs in sorted(by_ip.items()):
        lines.append(f"• {ip}  ({'+'.join(sorted(set(dirs)))})")
    return "\n".join(lines)


def _parse_netsh_text(out: str) -> str:
    """Parse netsh plain-text output and format SENTINEL rules by IP."""
    blocks = []
    current: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            current[k.strip().lower()] = v.strip()
    if current:
        blocks.append(current)

    sentinel_rules = [
        b for b in blocks if (b.get("rule name", "")).startswith(_RULE_PREFIX)
    ]
    if not sentinel_rules:
        return "📭 אין חסימות SENTINEL פעילות."

    by_ip: dict[str, list[dict]] = {}
    for r in sentinel_rules:
        raw = r["rule name"][len(_RULE_PREFIX):]
        ip = raw[3:] if raw.startswith("IN_") else raw
        by_ip.setdefault(ip, []).append(r)

    lines = [f"🔥 חסימות SENTINEL פעילות ({len(by_ip)} IPs):", ""]
    for ip, rules in sorted(by_ip.items()):
        dirs = sorted({r.get("direction", "?") for r in rules})
        lines.append(f"• {ip}  ({'+'.join(dirs)})")
    return "\n".join(lines)


def cmd_list(backend: FirewallBackend) -> str:
    """List all SENTINEL_BLOCK_* rules currently active."""
    rc, out, err = backend.list_rules()
    if rc != 0:
        return f"❌ שגיאה בקריאת חוקים: {err[:200]}"

    if out.strip().startswith("[") or out.strip().startswith("{"):
        return _parse_powershell_json(out)
    return _parse_netsh_text(out)
