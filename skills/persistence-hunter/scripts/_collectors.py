"""Persistence collectors — calls Windows commands directly (subprocess isolation).

Collects from ALL persistence vectors:
  - Registry Run/RunOnce keys (HKLM + HKCU) — T1547.001
  - Startup folders (%APPDATA% + %ProgramData%) — T1547.004
  - Scheduled Tasks — T1053.005
  - WMI Event Subscriptions — T1546.003

Returns structured entries (list[dict]) for baseline/diff operations.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from _mitre_tags import MITRE_TAGS

_REG_RUN_KEYS = [
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run", "T1547.001"),
    (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", "T1547.001"),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", "T1547.001"),
    (r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", "T1547.001"),
]

_STARTUP_FOLDERS = [
    (os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"), "User Startup", "T1547.004"),
    (os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"), "AllUsers Startup", "T1547.004"),
]


async def _run_subprocess(cmd: list[str], timeout: int = 10) -> str | None:
    """Run subprocess, return decoded stdout or None on timeout/error."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return None
        return stdout_b.decode("utf-8", errors="replace").strip()
    except (OSError, FileNotFoundError):
        return None


def _parse_reg_output(output: str) -> list[tuple[str, str]]:
    """Parse `reg query` output into (name, value) pairs."""
    entries: list[tuple[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("HKEY_") or "REG_" not in line:
            continue
        # Format: "    Name    REG_SZ    C:\path\to\program.exe"
        parts = line.split("REG_SZ", 1)
        if len(parts) == 2:
            name = parts[0].strip()
            value = parts[1].strip()
            if name and value:
                entries.append((name, value))
    return entries


async def collect_registry_entries() -> list[dict[str, Any]]:
    """Collect Registry Run/RunOnce entries from all 4 key locations."""
    entries: list[dict[str, Any]] = []
    for key_path, location, technique in _REG_RUN_KEYS:
        output = await _run_subprocess(["reg", "query", key_path], timeout=10)
        if not output:
            continue
        for name, value in _parse_reg_output(output):
            entries.append({
                "vector": "registry",
                "location": location,
                "name": name,
                "command": value,
                "mitre": technique,
                "mitre_name": MITRE_TAGS.get(technique, "Unknown"),
            })
    return entries


async def collect_startup_folder_entries() -> list[dict[str, Any]]:
    """Collect entries from Startup folders (shortcuts + executables)."""
    entries: list[dict[str, Any]] = []
    for folder, location, technique in _STARTUP_FOLDERS:
        if not os.path.isdir(folder):
            continue
        try:
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                if os.path.isfile(item_path):
                    entries.append({
                        "vector": "startup_folder",
                        "location": location,
                        "name": item,
                        "command": item_path,
                        "mitre": technique,
                        "mitre_name": MITRE_TAGS.get(technique, "Unknown"),
                    })
        except (PermissionError, OSError):
            continue
    return entries


async def collect_scheduled_tasks() -> list[dict[str, Any]]:
    """Collect scheduled tasks (non-Microsoft only is filtered later)."""
    entries: list[dict[str, Any]] = []
    output = await _run_subprocess(["schtasks", "/query", "/fo", "CSV", "/nh"], timeout=20)
    if not output:
        return entries
    for line in output.splitlines()[1:]:  # skip header
        parts = _parse_csv_line(line)
        if len(parts) < 2:
            continue
        task_name = parts[0].strip('"')
        if not task_name or task_name == "TaskName":
            continue
        entries.append({
            "vector": "scheduled_task",
            "location": "Scheduled Tasks",
            "name": task_name,
            "command": parts[1].strip('"') if len(parts) > 1 else "",
            "mitre": "T1053.005",
            "mitre_name": MITRE_TAGS.get("T1053.005", "Unknown"),
        })
    return entries


def _parse_csv_line(line: str) -> list[str]:
    """Simple CSV parser for schtasks output (handles quoted fields)."""
    result: list[str] = []
    current: list[str] = []
    in_quotes = False
    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            result.append("".join(current))
            current = []
        else:
            current.append(char)
    result.append("".join(current))
    return result


async def collect_wmi_subscriptions() -> list[dict[str, Any]]:
    """Collect WMI Event Subscriptions (T1546.003) via PowerShell."""
    ps_cmd = (
        "Get-WmiObject -Namespace root\\subscription -Class __EventConsumer "
        "-ErrorAction SilentlyContinue | Select-Object Name, __CLASS | ConvertTo-Csv -NoTypeInformation"
    )
    output = await _run_subprocess(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd], timeout=15
    )
    if not output:
        return []
    entries: list[dict[str, Any]] = []
    for line in output.splitlines()[1:]:  # skip header
        parts = _parse_csv_line(line)
        if len(parts) >= 1 and parts[0].strip('"'):
            entries.append({
                "vector": "wmi_subscription",
                "location": "WMI Event Subscription",
                "name": parts[0].strip('"'),
                "command": parts[1].strip('"') if len(parts) > 1 else "",
                "mitre": "T1546.003",
                "mitre_name": MITRE_TAGS.get("T1546.003", "Unknown"),
            })
    return entries


async def collect_all() -> list[dict[str, Any]]:
    """Collect from all persistence vectors concurrently."""
    reg, startup, tasks, wmi = await asyncio.gather(
        collect_registry_entries(),
        collect_startup_folder_entries(),
        collect_scheduled_tasks(),
        collect_wmi_subscriptions(),
    )
    return reg + startup + tasks + wmi
