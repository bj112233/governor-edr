"""Microsoft signature filter — filters out MS-signed entries by default.

Reduces noise: Windows has ~80+ legitimate MS persistence entries.
The filter checks if the command path points to a known Microsoft location
or a known MS binary. This is a heuristic (not cryptographic verification)
to keep the 16K token budget manageable.

Use --include-ms to show everything (for full audit).
"""

from __future__ import annotations

from typing import Any

# Known Microsoft paths (case-insensitive substring match)
_MS_PATH_MARKERS = (
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "%systemroot%",
    "%windir%",
)

# Known Microsoft binary names (case-insensitive exact match on filename)
_MS_BINARIES = {
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "onedrive.exe",
    "microsoftedgeupdate.exe",
    "officeclicktorun.exe",
    "integratedoffice.exe",
    "msosync.exe",
    "teams.exe",
    "skype.exe",
    "cortana.exe",
    "searchui.exe",
    "runtimebroker.exe",
    "textinputhost.exe",
    "windowsdefender.exe",
    "msmpeng.exe",
    "msedge.exe",
}


def is_likely_microsoft(entry: dict[str, Any]) -> bool:
    """Heuristic: True if entry looks like a legitimate Microsoft persistence item."""
    command = entry.get("command", "").lower()
    name = entry.get("name", "").lower()

    # Check path markers
    for marker in _MS_PATH_MARKERS:
        if marker in command:
            return True

    # Check known MS binary names
    for binary in _MS_BINARIES:
        if binary in command or binary in name:
            return True

    # Scheduled tasks: Microsoft tasks have predictable prefixes
    if entry.get("vector") == "scheduled_task":
        ms_task_prefixes = ("\\microsoft\\", "\\microsoftedgeupdate\\")
        for prefix in ms_task_prefixes:
            if prefix in name:
                return True

    return False


def filter_entries(entries: list[dict[str, Any]], include_ms: bool = False) -> list[dict[str, Any]]:
    """Filter out likely-Microsoft entries unless include_ms=True."""
    if include_ms:
        return entries
    return [e for e in entries if not is_likely_microsoft(e)]
