# services/process_analyzer.py
"""analyze_process_event — Sysmon-enriched process analysis wrapper.

Wraps `analyze_cmdline` (the existing regex engine, unchanged) and adds
4 checks that require Sysmon fields unavailable to psutil:

  1. Parent anomaly (T1059.005) — suspicious parent→child chain
  2. Hash reputation — known-malicious SHA256 (placeholder for intel feed)
  3. Integrity level — Medium spawning High = UAC bypass attempt
  4. Unsigned masquerading — unsigned binary in C:\\Windows\\

Each check gracefully skips when its required field is None (psutil path
or Sysmon partial event). The wrapper NEVER throws on missing data —
it falls back to `analyze_cmdline` results alone.

Returns `list[CmdlineMatch]` — same type as `analyze_cmdline`, so
downstream consumers (monitor_analyzer, _proc_formatter) can use either
function interchangeably.
"""

from __future__ import annotations

import logging
import os

from services.cmdline_analyzer import CmdlineMatch, analyze_cmdline
from services.process_event import ProcessEvent

logger = logging.getLogger(__name__)

# ── Parent anomaly: legitimate parent images for common processes ──
# If a process is spawned by a parent that should never spawn it, that's
# T1059.005 (Process Injection) or T1059.001 (PowerShell) abuse.
# Example: winword.exe → cmd.exe is classic macro-dropper behavior.
_SUSPICIOUS_PARENT_PAIRS: dict[str, frozenset[str]] = {
    # Office apps should never spawn shells or scripting engines
    "winword.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}),
    "excel.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}),
    "outlook.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}),
    "powerpoint.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}),
    # Browsers spawning shells — possible drive-by exploit
    "chrome.exe": frozenset({"cmd.exe", "powershell.exe"}),
    "msedge.exe": frozenset({"cmd.exe", "powershell.exe"}),
    "firefox.exe": frozenset({"cmd.exe", "powershell.exe"}),
    # PDF reader spawning shell
    "acrord32.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe"}),
    "acrobat.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe"}),
}


def _basename_lower(path: str) -> str:
    """Extract lowercase basename from a full path."""
    if not path:
        return ""
    # Handle both \ and / separators
    return path.replace("/", "\\").split("\\")[-1].lower()


def _check_parent_anomaly(event: ProcessEvent) -> CmdlineMatch | None:
    """T1059.005 — suspicious parent→child process chain.

    Returns a CmdlineMatch if the parent image is a known "should never
    spawn a shell" application (Office, browser, PDF reader) and the
    child is a shell/scripting engine. Returns None if:
      - parent_image is None (psutil path or orphan)
      - parent is not in the suspicious-parent table
      - child name is not in the parent's forbidden-children set
    """
    if event.parent_image is None:
        return None
    parent_name = _basename_lower(event.parent_image)
    child_name = event.name.lower() if event.name else ""

    forbidden_children = _SUSPICIOUS_PARENT_PAIRS.get(parent_name)
    if forbidden_children is None:
        return None  # parent not in table — no anomaly
    if child_name not in forbidden_children:
        return None  # child is not a forbidden spawn

    return CmdlineMatch(
        technique_id="T1059.005",
        name="Suspicious parent process chain",
        tactic="Defense Evasion",
        confidence=0.85,
        signals=[f"parent={parent_name}", f"child={child_name}"],
        suggested_score=75,  # High suspicion but not auto-block (needs context)
    )


def analyze_process_event(event: ProcessEvent) -> list[CmdlineMatch]:
    """Analyze a ProcessEvent for MITRE TTPs.

    Always runs `analyze_cmdline(event.cmdline)` (the regex engine).
    Additionally runs Sysmon-enriched checks when their required fields
    are present (skips gracefully when None).

    Args:
        event: ProcessEvent from psutil or Sysmon.

    Returns:
        List of CmdlineMatch sorted by suggested_score descending.
        Empty list if no suspicious patterns found.
    """
    # 1. Base regex analysis — always runs, even on empty cmdline
    matches = list(analyze_cmdline(event.cmdline))

    # 2. Parent anomaly (T1059.005) — requires parent_image
    parent_match = _check_parent_anomaly(event)
    if parent_match is not None:
        matches.append(parent_match)

    # 3-4. Hash reputation, integrity level, unsigned masquerading
    # — added in subsequent commits

    return sorted(matches, key=lambda m: m.suggested_score, reverse=True)
