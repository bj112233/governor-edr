"""System persistence intel — startup items, sessions, scheduled tasks.

Extracted from system_intel.py (SRP). Async subprocess-based collectors
for persistence mechanisms and active session enumeration.
"""

import asyncio

from config import truncate_for_context
from services._winutil import _decode_oem


async def _run_subprocess(cmd: list[str], timeout: int = 10) -> str | None:
    """Run subprocess, return decoded stdout or None on timeout/error."""
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
    return _decode_oem(stdout_b).strip()


async def get_startup_items_raw() -> str:
    """מחזיר Scheduled Tasks + Registry Run Keys לזיהוי Persistence"""
    parts = []

    tasks = await _run_subprocess(["schtasks", "/query", "/fo", "LIST"], timeout=15)
    parts.append(f"=== SCHEDULED TASKS ===\n{tasks[:2500]}" if tasks else "Scheduled Tasks: timeout")

    reg_hklm = await _run_subprocess(
        ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"], timeout=10
    )
    parts.append(f"=== REGISTRY RUN KEYS (HKLM) ===\n{reg_hklm}" if reg_hklm else "Registry HKLM: timeout")

    reg_hkcu = await _run_subprocess(
        ["reg", "query", r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"], timeout=10
    )
    parts.append(f"=== REGISTRY RUN KEYS (HKCU) ===\n{reg_hkcu}" if reg_hkcu else "Registry HKCU: timeout")

    return truncate_for_context("\n\n".join(parts), max_chars=8000)


async def get_active_sessions_raw() -> str:
    """מחזיר sessions פעילים ב-Windows: logged-in users + RDP sessions."""
    parts = []
    sessions = await _run_subprocess(["query", "session"], timeout=10)
    parts.append(
        f"=== ACTIVE SESSIONS ===\n{sessions or 'No sessions found.'}"
        if sessions is not None
        else "query session: timeout"
    )
    users = await _run_subprocess(["query", "user"], timeout=10)
    parts.append(
        f"=== LOGGED-IN USERS ===\n{users or 'No users found.'}" if users is not None else "query user: timeout"
    )
    return "\n\n".join(parts)


async def get_scheduled_tasks_detail_raw() -> str:
    """מחזיר פירוט מלא של Scheduled Tasks — CSV/V, יותר מעמיק מ-get_startup_items."""
    output = await _run_subprocess(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=20)
    if output is None:
        return "⏳ Scheduled tasks query timed out (>20s)."
    if not output:
        return "No scheduled tasks found."
    lines = output.splitlines()
    return truncate_for_context("\n".join(lines[:80]), max_chars=8000)
