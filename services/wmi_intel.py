# services/wmi_intel.py
"""
Level 150: WMI Intelligence Module
שאילתות PowerShell/WMI לנתוני חומרה, תוכנה, ומשתמשים.
"""

import asyncio
import logging

from config import TOOL_OUTPUT_MAX_CHARS
from services._winutil import _decode_oem

logger = logging.getLogger(__name__)

_PS_TIMEOUT = 20


async def _run_ps(cmd: str, timeout: int = _PS_TIMEOUT) -> str:
    """הרץ פקודת PowerShell והחזר stdout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return _decode_oem(stdout_b).strip() if stdout_b else ""
    except TimeoutError:
        return "[TIMEOUT] PowerShell query exceeded time limit."
    except Exception as e:
        logger.error(f"[WMI] _run_ps error: {e}")
        return f"[ERROR] {e}"


async def get_local_users() -> str:
    """רשימת משתמשים מקומיים + סטטוס."""
    cmd = (
        "Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet "
        "| Format-Table -AutoSize | Out-String -Width 200"
    )
    return (await _run_ps(cmd))[:TOOL_OUTPUT_MAX_CHARS]


async def get_network_adapters() -> str:
    """מתאמי רשת פעילים + כתובות IP."""
    cmd = (
        "Get-NetIPAddress -AddressFamily IPv4 "
        "| Where-Object { $_.IPAddress -notlike '127.*' } "
        "| Select-Object InterfaceAlias,IPAddress,PrefixLength "
        "| Format-Table -AutoSize | Out-String -Width 200"
    )
    return (await _run_ps(cmd))[:TOOL_OUTPUT_MAX_CHARS]
