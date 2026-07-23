# services/action_tools/defender.py
"""Windows Defender quick scan."""

import asyncio
import glob
import logging
import os
import shutil
from pathlib import Path

from config import TOOL_OUTPUT_MAX_CHARS
from services._winutil import _decode_oem

logger = logging.getLogger(__name__)

_MPCMD_PATHS = [
    r"C:\Program Files\Windows Defender\MpCmdRun.exe",
    r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe",
    r"C:\ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe",
]


def _find_mp_cmdrun() -> str | None:
    """Resolve MpCmdRun.exe across Windows editions (Home/Pro/Enterprise).

    Checks known exact paths, then wildcard for versioned subdirs,
    then falls back to PATH via shutil.which.
    """
    for p in _MPCMD_PATHS[:2]:
        if os.path.isfile(p):
            return p
    for pattern in _MPCMD_PATHS[2:]:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    return shutil.which("MpCmdRun")


async def defender_scan() -> str:
    _mpcmd = _find_mp_cmdrun()
    if not _mpcmd:
        logger.warning("[action_tools] MpCmdRun.exe not found — Defender scan skipped.")
        return "⚠️ Defender unavailable: MpCmdRun.exe not found in known paths or PATH."
    try:
        proc = await asyncio.create_subprocess_exec(
            _mpcmd,
            "-Scan",
            "-ScanType",
            "1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=300)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return "⏳ Defender scan timeout (>5 min) — הסריקה ממשיכה ברקע."
        output = _decode_oem(stdout_b).strip() if stdout_b else "Scan completed (no output)."
        rc = proc.returncode
        status = "✅" if rc == 0 else "⚠️"
        logger.info("[action_tools] defender_scan rc=%d", rc)
        return f"{status} Defender Quick Scan:\n{output[:TOOL_OUTPUT_MAX_CHARS]}"
    except Exception as e:
        logger.error("[action_tools] defender_scan error: %s", e)
        return f"❌ שגיאה בהפעלת Defender: {e}"
