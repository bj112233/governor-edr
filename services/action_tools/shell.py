# services/action_tools/shell.py
"""PowerShell execution — HITL-protected, Base64-encoded."""

import asyncio
import base64
import logging

from config import TOOL_OUTPUT_MAX_CHARS
from services._winutil import _decode_oem
from services.pending_actions import set_pending

from .security import is_powershell_safe

logger = logging.getLogger(__name__)


async def _run_powershell_exec(command: str) -> str:
    """INTERNAL executor — executes after all security checks."""
    if not is_powershell_safe(command):
        logger.warning("[action_tools] run_powershell BLOCKED: '%s' failed whitelist check", command[:80])
        return "❌ BLOCKED: הפקודה אינה עומדת במדיניות ה-Whitelist. ניתן להשתמש רק ב-Get-/Test-/Select-/Where-/Measure-/Write-/Out-/Format-/Sort-/Group-/Compare-/Split-/Join-/Convert- verb."
    try:
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        proc = await asyncio.create_subprocess_exec(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            encoded,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=30)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return "⏳ PowerShell timeout (>30s)."
        output = _decode_oem(stdout_b).strip() if stdout_b else ""
        err = _decode_oem(stderr_b).strip() if stderr_b else ""
        rc = proc.returncode
        status = "✅" if rc == 0 else "⚠️"
        parts = [f"{status} PowerShell (rc={rc}):"]
        if output:
            parts.append(output[:TOOL_OUTPUT_MAX_CHARS])
        if err:
            parts.append(f"STDERR: {err[:300]}")
        logger.info("[action_tools] run_powershell rc=%d: %s", rc, command[:80])
        return "\n".join(parts)
    except Exception as e:
        logger.error("[action_tools] run_powershell error: %s", e)
        return f"❌ שגיאה: {e}"


async def run_powershell(command: str) -> str:
    """Execute PowerShell: ALL commands require HITL approval.

    SECURITY: No fast-path. Every PowerShell command queues for user approval.
    """
    await set_pending(
        {
            "action": "run_powershell",
            "target": command,
            "reason": "PowerShell execution pending user approval",
        }
    )
    return (
        "⏳ PENDING_APPROVAL: PowerShell command queued for user approval.\n\n"
        f"Command:\n    {command}\n\n"
        "Use /approve to execute or /deny to cancel."
    )
