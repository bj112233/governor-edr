# services/action_tools/services_mgmt.py
"""Windows service management — start/stop/restart."""

import asyncio
import logging

from services._winutil import _decode_oem

from .security import is_service_action_valid, is_service_name_valid, is_service_protected

logger = logging.getLogger(__name__)


async def _exec_net(cmd_list: list[str]) -> tuple[int | None, bytes | None]:
    """Execute a net command with 30s timeout. Returns (returncode, stdout) or (None, None) on timeout."""
    proc = await asyncio.create_subprocess_exec(
        *cmd_list,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, _stderr_b = await asyncio.wait_for(proc.communicate(), timeout=30)
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return None, None
    return proc.returncode, stdout_b


def _validate_service_action(action: str, name: str) -> str | None:
    """Validate action + service name. Returns error message or None if valid."""
    if not is_service_action_valid(action):
        return f"❌ פעולה לא חוקית '{action}'. מותר: start, stop, restart"
    if is_service_protected(name):
        return f"❌ שירות '{name}' מוגן — לא ניתן לשינוי אוטונומי."
    if not is_service_name_valid(name):
        return f"❌ שם שירות לא תקין: {name}"
    return None


async def _exec_restart(name: str) -> tuple[int | None, bytes | None] | str:
    """Execute restart: stop then start. Returns (rc, stdout) or error string."""
    rc_stop, stdout_stop = await _exec_net(["net", "stop", name])
    if rc_stop is None:
        return f"❌ נכשל לעצור שירות '{name}': timeout"
    if rc_stop != 0 and b"service is not started" not in (stdout_stop or b"").lower():
        return f"❌ נכשל לעצור שירות '{name}': {_decode_oem(stdout_stop or b'')}"
    return await _exec_net(["net", "start", name])


async def manage_service(action: str, name: str) -> str:
    action = action.lower().strip()
    name = name.strip()

    error = _validate_service_action(action, name)
    if error:
        return error

    try:
        if action == "restart":
            result = await _exec_restart(name)
            if isinstance(result, str):
                return result
            rc, stdout_b = result
        else:
            rc, stdout_b = await _exec_net(["net", action, name])

        if rc is None:
            return f"❌ {action} '{name}': timeout"
        output = _decode_oem(stdout_b).strip() if stdout_b else ""
        status = "✅" if rc == 0 else "❌"
        logger.info("[action_tools] manage_service %s %s rc=%d", action, name, rc)
        return f"{status} {action} '{name}': {output[:300]}"
    except Exception as e:
        logger.error("[action_tools] manage_service error: %s", e)
        return f"❌ שגיאה בניהול שירות: {e}"
