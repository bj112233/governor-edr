# services/action_tools/firewall.py
"""Windows firewall IP block/unblock."""

import asyncio
import logging

from services._winutil import _decode_oem

from .security import validate_ip

logger = logging.getLogger(__name__)


async def block_ip(ip: str) -> str:
    if not validate_ip(ip):
        return f"❌ כתובת IP לא תקינה: {ip}"
    ip = ip.strip()
    base = ip.replace(":", "_")
    rule_out = f"SENTINEL_BLOCK_{base}"
    rule_in = f"SENTINEL_BLOCK_IN_{base}"
    errors = []
    successes = []

    async def _add_rule(name: str, direction: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f'name="{name}"',
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=10)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            errors.append(f"{direction}: timeout")
            return
        if proc.returncode != 0:
            err = _decode_oem(stderr_b).strip() if stderr_b else ""
            logger.warning("[action_tools] block_ip %s rc=%d: %s", direction, proc.returncode, err)
            errors.append(f"{direction}: {err}")
        else:
            successes.append(direction)

    async def _del_rule_rollback(name: str, direction: str) -> None:
        """Delete a firewall rule (rollback helper). Raises on failure."""
        proc = await asyncio.create_subprocess_exec(
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f'name="{name}"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=10)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            raise RuntimeError(f"{direction}: rollback timeout") from None

    try:
        await _add_rule(rule_out, "out")
        await _add_rule(rule_in, "in")
        if successes:
            if errors:
                # B3 FIX: partial failure — rollback the succeeded outbound rule
                # to avoid orphaning a half-applied block (outbound only).
                if "out" in successes and any(e.startswith("in") for e in errors):
                    try:
                        await _del_rule_rollback(rule_out, "out")
                        logger.warning("[action_tools] block_ip %s: inbound failed, rolled back outbound rule.", ip)
                    except Exception as rb_exc:
                        logger.error("[action_tools] block_ip %s: rollback of outbound FAILED: %s", ip, rb_exc)
                        return (
                            f"❌ CRITICAL: IP {ip} — inbound failed AND outbound rollback failed. "
                            f"Outbound rule may still be active. Manual cleanup required: "
                            f"netsh advfirewall firewall delete rule name=\"{rule_out}\""
                        )
                return f"⚠️ IP {ip} נחסם חלקית ({', '.join(successes)}). כשלונות: {' | '.join(errors)}"
            return f"✅ IP {ip} נחסם (inbound + outbound) בחומת האש."
        return f"❌ שגיאה בחסימת IP: {' | '.join(errors)}"
    except Exception as e:
        logger.error("[action_tools] block_ip error: %s", e)
        return f"❌ שגיאה בחסימת IP: {e}"


async def unblock_ip(ip: str) -> str:
    if not validate_ip(ip):
        return f"❌ כתובת IP לא תקינה: {ip}"
    ip = ip.strip()
    base = ip.replace(":", "_")
    rule_out = f"SENTINEL_BLOCK_{base}"
    rule_in = f"SENTINEL_BLOCK_IN_{base}"
    deleted = []
    errors = []

    async def _del_rule(name: str, direction: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "netsh",
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f'name="{name}"',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=10)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            errors.append(f"{direction}: timeout")
            return
        output = _decode_oem(stdout_b).strip() if stdout_b else ""
        if "No rules match" not in output and proc.returncode == 0:
            deleted.append(direction)
        else:
            errors.append(f"{direction}: {output or 'no match'}")

    try:
        await _del_rule(rule_out, "out")
        await _del_rule(rule_in, "in")
        logger.info("[action_tools] Unblocked IP: %s (deleted: %s)", ip, deleted)
        if deleted:
            return f"✅ IP {ip} שוחרר מחומת האש (כיוונים: {', '.join(deleted)})."
        return f"⚠️ לא נמצאו חוקי חסימה עבור IP {ip} (ייתכן שלא היה חסום)."
    except Exception as e:
        logger.error("[action_tools] unblock_ip error: %s", e)
        return f"❌ שגיאה בשחרור IP: {e}"
