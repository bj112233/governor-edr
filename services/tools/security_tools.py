# services/tools/security_tools.py
"""Security action tools: firewall, IP blocking, defender, powershell."""

from pydantic import BaseModel, Field

from services.action_tools import run_powershell
from services.credential_monitor import format_credential_results, scan_credential_leaks
from services.pending_actions import set_pending
from services.tools.registry import ToolSpec
from services.yara_engine import match as yara_match


class NoArgs(BaseModel):
    pass


class RunPowershellArgs(BaseModel):
    command: str = Field(..., description="PowerShell command to queue")


class BlockIpArgs(BaseModel):
    ip: str = Field(..., description="IP address to block")


class UnblockIpArgs(BaseModel):
    ip: str = Field(..., description="IP address to unblock")


class ManageServiceArgs(BaseModel):
    action: str = Field(..., description="start | stop | restart")
    name: str = Field(..., description="Service name, e.g. wuauserv")


async def _defender_scan_handler(**_):
    await set_pending(
        {"action": "defender_scan", "target": "", "reason": "Windows Defender scan pending user approval"}
    )
    return "⏳ PENDING_APPROVAL: Defender scan queued. Use /approve to execute or /deny to cancel."


async def _block_ip_handler(ip, **_):
    ip_clean = str(ip).strip()
    # Provenance Gate: block IPs that originated only from tainted external sources
    from services.agent._provenance import verify_execution_gate

    allowed, reason = verify_execution_gate(f"IP:{ip_clean}", "block_ip")
    if not allowed:
        return f"🛑 {reason}"
    await set_pending(
        {"action": "block_ip", "target": ip_clean, "reason": f"Block IP {ip_clean} pending user approval"}
    )
    return f"⏳ PENDING_APPROVAL: Block IP {ip_clean} queued. Use /approve to execute or /deny to cancel."


async def _unblock_ip_handler(ip, **_):
    ip_clean = str(ip).strip()
    # Provenance Gate: block unblock of IPs from tainted-only sources
    from services.agent._provenance import verify_execution_gate

    allowed, reason = verify_execution_gate(f"IP:{ip_clean}", "unblock_ip")
    if not allowed:
        return f"🛑 {reason}"
    await set_pending(
        {"action": "unblock_ip", "target": ip_clean, "reason": f"Unblock IP {ip_clean} pending user approval"}
    )
    return f"⏳ PENDING_APPROVAL: Unblock IP {ip_clean} queued. Use /approve to execute or /deny to cancel."


async def _manage_service_handler(action, name, **_):
    action_clean = str(action).strip()
    name_clean = str(name).strip()
    await set_pending(
        {
            "action": "manage_service",
            "target": {"action": action_clean, "name": name_clean},
            "reason": f"manage_service {action_clean} '{name_clean}' pending user approval",
        }
    )
    return (
        f"⏳ PENDING_APPROVAL: manage_service {action_clean} '{name_clean}' queued. "
        "Use /approve to execute or /deny to cancel."
    )


async def _run_powershell_handler(command, **_):
    return await run_powershell(str(command))


async def _local_screenshot_handler(**_):
    await set_pending(
        {"action": "screenshot", "target": "", "reason": "Desktop screenshot capture pending user approval"}
    )
    return "⏳ PENDING_APPROVAL: Screenshot queued. Use /approve to capture or /deny to cancel."


class ScanFileYaraArgs(BaseModel):
    filepath: str = Field(..., description="Path to file to scan with YARA rules.")


class ScanCredentialLeaksArgs(BaseModel):
    query: str = Field(..., description="Domain, email, or keyword to search for leaked credentials.")


def _format_yara_results(filepath: str) -> str:
    """Format YARA scan results as Telegram-ready text."""
    results = yara_match(filepath)
    if not results:
        return f"✅ No YARA rule matches for: {filepath}"
    lines = [f"🚨 **YARA Matches** ({len(results)} rule(s)):"]
    for r in results:
        tags = ", ".join(r.get("tags", [])) or "none"
        lines.append(f"- **{r['rule']}** [tags: {tags}]")
        meta = r.get("meta", {})
        if meta:
            for k, v in list(meta.items())[:3]:
                lines.append(f"  {k}: {v}")
        strings = r.get("strings", [])
        if strings:
            lines.append(f"  strings ({len(strings)}):")
            for s in strings[:3]:
                lines.append(f"    offset={s.get('offset', '?')} id={s.get('identifier', '?')}")
    return "\n".join(lines)


async def _scan_credential_leaks_handler(query, **_) -> str:
    """Search Pastebin/GitHub for leaked credentials. 25s timeout, graceful degradation."""
    import asyncio as _aio

    try:
        results = await _aio.wait_for(scan_credential_leaks(str(query)), timeout=25.0)
        return format_credential_results(results)
    except TimeoutError:
        return f"⏱️ Credential leak scan timed out (>25s) for query: {query}"
    except Exception as exc:
        return f"❌ Credential leak scan failed: {exc}"


def get_security_tools() -> list[ToolSpec]:
    """Return all security and action tools."""
    return [
        ToolSpec(
            name="defender_scan",
            description="Queue Windows Defender Quick Scan (pending user approval).",
            pydantic_model=NoArgs,
            handler=_defender_scan_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="run_powershell",
            description="Queue PowerShell command (pending user approval).",
            pydantic_model=RunPowershellArgs,
            handler=_run_powershell_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="block_ip",
            description="Queue IP block (pending user approval).",
            pydantic_model=BlockIpArgs,
            handler=_block_ip_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="unblock_ip",
            description="Queue IP unblock (pending user approval).",
            pydantic_model=UnblockIpArgs,
            handler=_unblock_ip_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="manage_service",
            description="Queue service start|stop|restart (pending user approval).",
            pydantic_model=ManageServiceArgs,
            handler=_manage_service_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="local_screenshot",
            description="Queue desktop screenshot capture (pending user approval).",
            pydantic_model=NoArgs,
            handler=_local_screenshot_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="scan_file_yara",
            description="Scan a file against compiled YARA rules for malware pattern detection.",
            pydantic_model=ScanFileYaraArgs,
            handler=lambda **kwargs: _format_yara_results(kwargs["filepath"]),
            safety_level="safe",
        ),
        ToolSpec(
            name="scan_credential_leaks",
            description="Search Pastebin/GitHub for leaked credentials (domain, email, or keyword).",
            pydantic_model=ScanCredentialLeaksArgs,
            handler=_scan_credential_leaks_handler,
            safety_level="safe",
        ),
    ]
