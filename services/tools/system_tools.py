# services/tools/system_tools.py
"""System monitoring, network, and hardware tool definitions."""

from typing import Any

from pydantic import BaseModel, Field

from services.cmdline_analyzer import analyze_cmdline
from services.device_registry import auto_discover_lan, load_registry
from services.firewall_intel import get_firewall_drops
from services.gpu_amd import get_cached_gpu_info
from services.monitor_engine import _scan_suspicious_procs
from services.net_intel import get_external_connections_raw, get_listening_ports_raw
from services.os_module import get_all_disks_info
from services.pending_actions import set_pending
from services.system_intel import (
    get_active_sessions_raw,
    get_event_log_raw,
    get_process_list_raw,
    get_scheduled_tasks_detail_raw,
    get_services_raw,
    get_startup_items_raw,
    get_system_snapshot_raw,
    terminate_process,
)
from services.tools._baseline_handler import get_baseline_tool
from services.tools._infra_handler import scan_infrastructure_handler
from services.tools._ioc_history_handler import query_ioc_history_handler
from services.tools.registry import ToolSpec
from services.wmi_intel import get_local_users, get_network_adapters


class NoArgs(BaseModel):
    pass


class TerminateProcessArgs(BaseModel):
    pid: int = Field(..., description="The Process ID to terminate.")


async def _terminate_process_handler(pid, **_) -> str:
    """Queue process kill for user HITL approval."""
    try:
        pid_clean = int(str(pid).strip())
    except (ValueError, TypeError):
        return f"❌ ERROR: Invalid PID format ('{pid}'). Could not queue action."
    # Provenance Gate: block PIDs that originated only from tainted external sources
    from services.agent._provenance import verify_execution_gate

    allowed, reason = verify_execution_gate(f"PID:{pid_clean}", "terminate_process")
    if not allowed:
        return f"🛑 {reason}"
    await set_pending(
        {
            "action": "terminate_process",
            "target": pid_clean,
            "reason": f"Kill PID {pid_clean} pending user approval",
        }
    )
    return f"⏳ PENDING_APPROVAL: Kill PID {pid_clean} queued. Use /approve to execute or /deny to cancel."


def _format_gpu_info(info: dict[str, Any]) -> str:
    """Format AMD GPU dict to Telegram-ready text."""
    if "error" in info:
        return f"🎮 GPU: {info['error']}"
    lines = [f"🎮 {info.get('name', 'AMD GPU')}"]
    util = info.get("utilization_percent")
    temp = info.get("temperature_c")
    ram_gb = info.get("adapter_ram_gb", 0)
    if util is not None:
        lines.append(f"📊 Utilization: {util}%")
    if temp is not None:
        lines.append(f"🌡️ Temp: {temp}°C")
    if ram_gb:
        lines.append(f"💾 VRAM: {ram_gb}GB")
    clk = info.get("engine_clock_mhz")
    if clk is not None:
        lines.append(f"⚡ Clock: {clk} MHz")
    mem_clk = info.get("memory_clock_mhz")
    if mem_clk is not None:
        lines.append(f"🧠 Mem Clock: {mem_clk} MHz")
    fan = info.get("fan_speed_percent")
    if fan is not None:
        lines.append(f"🌀 Fan: {fan}%")
    pwr = info.get("power_draw_w")
    if pwr is not None:
        lines.append(f"🔌 Power: {pwr}W")
    driver = info.get("driver_version", "Unknown")
    status = info.get("status", "Unknown")
    lines.append(f"📅 Driver: {driver} | Status: {status}")
    return "\n".join(lines)


def _format_known_devices() -> str:
    registry = load_registry()
    if not registry:
        return "אין מכשירים ידועים ברשת. הרץ /lanscan לגילוי."
    lines = [f"**🏠 מכשירי LAN ({len(registry)}):**"]
    for ip, info in registry.items():
        lines.append(
            f"- {ip:<16} MAC: {info.get('mac', '?'):<18} שם: {info.get('name', ip)}  נוסף: {info.get('added', '?')}"
        )
    return "\n".join(lines)


async def _scan_lan_tool() -> str:
    new_count = await auto_discover_lan()
    registry = load_registry()
    icon = "🔔" if new_count > 0 else "✅"
    lines = [
        f"{icon} **סריקת LAN הושלמה**",
        f"- מכשירים חדשים שנמצאו: {new_count}",
        f'- סה"כ מכשירים מוכרים: {len(registry)}',
    ]
    if registry:
        lines.append("- רשימת מכשירים:")
        for ip, info in registry.items():
            name = info.get("name", "Unknown")
            mac = info.get("mac", "N/A")
            lines.append(f"  - {ip} | MAC: {mac} | Name: {name}")
    return "\n".join(lines)


async def _get_local_users_handler(**_):
    return await get_local_users()


async def _get_network_adapters_handler(**_):
    return await get_network_adapters()


class AnalyzeCmdlineArgs(BaseModel):
    cmdline: str = Field(..., description="Process command line to analyze for MITRE ATT&CK TTPs.")


class ScanInfrastructureArgs(BaseModel):
    domain: str = Field(..., description="Domain to discover subdomains, archived URLs, and passive scan data.")


class QueryIOCArgs(BaseModel):
    ioc: str = Field(..., description="The exact IOC (IP, domain, hash) to query in historical memory.")


class FinalAnswerArgs(BaseModel):
    text: str = Field(description="Complete Hebrew response with all findings and data; keep cyber terms in English.")


def _format_cmdline_analysis(cmdline: str) -> str:
    """Format cmdline_analyzer results as Telegram-ready text.

    Delegates to _proc_formatter for the actual implementation.
    """
    from services.tools._proc_formatter import format_cmdline_analysis

    return format_cmdline_analysis(cmdline)


def _format_suspicious_procs() -> str:
    """Format suspicious process scan + deterministic cmdline analysis.

    Delegates to _proc_formatter for the actual implementation.
    Pre-Compute Deterministic Enrichment: the LLM receives hard facts.
    """
    from services.tools._proc_formatter import format_suspicious_procs

    return format_suspicious_procs()


def get_system_tools() -> list[ToolSpec]:
    """Return all system and network monitoring tools."""
    return [
        ToolSpec(
            name="get_system_snapshot",
            description="CPU/RAM/disk usage snapshot (always call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_system_snapshot_raw(),
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="get_amd_gpu_info",
            description="AMD GPU information via WMI.",
            pydantic_model=NoArgs,
            handler=lambda **_: _format_gpu_info(get_cached_gpu_info()),
        ),
        ToolSpec(
            name="get_process_list",
            description="Running processes sorted by CPU (call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_process_list_raw(),
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="get_running_processes",
            description="Running processes sorted by CPU (call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_process_list_raw(),
            expose_to_llm=False,  # duplicate of get_process_list — save a tool slot
        ),
        ToolSpec(
            name="get_external_connections",
            description="Active external network connections (call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_external_connections_raw(),
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="get_listening_ports",
            description="Listening TCP/UDP ports (call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_listening_ports_raw(),
        ),
        ToolSpec(
            name="get_event_log",
            description="Recent Windows Security event log.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_event_log_raw(),
        ),
        ToolSpec(
            name="get_services",
            description="Running Windows services.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_services_raw(),
        ),
        ToolSpec(
            name="get_local_users",
            description="Local Windows user accounts.",
            pydantic_model=NoArgs,
            handler=_get_local_users_handler,
        ),
        ToolSpec(
            name="get_disk_details",
            description="Per-partition disk usage.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_all_disks_info(),
        ),
        ToolSpec(
            name="get_startup_items",
            description="Scheduled tasks + registry Run keys.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_startup_items_raw(),
        ),
        ToolSpec(
            name="get_firewall_drops",
            description="Recent Firewall DROP events.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_firewall_drops(20),
        ),
        ToolSpec(
            name="terminate_process",
            description="Queue PID kill (pending user approval).",
            pydantic_model=TerminateProcessArgs,
            handler=_terminate_process_handler,
            safety_level="critical",
            requires_data_integrity=True,
        ),
        ToolSpec(
            name="get_network_adapters",
            description="Network adapters with IP/MAC.",
            pydantic_model=NoArgs,
            handler=_get_network_adapters_handler,
        ),
        ToolSpec(
            name="scan_lan",
            description="ARP scan of LAN for new devices.",
            pydantic_model=NoArgs,
            handler=_scan_lan_tool,
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="get_known_devices",
            description="Known LAN devices from registry.",
            pydantic_model=NoArgs,
            handler=lambda **_: _format_known_devices(),
        ),
        ToolSpec(
            name="get_active_sessions",
            description="Active sessions and logged-in users incl. RDP (call fresh).",
            pydantic_model=NoArgs,
            handler=lambda **_: get_active_sessions_raw(),
        ),
        ToolSpec(
            name="get_scheduled_tasks_detail",
            description="Detailed scheduled tasks metadata.",
            pydantic_model=NoArgs,
            handler=lambda **_: get_scheduled_tasks_detail_raw(),
        ),
        ToolSpec(
            name="analyze_cmdline",
            description="Analyze a process command line for MITRE ATT&CK TTPs (PowerShell evasion, base64, download cradles).",
            pydantic_model=AnalyzeCmdlineArgs,
            handler=lambda **kwargs: _format_cmdline_analysis(kwargs["cmdline"]),
            safety_level="safe",
        ),
        ToolSpec(
            name="scan_suspicious_procs",
            description="Scan for suspicious processes (powershell, wmic, certutil, mshta) with command line capture.",
            pydantic_model=NoArgs,
            handler=lambda **_: _format_suspicious_procs(),
            safety_level="safe",
        ),
        ToolSpec(
            name="scan_infrastructure",
            description="Discover subdomains (crt.sh), archived URLs (Wayback), and passive scan data (urlscan.io) for a domain.",
            pydantic_model=ScanInfrastructureArgs,
            handler=scan_infrastructure_handler,
            safety_level="safe",
        ),
        ToolSpec(
            name="query_ioc_history",
            description="Query historical threat score for an IOC (IP/domain/hash) with 14-day exponential decay. Returns decayed score + raw events.",
            pydantic_model=QueryIOCArgs,
            handler=query_ioc_history_handler,
            safety_level="safe",
        ),
        get_baseline_tool(),
        ToolSpec(
            name="final_answer",
            description="Deliver complete answer to the user.",
            pydantic_model=FinalAnswerArgs,
            handler=lambda **kwargs: kwargs.get("text", ""),
            expose_to_mcp=False,
        ),
    ]
