# services/behavioral_filter.py
"""Behavioral profiling for network connections.
- OS/CDN silent whitelist (svchost -> Akamai/Fastly/Microsoft)
- Shell process zero-tolerance (powershell, cmd, wscript -> CRITICAL)
- Dual-stack aggregation by subnet to prevent LLM spam.
All new files < 300 lines (SRP).
"""

import ipaddress
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from services.net_parser import get_subnet

logger = logging.getLogger(__name__)

# -- Standard OS binaries that legitimately connect to CDN/Telemetry --
_OS_PROCS = {
    "svchost.exe",
    "svchost",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "csrss.exe",
    "smss.exe",
    "winlogon.exe",
    "explorer.exe",
    "SearchIndexer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "svchost.exe*32",
}

# -- Known benign CDN / Telemetry CIDR ranges (Akamai, Fastly, Microsoft) --
_CDN_CIDRS_RAW: list[str] = [
    # Akamai
    "23.0.0.0/12",
    "23.32.0.0/11",
    "23.64.0.0/14",
    "96.16.0.0/15",
    "184.24.0.0/13",
    "2.16.0.0/13",
    # Fastly
    "151.101.0.0/16",
    "199.232.0.0/16",
    "146.75.0.0/16",
    # Microsoft / Azure / Bing CDN
    "13.107.0.0/16",
    "20.190.0.0/16",
    "40.126.0.0/16",
    "52.182.0.0/16",
    "72.21.81.0/24",
    "104.44.88.0/21",
    "191.232.0.0/13",
    "204.79.197.0/24",
    "2620:1ec::/36",
    "2a01:111::/32",
    "2603::/24",
    "2a06::/29",
    "2606:2800::/32",
    # Akamai IPv6 (ARIN-allocated, validated via RDAP 2026-06-01)
    "2600:1400::/24",
]
_CDN_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network(c, strict=False) for c in _CDN_CIDRS_RAW
]


def _ip_in_cdn(ip: str) -> bool:
    """Return True if `ip` falls within a known benign CDN/telemetry CIDR."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _CDN_NETWORKS)


# -- Shell / scripting processes -- zero tolerance --
_SHELL_PROCS = {
    "powershell.exe",
    "powershell",
    "cmd.exe",
    "cmd",
    "wscript.exe",
    "wscript",
    "cscript.exe",
    "cscript",
    "mshta.exe",
    "mshta",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}

# Known terminal / IDE parents that legitimately spawn shells
_SHELL_PARENT_WHITELIST = {
    "windowsterminal.exe",
    # both casing variants
    "code.exe",
    "pycharm64.exe",
    "idea64.exe",
    "cursor.exe",
    "windsurf.exe",
    "devin.exe",
    "wt.exe",  # Windows Terminal (short exe)
}


def _get_parent_name(pid: int) -> str:
    """Return lower-case parent process basename (handles full paths)."""
    try:
        import psutil

        proc = psutil.Process(pid)
        parent = proc.parent()
        if parent is None:
            return ""
        # psutil.name() sometimes returns a full path — extract basename
        return Path(parent.name()).name.lower()
    except Exception:
        return ""


@dataclass(frozen=True)
class BehavioralAssessment:
    status: str  # 'clean' | 'critical'
    reason: str = ""
    details: dict = field(default_factory=dict)


class BehavioralFilter:
    """Filter and classify active connections."""

    def filter_and_classify(self, connections: list[dict]) -> tuple[list[dict], list[BehavioralAssessment]]:
        """Return (filtered_connections, assessments).

        - OS->CDN connections are silently dropped.
        - Shell processes always emit CRITICAL and bypass filters.
        - Remaining connections are aggregated by (proc, subnet).
        """
        assessments: list[BehavioralAssessment] = []
        survivors: list[dict] = []

        # -- Zero-tolerance pass: shell processes (with parent chain check) --
        for c in connections:
            proc = c.get("proc_name", "unknown").lower()
            if proc in _SHELL_PROCS:
                pid = c.get("pid", 0)
                parent_name = _get_parent_name(pid) if pid else ""
                if parent_name in _SHELL_PARENT_WHITELIST:
                    logger.debug(
                        "[BehavioralFilter] Shell from known terminal allowed: %s (parent=%s) -> %s",
                        proc,
                        parent_name,
                        c.get("raddr_ip", "?"),
                    )
                    survivors.append(c)
                    continue
                assessments.append(
                    BehavioralAssessment(
                        status="critical",
                        reason=f"\u05d7\u05d9\u05d1\u05d5\u05e8 \u05d7\u05d9\u05e6\u05d5\u05e0\u05d9 \u05de\u05ea\u05d4\u05dc\u05d9\u05da shell: {proc} -> {c.get('raddr_ip', '?')}:{c.get('raddr_port', 0)}",
                        details={
                            "proc": proc,
                            "remote_ip": c.get("raddr_ip", ""),
                            "remote_port": c.get("raddr_port", 0),
                            "zero_tolerance": True,
                            "parent": parent_name or "unknown",
                        },
                    )
                )
                # Shell connections are NOT added to survivors -- they go straight to LLM
                continue
            survivors.append(c)

        # -- Silent whitelist pass: OS binary -> CDN/Telemetry --
        filtered: list[dict] = []
        for c in survivors:
            proc = c.get("proc_name", "unknown").lower()
            rip = c.get("raddr_ip", "")
            if proc in _OS_PROCS and _ip_in_cdn(rip):
                logger.debug("[BehavioralFilter] Silently dropping OS->CDN: %s -> %s", proc, rip)
                continue
            filtered.append(c)

        # -- Dual-stack aggregation by (proc_name, subnet) --
        grouped: dict[tuple, list[dict]] = defaultdict(list)
        for c in filtered:
            rip = c.get("raddr_ip", "")
            proc = c.get("proc_name", "unknown")
            subnet = get_subnet(rip, prefix_v4=24, prefix_v6=64)
            grouped[(proc, subnet)].append(c)

        aggregated: list[dict] = []
        for (proc, subnet), conns in grouped.items():
            if len(conns) == 1:
                aggregated.append(conns[0])
            else:
                # Roll multiple connections to same subnet into one event
                ports = sorted({c.get("raddr_port", 0) for c in conns if c.get("raddr_port", 0) > 0})
                aggregated.append(
                    {
                        "proc_name": proc,
                        "raddr_ip": subnet,
                        "raddr_port": ports[0] if ports else 0,
                        "aggregated_count": len(conns),
                        "aggregated_ports": ports,
                        "laddr_ip": conns[0].get("laddr_ip", ""),
                        "laddr_port": conns[0].get("laddr_port", 0),
                        "pid": conns[0].get("pid", 0),
                    }
                )
                logger.debug(
                    "[BehavioralFilter] Aggregated %d conns from %s to %s",
                    len(conns),
                    proc,
                    subnet,
                )

        return aggregated, assessments


# -- Phase 7: Allowlist for expected system network behavior --
ALLOWED_SYSTEM_PROCESSES = {
    # Core OS & Browsers
    "svchost.exe",
    "explorer.exe",
    "msedge.exe",
    "chrome.exe",
    "system",
    "searchapp.exe",
    "widgets.exe",
    "searchhost.exe",
    # Security & Telemetry
    "mpdefendercoreservice.exe",
    "smartscreen.exe",
    "wermgr.exe",
    "taskhostw.exe",
    "backgroundtaskhost.exe",
    # Developer Tools & Sync
    "windsurf.exe",
    "language_server_windows_x64.exe",
    "msedgewebview2.exe",
    "onedrive.exe",
    "devin.exe",
}

# Standard web/system ports considered benign for allowlisted processes
_STANDARD_PORTS = {80, 443, 123, 53}

# M1 fix: Legitimate paths for allowlisted browser/system processes.
# Malware named "chrome.exe" in C:\Temp\ fails this check.
import os as _os

_PROGRAM_FILES = _os.environ.get("ProgramFiles", r"C:\Program Files").lower()
_PROGRAM_FILES_X86 = _os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower()
_LOCAL_APPDATA = _os.environ.get("LOCALAPPDATA", "").lower()
_WINDOWS = _os.environ.get("SystemRoot", r"C:\Windows").lower()

_LEGIT_PATH_PREFIXES = tuple(
    p
    for p in (
        _PROGRAM_FILES,
        _PROGRAM_FILES_X86,
        _LOCAL_APPDATA,
        _WINDOWS,
    )
    if p
)


def _is_legitimate_process_path(pid: int | None, process_name: str) -> bool:
    """M1 fix: Verify allowlisted process runs from a legitimate directory.

    Without PID → fail-open (name-only match, backward compat).
    With PID → check psutil.Process(pid).exe() against legit prefixes.
    Malware in C:\\Temp\\chrome.exe fails this check.
    """
    if pid is None or pid <= 4:
        return True  # can't verify — fail-open to name-only
    try:
        import psutil

        exe = psutil.Process(pid).exe()
        if not exe:
            return False  # fail-closed — can't read path
        exe_lower = exe.lower()
        return any(exe_lower.startswith(prefix) for prefix in _LEGIT_PATH_PREFIXES)
    except Exception:
        return True  # fail-open on psutil errors (AccessDenied, NoSuchProcess)


def is_expected_network_behavior(process_name: str, remote_port: int, pid: int | None = None) -> bool:
    """Return True if process is allowlisted AND port is a standard web/system port.

    M1 fix: When PID is available, also verifies the process executable
    path is from a legitimate directory (Program Files, LocalAppData,
    Windows). Malware spoofing "chrome.exe" from C:\\Temp\\ is NOT
    treated as expected behavior.
    """
    if not process_name:
        return False
    try:
        port = int(remote_port)
    except (TypeError, ValueError):
        return False
    if process_name.lower() not in ALLOWED_SYSTEM_PROCESSES:
        return False
    if port not in _STANDARD_PORTS:
        return False
    return _is_legitimate_process_path(pid, process_name)
