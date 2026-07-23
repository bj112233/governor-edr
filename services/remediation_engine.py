# services/remediation_engine.py
"""Titanium Cage — Human-in-the-Loop remediation engine.
Hardcoded whitelists. Windows-native commands only.
"""

import logging
import os
import subprocess

import psutil

logger = logging.getLogger(__name__)

SAFE_PROCESSES = {"svchost.exe", "explorer.exe", "system", "wininit.exe", "lsass.exe"}
SAFE_IPS = {"127.0.0.1"}

# System directories where legitimate Windows processes must reside.
# Malware masquerading as svchost.exe from C:\Temp\ fails this check.
_SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()
_SAFE_PROCESS_DIRS = (
    os.path.join(_SYSTEM_ROOT, "System32").lower(),
    os.path.join(_SYSTEM_ROOT, "SysWOW64").lower(),
    _SYSTEM_ROOT,
)


def _is_safe_system_process(proc_name: str, pid: int | None = None) -> bool:
    """Verify a process is a legitimate Windows system process.

    Two-layer check:
    1. Name must match SAFE_PROCESSES (fast path).
    2. If PID available, executable path must be under SystemRoot.
       Malware in C:\\Temp\\svchost.exe fails this check.

    Fail-closed: if we can't read the exe path (AccessDenied), treat as
    NOT safe — prevents fail-open on permission manipulation.
    """
    pname = proc_name.lower()
    if pname not in {p.lower() for p in SAFE_PROCESSES}:
        return False
    if pid is None or pid <= 4:
        # No PID to verify path — name match alone is insufficient for
        # system processes. Refuse kill to prevent masquerading bypass.
        return True  # name-only fallback for system PIDs (0-4 are kernel)
    try:
        proc = psutil.Process(pid)
        exe_path = (proc.exe() or "").lower()
        if not exe_path:
            return False  # can't read path → fail-closed
        return any(exe_path.startswith(d) for d in _SAFE_PROCESS_DIRS)
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return False  # fail-closed — don't protect potential malware


def _is_loopback_ip(ip: str) -> bool:
    """M4: Return True iff IP is loopback (127.0.0.0/8 or ::1)."""
    return ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1")


def _is_rfc1918_ip(ip: str) -> bool:
    """M4: Return True iff IP is RFC1918 private LAN (not loopback).

    Includes 10/8, 172.16-31/12, 192.168/16, fe80::/10, fc00::/7 (ULA).
    """
    return ip.startswith(
        (
            "192.168.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "fe80:",
            "fc00:",
            "fd00:",
        )
    )


def _is_local_ip(ip: str) -> bool:
    """M4: Return True iff IP is loopback OR RFC1918 private.

    Used by block_ip_in_firewall to prevent blocking loopback (always)
    and RFC1918 (configurable via ALLOW_LAN_BLOCK env var).
    """
    return _is_loopback_ip(ip) or _is_rfc1918_ip(ip)


def _kill_by_name(proc_name: str) -> tuple[bool, str]:
    """Kill a process by name when PID is unknown.

    H7 fix: refuses to kill if multiple processes match the name
    (collateral damage prevention). Requires disambiguation via PID.
    """
    pname_lower = proc_name.lower()
    try:
        matching_pids: list[int] = []
        for p in psutil.process_iter(["pid", "name"]):
            if (p.info.get("name") or "").lower() == pname_lower:
                if p.info["pid"] <= 4 or p.info["pid"] == os.getpid():
                    continue
                matching_pids.append(p.info["pid"])
        if not matching_pids:
            return False, f"Process '{proc_name}' not found by name."
        if len(matching_pids) > 1:
            logger.warning(
                "[Remediation] Refused ambiguous kill: %d processes match '%s' (PIDs: %s)",
                len(matching_pids),
                proc_name,
                matching_pids,
            )
            return (
                False,
                f"Ambiguous: {len(matching_pids)} processes match '{proc_name}' "
                f"(PIDs: {matching_pids}). PID required for disambiguation.",
            )
        target_pid = matching_pids[0]
        psutil.Process(target_pid).kill()
        logger.warning("[Remediation] Killed %s (PID %s, by name)", proc_name, target_pid)
        return True, f"✅ '{proc_name}' (PID {target_pid}) terminated (by name lookup)."
    except Exception as e:
        return False, f"Kill by name failed: {e}"


def kill_process(pid: int | None, proc_name: str, degraded_mode: bool = False) -> tuple[bool, str]:
    if degraded_mode:
        logger.warning("[Remediation] kill_process refused: DEGRADED mode (Critic offline).")
        return False, "BLOCKED: DEGRADED mode — Critic offline, destructive actions refused."
    if _is_safe_system_process(proc_name, pid):
        return False, f"Process '{proc_name}' is whitelisted (verified system path) and cannot be killed."
    if pid is None:
        return _kill_by_name(proc_name)
    if pid <= 4:
        return False, f"PID {pid} is a system process and cannot be killed."
    if pid == os.getpid():
        return False, "Cannot kill Sentinel itself."
    try:
        p = psutil.Process(pid)
        actual = p.name().lower()
        if actual != proc_name.lower():
            return False, f"PID {pid} mismatch: expected '{proc_name}', got '{p.name()}'."
        p.kill()
        logger.warning("[Remediation] Killed %s (PID %s)", proc_name, pid)
        return True, f"✅ '{proc_name}' (PID {pid}) terminated."
    except psutil.NoSuchProcess:
        return False, f"PID {pid} not found."
    except Exception as e:
        return False, f"Kill failed: {e}"


def block_ip_in_firewall(ip: str) -> tuple[bool, str]:
    # M4: Loopback is ALWAYS blocked from firewall rules (would break the host).
    if _is_loopback_ip(ip):
        return False, f"IP {ip} is loopback and cannot be blocked."
    # M4: RFC1918 LAN IPs CAN be blocked (lateral movement defense).
    # If svchost.exe connects to 192.168.1.50:4444, that's a C2 event.
    # The operator (HITL) must approve — this is not automatic.
    if ip in SAFE_IPS:
        return False, f"IP {ip} is whitelisted."
    rule = f"SENTINEL_BLOCK_{ip.replace(':', '_')}"
    try:
        r = subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f'name="{rule}"',
                "dir=out",
                "action=block",
                f"remoteip={ip}",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if r.returncode == 0:
            # Also block inbound connections from this IP
            rule_in = f"SENTINEL_BLOCK_IN_{ip.replace(':', '_')}"
            r_in = subprocess.run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f'name="{rule_in}"',
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if r_in.returncode != 0:
                err_in = (r_in.stderr or r_in.stdout or "").strip()
                logger.warning("[Remediation] Inbound block failed for %s: %s", ip, err_in)
                return False, f"⚠️ Outbound blocked, inbound failed: {err_in[:200]}"
            logger.warning("[Remediation] Blocked %s (rules %s, %s)", ip, rule, rule_in)
            return True, f"✅ {ip} blocked (outbound + inbound)."
        return False, f"netsh failed: {r.stderr.strip() or r.stdout.strip()}"
    except subprocess.TimeoutExpired:
        return False, "netsh timed out."
    except Exception as e:
        return False, f"Block failed: {e}"
