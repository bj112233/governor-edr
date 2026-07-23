# services/net_intel.py
"""Level 150: Network Intelligence Data Gatherer
אוסף נתוני רשת מתקדמים כטקסט גולמי לניתוח AI
"""

import logging

import psutil

from services.device_registry import load_registry
from services.monitor_engine import is_whitelisted
from services.net_parser import parse_ip_port

logger = logging.getLogger(__name__)


def _build_pid_name_map() -> dict[int, str]:
    """Build a pid→name mapping once to avoid O(n²) Process(pid) lookups."""
    mapping: dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            mapping[proc.info["pid"]] = proc.info["name"] or "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return mapping


def get_listening_ports_raw() -> str:
    """מחזיר פורטים מאזינים (LISTEN) עם שם תהליך"""
    lines = []
    pid_map = _build_pid_name_map()
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN:
            continue
        pid = conn.pid or 0
        proc_name = pid_map.get(pid, "System" if pid == 0 else "Restricted")
        proto = "TCP" if conn.type == 1 else "UDP"
        # Robust IP:Port parsing (IPv6 bracket support)
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
        l_ip, l_port = parse_ip_port(laddr_str)
        l_ip = l_ip or conn.laddr.ip
        l_port = l_port or conn.laddr.port
        lines.append(f"PORT={l_port} | {proto} | ADDR={l_ip} | PID={pid} | PROCESS={proc_name}")
    return "\n".join(lines) if lines else "No listening ports found."


def get_external_connections_raw() -> str:
    """מחזיר חיבורים ESTABLISHED לכתובות חיצוניות (לא ב-whitelist ולא ב-registry)"""
    registry = load_registry()
    lines = []
    pid_map = _build_pid_name_map()
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        if is_whitelisted(conn.raddr.ip) or conn.raddr.ip in registry:
            continue
        pid = conn.pid or 0
        proc_name = pid_map.get(pid, "Unknown" if pid else "System")
        # Robust IP:Port parsing for both IPv4 and IPv6
        raddr_str = f"{conn.raddr.ip}:{conn.raddr.port}"
        r_ip, r_port = parse_ip_port(raddr_str)
        r_ip = r_ip or conn.raddr.ip
        r_port = r_port or conn.raddr.port
        laddr_str = f"{conn.laddr.ip}:{conn.laddr.port}"
        l_ip, l_port = parse_ip_port(laddr_str)
        l_ip = l_ip or conn.laddr.ip
        l_port = l_port or conn.laddr.port
        lines.append(f"{proc_name} (PID={pid}) | {l_ip}:{l_port} -> {r_ip}:{r_port}")
    return "\n".join(lines) if lines else "No external connections detected."
