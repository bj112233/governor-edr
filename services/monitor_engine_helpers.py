"""Monitor engine helpers — network analysis + disk check.

Extracted from monitor_engine.py to reduce get_system_snapshot from D(26).
"""

import asyncio
import ipaddress
import logging
import socket
from typing import Any

import psutil

from config import is_ip_whitelisted
from services.device_registry import load_registry

logger = logging.getLogger(__name__)

_BROWSER_PROCS = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "msedgewebview2.exe",
}
_STANDARD_WEB_PORTS = {80, 443, 8080, 8443}

_KNOWN_GOOD_ASNS = {
    "15169",
    "16509",
    "8075",
    "13335",
    "20940",
    "54113",
    "32934",
    "36459",
    "14618",
    "174",
    "7922",
    "7018",
    "701",
    "3356",
}
_KNOWN_GOOD_ORGS = {
    "google",
    "microsoft",
    "amazon",
    "aws",
    "cloudfront",
    "cloudflare",
    "akamai",
    "fastly",
    "github",
    "facebook",
    "apple",
    "oracle",
    "cognition",
}
_WHITELISTED_NET_PROCS = {
    "devin.exe",
    "language_server_windows_x64.exe",
    "language_server.exe",
    "windsurf.exe",
    "code.exe",
    "cursor.exe",
    "svchost.exe",
    "services.exe",
    "lsass.exe",
    "mpdefendercoreservice.exe",
    "msmpeng.exe",
    "mpcmdrun.exe",
    "securityhealthservice.exe",
    "smartscreen.exe",
    "whatsapp.root.exe",
}

# WhatsApp Desktop → Facebook/Meta on XMPP port 5222.
# psutil.net_connections() returns pid=None for these on Windows
# without admin/service privileges, so proc_name arrives as "unknown".
# Filter by port + Facebook ASN to stop the recurring alert bleed.
_MESSAGING_XMPP_PORTS = {5222}
_FACEBOOK_ASN = "32934"
# Static BGP-announced fallback for AS32934 (Facebook/Meta). Live ASN/org
# enrichment goes through ip-api.com with a 2s timeout and can silently
# fail for IPv6 lookups — when it does, asn/org come back None and the
# ASN/org check above never fires, letting the connection bleed through
# as a false "non-standard port" alert. This CIDR is stable regardless.
_FACEBOOK_IPV6_NET = ipaddress.ip_network("2a03:2880::/32")


def is_whitelisted(ip: str) -> bool:
    return is_ip_whitelisted(ip)


def is_browser_connection(proc_name: str, port: int) -> bool:
    return proc_name.lower() in _BROWSER_PROCS and port in _STANDARD_WEB_PORTS


def _is_messaging_xmpp_to_facebook(port: int, asn: str | None, org: str | None, ip: str = "") -> bool:
    """Filter WhatsApp Desktop XMPP traffic to Facebook/Meta on port 5222.

    On Windows without admin privileges, psutil.net_connections() returns
    pid=None for WhatsApp's connections, making proc_name='unknown'.
    This bypass filters by port + ASN so the alert bleed stops regardless
    of whether the process name was resolved. Falls back to a static
    Facebook IPv6 CIDR when live ASN/org enrichment is unavailable
    (ip-api.com timeout/failure for that IP).
    """
    if port not in _MESSAGING_XMPP_PORTS:
        return False
    asn_str = str(asn).strip().upper().lstrip("AS") if asn else ""
    if asn_str == _FACEBOOK_ASN:
        return True
    org_lower = (org or "").lower()
    if "facebook" in org_lower or "meta" in org_lower:
        return True
    if ip:
        try:
            return ipaddress.ip_address(ip) in _FACEBOOK_IPV6_NET
        except ValueError:
            return False
    return False


def _is_known_good_asn(asn: str | None, org: str | None) -> bool:
    if asn:
        asn_str = str(asn).strip().upper().lstrip("AS")
        if asn_str in _KNOWN_GOOD_ASNS:
            return True
    if org:
        org_lower = org.lower()
        if any(k in org_lower for k in _KNOWN_GOOD_ORGS):
            return True
    return False


async def _enrich_ips(unique_ips: set[str], cache: dict[str, dict]) -> dict[str, dict]:
    """Parallel enrichment for a batch of IPs (reverse DNS + lightweight ASN)."""
    import requests

    async def _reverse(ip: str) -> tuple[str, list[str], list[str]] | None:
        try:
            return await asyncio.to_thread(socket.gethostbyaddr, ip)
        except Exception:
            return None

    rev_tasks = {ip: asyncio.create_task(_reverse(ip)) for ip in unique_ips}
    rev_results = {ip: r[0] if (r := await t) else None for ip, t in rev_tasks.items()}

    async def _asn(ip: str) -> tuple[str | None, str | None]:
        if ip in cache:
            cached = cache[ip]
            return cached.get("asn"), cached.get("org")
        try:
            r = await asyncio.to_thread(
                requests.get,
                f"http://ip-api.com/json/{ip}?fields=as,org,isp,query",
                timeout=2.0,
            )
            if r.status_code == 200:
                data = r.json()
                raw_as = data.get("as", "")
                asn = raw_as.split()[0].lstrip("AS") if raw_as else None
                org = data.get("org") or data.get("isp")
                return asn, org
        except Exception:
            pass
        return None, None

    asn_tasks = {ip: asyncio.create_task(_asn(ip)) for ip in unique_ips}
    for ip, t in asn_tasks.items():
        asn, org = await t
        cache[ip] = {"hostname": rev_results.get(ip), "asn": asn, "org": org}
    return cache


def _get_proc_names(pid_set: set[int]) -> dict[int, str]:
    """Batch resolve process names for a set of PIDs."""
    names: dict[int, str] = {}
    for pid in pid_set:
        try:
            names[pid] = psutil.Process(pid).name()
        except psutil.NoSuchProcess:
            names[pid] = "unknown"
        except psutil.AccessDenied:
            names[pid] = "unknown"
            logger.debug(
                "[NetMonitor] AccessDenied resolving PID %d — "
                "consider running Sentinel as a Windows Service for full network stack visibility.",
                pid,
            )
    return names


def _collect_candidates(
    connections,
    registry: dict[str, dict],
) -> tuple[list[tuple[str, int, int | None]], set[int]]:
    """Filter established non-whitelisted connections → (candidates, pids)."""
    candidates: list[tuple[str, int, int | None]] = []
    pids: set[int] = set()
    for c in connections:
        if c.status != "ESTABLISHED" or not c.raddr:
            continue
        ip = c.raddr.ip
        if is_whitelisted(ip) or ip in registry:
            continue
        port = c.raddr.port
        pid = c.pid
        candidates.append((ip, port, pid))
        if pid:
            pids.add(pid)
    return candidates, pids


def _is_connection_filtered(
    pid: int | None,
    proc_name: str,
    port: int,
    ip: str,
    ip_cache: dict,
) -> bool:
    """Return True if a connection should be filtered out (not suspicious)."""
    from services.self_whitelist import is_self_process

    if is_self_process(pid, proc_name):
        return True
    if is_browser_connection(proc_name, port):
        return True
    enrichment = ip_cache.get(ip, {})
    asn = enrichment.get("asn")
    org = enrichment.get("org")
    if _is_messaging_xmpp_to_facebook(port, asn, org, ip=ip):
        return True
    if proc_name.lower() in _WHITELISTED_NET_PROCS and _is_known_good_asn(asn, org):
        return True
    return False


def _format_connection(
    ip: str,
    port: int,
    pid: int | None,
    proc_name: str,
    ip_cache: dict,
) -> str:
    """Format a suspicious connection as a display string."""
    enrichment = ip_cache.get(ip, {})
    asn = enrichment.get("asn")
    org = enrichment.get("org")
    addr_display = f"[{ip}]:{port}" if ip.count(":") > 1 else f"{ip}:{port}"
    meta_parts = [p for p in (org, f"AS{asn}" if asn else None) if p]
    meta = " / ".join(meta_parts) if meta_parts else "unknown provider"
    return f"{addr_display} ({meta}) ({proc_name}:{pid or '?'})"


async def _collect_suspicious_net(connections, _ip_cache: dict) -> tuple[list[str], int]:
    """Collect suspicious network connections with enrichment.

    Returns (suspicious_net_lines, self_filtered_count) where
    self_filtered_count is the number of Sentinel/KoboldCpp connections
    that were self-whitelisted (used for connection-storm detection).
    """
    registry = await asyncio.to_thread(load_registry)

    candidates, pids = _collect_candidates(connections, registry)
    proc_names = await asyncio.to_thread(_get_proc_names, pids)

    unique_ips = {ip for ip, _, _ in candidates}
    if unique_ips:
        await _enrich_ips(unique_ips, _ip_cache)

    suspicious_net: list[str] = []
    self_filtered = 0
    null_pid_count = 0
    for ip, port, pid in candidates:
        if not pid:
            null_pid_count += 1
        proc_name = proc_names.get(pid, "unknown") if pid else "unknown"
        if _is_connection_filtered(pid, proc_name, port, ip, _ip_cache):
            self_filtered += 1
            continue
        suspicious_net.append(_format_connection(ip, port, pid, proc_name, _ip_cache))

    if self_filtered:
        logger.info("[NetMonitor] Self-whitelisted %d Sentinel/KoboldCpp connections.", self_filtered)

    if null_pid_count:
        logger.warning(
            "[NetMonitor] %d connection(s) had pid=None — psutil.net_connections() "
            "cannot resolve PIDs without admin/service privileges on Windows. "
            "Process names for these connections are 'unknown'.",
            null_pid_count,
        )

    return suspicious_net, self_filtered


async def _check_disks() -> list[str]:
    """Check all disk partitions for usage above threshold."""
    from config import DISK_THRESHOLD

    partitions = await asyncio.to_thread(psutil.disk_partitions, all=False)

    async def check_single_partition(part) -> str:
        try:
            usage = await asyncio.to_thread(psutil.disk_usage, part.mountpoint)
            if usage.percent > DISK_THRESHOLD:
                return f"{part.device} {usage.percent:.0f}%"
        except (PermissionError, OSError):
            pass
        return ""

    disk_results = await asyncio.gather(*(check_single_partition(part) for part in partitions))
    return [alert for alert in disk_results if alert]
