# services/net_noise_filter.py
"""Shared benign-connection suppression — Single Source of Truth.

Used by BOTH detection paths:
  1. SnapshotDiffer._diff_connections (alert path)
  2. threat_hunter hunt context (LLM prompt + IOC enrichment path)

Before this module, the hunt path injected raw suspicious_net lines into the
LLM prompt, bypassing every filter the differ already applied — known cloud
CIDRs, behavioral allowlist, learned baseline, and intel whitelist. The LLM
then hallucinated "Lateral Movement" from routine Windows→Azure telemetry.
All new files < 300 lines (SRP).
"""

import ipaddress
import logging
import re

from services.behavioral_filter import is_expected_network_behavior
from services.net_baseline import is_intel_whitelisted, is_known_combo
from services.net_parser import parse_ip_port
from services.self_whitelist import is_self_process_by_name

logger = logging.getLogger(__name__)

# Known CDN / cloud provider networks that generate noise alerts.
# Multi-tenant cloud ranges: an "abusive" IP here is recycled across
# thousands of customers — membership alone carries zero threat signal.
_CDN_NETWORKS = [
    ipaddress.ip_network("2a04:4e42::/32"),  # Fastly
    ipaddress.ip_network("2001:4cd0::/32"),  # Cloudflare
    ipaddress.ip_network("2600:1900::/28"),  # Google Cloud
    ipaddress.ip_network("2600:1901::/32"),  # Google Cloud (secondary)
    ipaddress.ip_network("143.204.0.0/16"),  # AWS CloudFront
    ipaddress.ip_network("2606:4700::/32"),  # Cloudflare IPv6
    ipaddress.ip_network("2404:6800::/32"),  # Google
    ipaddress.ip_network("2a00:1450::/32"),  # Google
    ipaddress.ip_network("48.0.0.0/8"),  # Prudential (false-positive)
    ipaddress.ip_network("2600:1400::/24"),  # Akamai IPv6 (ARIN)
    ipaddress.ip_network("13.64.0.0/11"),  # Microsoft Azure (13.64-13.95)
    ipaddress.ip_network("13.104.0.0/14"),  # Microsoft Azure (13.104-13.107)
    ipaddress.ip_network("20.0.0.0/8", strict=False),  # Microsoft Azure
    ipaddress.ip_network("40.0.0.0/8", strict=False),  # Microsoft Azure (secondary)
    ipaddress.ip_network("2603:1046::/32", strict=False),  # Microsoft Azure IPv6
    ipaddress.ip_network("2603:1030::/28", strict=False),  # Microsoft Corporation IPv6
]

_PAREN_GROUP_RE = re.compile(r"\(([^)]+)\)")


def is_cdn_whitelisted_ip(ip: str) -> bool:
    """Return True if IP belongs to a known CDN / cloud provider."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _CDN_NETWORKS)
    except ValueError:
        return False


def parse_conn_line(line: str) -> tuple[str, str, int, int | None] | None:
    """Parse one suspicious_net line into (ip, proc_name, remote_port, pid).

    Line format: '[ip]:port (org / AS123) (proc_name:pid)'.
    The proc_name:pid is always the LAST parenthesized group.
    Returns None if the line is unparseable. PID is None if not parseable.
    """
    if not line or "(" not in line or ")" not in line:
        return None
    try:
        ip_part = line.split(" ")[0]
        paren_groups = _PAREN_GROUP_RE.findall(line)
        if not paren_groups:
            return None
        proc_part = paren_groups[-1]  # last group = proc_name:pid
        ip, port = parse_ip_port(ip_part)
        if not ip or not port:
            return None
        proc_name = proc_part.split(":")[0] if ":" in proc_part else "unknown"
        pid: int | None = None
        if ":" in proc_part:
            try:
                pid = int(proc_part.split(":")[1])
            except (ValueError, IndexError):
                pass
        return (ip, proc_name, int(port), pid)
    except (ValueError, IndexError):
        return None


async def suppression_reason(proc_name: str, ip: str, port: int, pid: int | None = None) -> str | None:
    """Return the suppression reason if this connection is known-benign, else None.

    Filter chain (mirrors SnapshotDiffer Phases 7-9):
      cdn_whitelist → self_process → expected_behavior → learned_baseline → intel_whitelist
    DB-backed checks fail-open: on lookup error the connection is NOT suppressed.

    H1 fix: When PID is available, uses full 4-layer self-process
    verification (path + lineage + hash) instead of name-only check.
    Fails open to name-only if PID is None or verification raises.
    """
    if is_cdn_whitelisted_ip(ip):
        return "cdn_whitelist"
    # H1: Use full PID-based verification when available, fall back to name-only
    if pid is not None and pid > 0:
        try:
            from services.self_whitelist import is_self_process

            if is_self_process(pid, proc_name):
                return "self_process"
        except Exception:
            pass  # fail-open to name-only check below
    if is_self_process_by_name(proc_name):
        return "self_process"
    if is_expected_network_behavior(proc_name, port, pid):
        return "expected_behavior"
    try:
        if await is_known_combo(proc_name, ip, port):
            return "learned_baseline"
    except Exception:
        pass  # Fail-open: if baseline lookup fails, emit the alert
    try:
        if await is_intel_whitelisted(ip):
            return "intel_whitelist"
    except Exception:
        pass
    return None


async def apply_snapshot_noise_filter(snapshot: dict) -> None:
    """Filter snapshot['suspicious_net'] — tag benign conns, don't delete.

    Physical law: "A clean network signature does NOT cancel a malicious
    behavioral signature." (C1+C2 fix)

    Instead of one-way deletion, suppressed connections are preserved in
    snapshot['filtered_net'] with their suppression reason. The Behavioral
    Escape Hatch (behavioral_escape_hatch.py) reads both suspicious_net
    AND filtered_net — if local behavior is anomalous (4+ signals), the
    filtered connections are the prime C2 suspects (cloud-hosted C2 is
    invisible to IOC enrichment but visible to behavioral analysis).

    The LLM still only sees suspicious_net (no hallucination on cloud
    telemetry). filtered_net is consumed by the deterministic scoring
    layer only.
    """
    raw_net = snapshot.get("suspicious_net", [])
    if not raw_net:
        return
    survivors, suppressed = await filter_benign_conns_tagged(raw_net)
    snapshot["suspicious_net"] = survivors
    snapshot["filtered_net"] = suppressed
    if suppressed:
        logger.info(
            "[NetNoiseFilter] Tagged %d/%d benign connection(s) as filtered_net "
            "(available to Behavioral Escape Hatch, hidden from LLM).",
            len(suppressed),
            len(raw_net),
        )


async def filter_benign_conns(suspicious_net: list[str]) -> list[str]:
    """Return only the suspicious_net lines that survive the benign filter chain.

    Unparseable lines are KEPT (fail-open) — a malformed line must not become
    an invisibility cloak. Used by the threat hunter so the LLM never sees
    known-benign OS/cloud telemetry (no data → no hallucination).
    """
    survivors, _ = await filter_benign_conns_tagged(suspicious_net)
    return survivors


async def filter_benign_conns_tagged(
    suspicious_net: list[str],
) -> tuple[list[str], list[dict]]:
    """Split suspicious_net into (survivors, suppressed_metadata).

    Returns:
        survivors: lines that passed the filter (shown to LLM).
        suppressed: list of {line, reason, ip, proc_name, port} dicts
                    for Behavioral Escape Hatch analysis (NOT shown to LLM).
    """
    survivors: list[str] = []
    suppressed: list[dict] = []
    for line in suspicious_net:
        conn = parse_conn_line(line)
        if conn is None:
            survivors.append(line)
            continue
        ip, proc_name, port, pid = conn
        reason = await suppression_reason(proc_name, ip, port, pid)
        if reason:
            logger.debug(
                "[NetNoiseFilter] Suppressing benign conn (%s): %s -> %s:%d",
                reason,
                proc_name,
                ip,
                port,
            )
            suppressed.append(
                {
                    "line": line,
                    "reason": reason,
                    "ip": ip,
                    "proc_name": proc_name,
                    "port": port,
                }
            )
            continue
        survivors.append(line)
    return survivors, suppressed
