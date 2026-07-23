"""IOC aggregator — merges DNS + TLS results into unified IOC JSON for intel-skill.

Output protocol (shared across all 3 Visibility Triad skills):
  {
    "iocs": {"domains": [...], "ips": [...], "urls": [...], "hashes": [...]},
    "source": "pcap-analyst",
    "chain_to": "intel-skill"
  }

Triage layer: filter_private_ips + filter_benign_domains + top_k_triage
applied before JSON output to prevent intel-skill rate-limit exhaustion.
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any

# ── Dynamic sys.path injection (survives subprocess execution) ──
# scripts/ → pcap-analyst/ → skills/ → _shared/
_SHARED_DIR = str(Path(__file__).resolve().parent.parent.parent / "_shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)

from ioc_triage import (  # noqa: E402
    filter_benign_domains,
    filter_private_ips,
    generate_triage_report,
    top_k_triage,
)

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

_TOP_K = 15  # aligns with VT rate limit (4 req/min → ~4 min background processing)


def _is_ip(value: str) -> bool:
    """True if value is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    """True if value looks like a domain (has a dot, not an IP, not a CNAME suffix)."""
    if _is_ip(value):
        return False
    if "." not in value:
        return False
    # Filter out DNS answer types that aren't domains/IPs (e.g. "0" from TXT)
    if value.isdigit():
        return False
    return bool(_IPV4_RE.match(value) is None) and "." in value


def aggregate_to_iocs(dns_result: dict[str, Any], tls_result: dict[str, Any]) -> dict[str, Any]:
    """Merge DNS queries/answers + TLS SNI into a unified, triaged IOC dict.

    Triage pipeline (deterministic, before JSON output):
      1. Collect raw domains + IPs from DNS queries/answers + TLS SNI
      2. filter_private_ips — drop RFC1918/loopback/link-local
      3. filter_benign_domains — drop known-legitimate roots (Microsoft, Google, etc.)
      4. top_k_triage — cap at _TOP_K IOCs to prevent intel-skill rate-limit exhaustion
    """
    raw_domains: set[str] = set()
    raw_ips: set[str] = set()

    # From DNS queries (always domains)
    for q in dns_result.get("queries", set()):
        if _is_ip(q):
            raw_ips.add(q)
        elif _is_domain(q):
            raw_domains.add(q)

    # From DNS answers (can be IPs or domains — CNAME chains)
    for a in dns_result.get("answers", set()):
        if _is_ip(a):
            raw_ips.add(a)
        elif _is_domain(a):
            raw_domains.add(a)

    # From TLS SNI (always domains)
    for s in tls_result.get("sni", set()):
        if _is_domain(s):
            raw_domains.add(s)

    # ── Triage: deterministic filtering before enrichment ──
    original_count = len(raw_domains) + len(raw_ips)
    filtered_ips = filter_private_ips(sorted(raw_ips))
    filtered_domains = filter_benign_domains(sorted(raw_domains))
    filtered_count = len(filtered_domains) + len(filtered_ips)

    # Top-K selection (frequency=1 for all since collectors use set())
    # Sort alphabetically for deterministic output, then take top-K
    ip_counts = {ip: 1 for ip in filtered_ips}
    domain_counts = {d: 1 for d in filtered_domains}
    selected_ips = top_k_triage(ip_counts, k=_TOP_K)
    selected_domains = top_k_triage(domain_counts, k=_TOP_K)
    selected_count = len(selected_ips) + len(selected_domains)

    triage_report = generate_triage_report(original_count, filtered_count, selected_count)

    return {
        "iocs": {
            "domains": selected_domains,
            "ips": selected_ips,
            "urls": [],
            "hashes": [],
        },
        "source": "pcap-analyst",
        "chain_to": "intel-skill",
        "stats": {
            "dns_packets": dns_result.get("packet_count", 0),
            "tls_packets": tls_result.get("packet_count", 0),
            "raw_domains": len(raw_domains),
            "raw_ips": len(raw_ips),
            "filtered_domains": len(filtered_domains),
            "filtered_ips": len(filtered_ips),
            "selected_total": selected_count,
        },
        "triage": triage_report,
    }


def render_ioc_json(iocs: dict[str, Any]) -> str:
    """Render IOC dict as compact JSON string for intel-skill chaining."""
    return json.dumps(iocs, ensure_ascii=False, separators=(",", ":"))
