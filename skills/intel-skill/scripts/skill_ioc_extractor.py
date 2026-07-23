"""Skill-level IOC extractor — imports patterns from skills/_shared/ioc_patterns.py.

Single Source of Truth: regex patterns live in _shared/ioc_patterns.py (Pure Python,
zero deps). This module adds skill-specific aggregation logic (dedup, filtering).

Supports ALL 9 IOC types: CVE, IPv4, IPv6, domains, URLs, hashes, CIDRs, ASNs, emails.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ── Dynamic sys.path injection (survives subprocess execution) ──
# scripts/ → intel-skill/ → skills/ → _shared/
_SHARED_DIR = str(Path(__file__).resolve().parent.parent.parent / "_shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)

from ioc_patterns import (  # noqa: E402
    ASN_RE,
    CIDR_RE,
    CVE_RE,
    DOMAIN_RE,
    EMAIL_RE,
    HASH_RE,
    IPV4_RE,
    IPV6_RE,
    URL_RE,
    URL_TRAILING_PUNCT,
)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def _strip_url_trailing(url: str) -> str:
    while url and url[-1] in URL_TRAILING_PUNCT:
        url = url[:-1]
    return url


def _is_ipv4_like(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() for p in parts)


def _validate_cidr(value: str) -> bool:
    try:
        import ipaddress

        net = ipaddress.ip_network(value, strict=False)
        return net.prefixlen <= 32 and net.version == 4
    except ValueError:
        return False


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Extract all IOC types from text.

    Returns dict with: cves, ips_v4, ips_v6, domains, urls, hashes, cidrs, asns, emails.
    """
    if not text:
        return {
            "cves": [], "ips_v4": [], "ips_v6": [], "domains": [],
            "urls": [], "hashes": [], "cidrs": [], "asns": [], "emails": [],
        }

    cves = [c.upper() for c in CVE_RE.findall(text)]
    ips_v4 = [ip for ip in IPV4_RE.findall(text) if not ip.startswith("0.")]
    ips_v6 = IPV6_RE.findall(text)
    urls = [_strip_url_trailing(u) for u in URL_RE.findall(text)]
    hashes = list(HASH_RE.findall(text))
    cidrs = [c for c in CIDR_RE.findall(text) if _validate_cidr(c)]
    asns = [a.upper() for a in ASN_RE.findall(text)]
    emails = list(EMAIL_RE.findall(text))

    # Domains — filter IPv4-like and protocol prefixes
    # Note: BAD_DOMAINS filtering intentionally NOT applied here (skill-level)
    # to match original behavior — domains like "evil.com" must be preserved
    # for feed matching. The services-level extractor applies stricter filtering.
    domains = []
    for d in DOMAIN_RE.findall(text):
        parts = d.split(".")
        if len(parts) < 2:
            continue
        if all(p.isdigit() for p in parts):
            continue
        if parts[0] in ("http", "https", "ftp", "sftp"):
            continue
        domains.append(d)

    return {
        "cves": _dedupe(cves),
        "ips_v4": _dedupe(ips_v4),
        "ips_v6": _dedupe(ips_v6),
        "domains": _dedupe(domains),
        "urls": _dedupe(urls),
        "hashes": _dedupe(hashes),
        "cidrs": _dedupe(cidrs),
        "asns": _dedupe(asns),
        "emails": _dedupe(emails),
    }
