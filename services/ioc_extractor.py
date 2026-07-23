# services/ioc_extractor.py
"""IOC Extraction Engine — 'Nimrod'.

Parses raw text / snippets for threat intelligence indicators:
IPv4, IPv6, domains, file hashes, CVE identifiers.

Returns structured, deduplicated dict for downstream AI and alerting.
All new files < 300 lines (SRP).

Regex patterns imported from skills/_shared/ioc_patterns.py (Single Source of Truth).
Aggregation logic (dedup, filtering, validation) stays here.
"""

import logging
import re
from pathlib import Path

# ── Single Source of Truth: import pre-compiled regex from shared module ──
_SHARED_DIR = str(Path(__file__).resolve().parent.parent / "skills" / "_shared")
import sys

if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)

from ioc_patterns import (  # noqa: E402
    ASN_RE as _ASN_RE,
)
from ioc_patterns import (
    BAD_DOMAINS as _BAD_DOMAINS,
)
from ioc_patterns import (
    CIDR_RE as _CIDR_RE,
)
from ioc_patterns import (
    CVE_RE as _CVE_RE,
)
from ioc_patterns import (
    DOMAIN_RE as _DOMAIN_RE,
)
from ioc_patterns import (
    EMAIL_RE as _EMAIL_RE,
)
from ioc_patterns import (
    HASH_RE as _HASH_RE,
)
from ioc_patterns import (
    IPV4_RE as _IPV4_RE,
)
from ioc_patterns import (
    IPV6_RE as _IPV6_RE,
)
from ioc_patterns import (
    URL_RE as _URL_RE,
)
from ioc_patterns import (
    URL_TRAILING_PUNCT as _URL_TRAILING_PUNCT,
)

logger = logging.getLogger(__name__)


def _is_ipv4_like(value: str) -> bool:
    """Return True if value looks like an IPv4 address (all parts numeric)."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() for p in parts)


def _validate_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4 CIDR with prefix 0..32."""
    try:
        import ipaddress

        net = ipaddress.ip_network(value, strict=False)
        return net.prefixlen <= 32 and net.version == 4
    except ValueError:
        return False


def _strip_url_trailing(url: str) -> str:
    """Strip prose punctuation glued to URL tail (preserve query/fragment)."""
    while url and url[-1] in _URL_TRAILING_PUNCT:
        url = url[:-1]
    return url


def _dedupe(values: list[str]) -> list[str]:
    """Preserve order, case-normalise hashes/CVEs, keep first occurrence."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        key = v.lower()
        if key not in seen:
            seen.add(key)
            out.append(v)
    return out


def extract_all(text: str) -> dict[str, list[str]]:
    """Extract all IOC indicators from raw text / HTML snippets.

    Returns:
        {
            "ips_v4":   ["1.2.3.4", ...],
            "ips_v6":   ["2001:db8::1", ...],
            "domains":  ["evil.com", ...],
            "hashes":   ["aabbcc...", ...],
            "cves":     ["CVE-2024-1234", ...],
            "urls":     ["https://evil.com/x?id=1", ...],
            "cidrs":    ["10.0.0.0/8", ...],
            "asns":     ["AS15169", ...],
            "emails":   ["a@b.com", ...],
        }
    """
    _empty: dict[str, list[str]] = {
        "ips_v4": [],
        "ips_v6": [],
        "domains": [],
        "hashes": [],
        "cves": [],
        "urls": [],
        "cidrs": [],
        "asns": [],
        "emails": [],
    }
    if not text:
        return _empty

    # IPv4
    raw_v4 = _IPV4_RE.findall(text)
    v4 = [ip for ip in raw_v4 if not ip.startswith("0.")]

    # IPv6
    raw_v6 = _IPV6_RE.findall(text)
    v6 = list(raw_v6)

    # Hashes
    raw_hashes = _HASH_RE.findall(text)
    hashes = list(raw_hashes)

    # CVEs — normalise to uppercase
    raw_cves = _CVE_RE.findall(text)
    cves = [c.upper() for c in raw_cves]

    # URLs — strip trailing prose punctuation, dedupe case-insensitively
    raw_urls = _URL_RE.findall(text)
    urls = [_strip_url_trailing(u) for u in raw_urls]

    # CIDRs — validate prefix range 0..32
    raw_cidrs = _CIDR_RE.findall(text)
    cidrs = [c for c in raw_cidrs if _validate_cidr(c)]

    # ASN — normalise to uppercase "AS123"
    raw_asns = _ASN_RE.findall(text)
    asns = [a.upper() for a in raw_asns]

    # Emails
    raw_emails = _EMAIL_RE.findall(text)
    emails = list(raw_emails)

    # Domains — filter false positives
    raw_domains = _DOMAIN_RE.findall(text)
    domains = []
    for d in raw_domains:
        if _is_ipv4_like(d):
            continue
        parts = d.lower().split(".")
        # Skip if TLD-only or if last part is a file extension
        if len(parts) < 2:
            continue
        # Defensive normalization: TLD must be alphabetic (not numeric like "9.2")
        # Prevents version numbers, decimal values, and log fragments from
        # being treated as domains and sent to VirusTotal/URLhaus.
        if not parts[-1].isalpha():
            continue
        if parts[-1] in _BAD_DOMAINS and len(parts) == 2:
            continue
        # Skip if looks like a protocol-prefixed fragment (http, https, ftp)
        if parts[0] in ("http", "https", "ftp", "sftp"):
            continue
        # Minimum TLD length (2 chars) — rejects single-char fragments
        if len(parts[-1]) < 2:
            continue
        domains.append(d)

    result = {
        "ips_v4": _dedupe(v4),
        "ips_v6": _dedupe(v6),
        "domains": _dedupe(domains),
        "hashes": _dedupe(hashes),
        "cves": _dedupe(cves),
        "urls": _dedupe(urls),
        "cidrs": _dedupe(cidrs),
        "asns": _dedupe(asns),
        "emails": _dedupe(emails),
    }

    total = sum(len(v) for v in result.values())
    if total:
        logger.info(
            "[IOCExtractor] Extracted %d indicators (v4=%d v6=%d dom=%d hash=%d cve=%d url=%d cidr=%d asn=%d email=%d)",
            total,
            len(result["ips_v4"]),
            len(result["ips_v6"]),
            len(result["domains"]),
            len(result["hashes"]),
            len(result["cves"]),
            len(result["urls"]),
            len(result["cidrs"]),
            len(result["asns"]),
            len(result["emails"]),
        )
    return result
