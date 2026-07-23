"""
IOC Triage Module
Provides deterministic filtering for IOCs before LLM enrichment to prevent
API rate limits and context bloat.

Must not import any layer from services/ to maintain strict skill isolation.
"""

import ipaddress
from typing import Dict, List

# Known benign domain roots (kept independent for SRP — no services/ import)
_BENIGN_DOMAINS = frozenset(
    [
        "microsoft.com",
        "windows.com",
        "office365.com",
        "live.com",
        "msft.net",
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "youtube.com",
        "amazonaws.com",
        "amazon.com",
        "cloudfront.net",
        "apple.com",
        "icloud.com",
        "cloudflare.com",
        "akamai.com",
        "akamaized.net",
        "github.com",
        "githubusercontent.com",
        "telegram.org",
        "t.me",
        "mozilla.org",
        "firefox.com",
        "wikipedia.org",
        "stackoverflow.com",
    ]
)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP is RFC1918, loopback, or link-local."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def filter_private_ips(ips: list[str]) -> list[str]:
    """Return only public IPs from the given list."""
    if not ips:
        return []
    return [ip for ip in ips if not _is_private_ip(ip)]


def _is_benign_domain(domain_str: str) -> bool:
    """Check if a domain is a subdomain of a known benign root."""
    domain_str = domain_str.lower().strip()
    for benign in _BENIGN_DOMAINS:
        if domain_str == benign or domain_str.endswith("." + benign):
            return True
    return False


def filter_benign_domains(domains: list[str]) -> list[str]:
    """Return only domains that are not explicitly trusted."""
    if not domains:
        return []
    return [d for d in domains if not _is_benign_domain(d)]


def top_k_triage(ioc_counts: dict[str, int], k: int = 15) -> list[str]:
    """
    Select top K IOCs based on count (frequency descending).

    Assumes benign noise is already filtered by filter_private_ips +
    filter_benign_domains. k=15 aligns with VT rate limit (4 req/min →
    ~4 min background processing for a deep hunt).
    """
    if not ioc_counts:
        return []
    sorted_iocs = sorted(ioc_counts.items(), key=lambda item: item[1], reverse=True)
    return [ioc for ioc, count in sorted_iocs[:k]]


def generate_triage_report(original_count: int, filtered_count: int, selected_count: int) -> str:
    """Generate a standard triage markdown string for the LLM."""
    if original_count == 0:
        return ""
    dropped = original_count - filtered_count
    return (
        f"\n\n> 📊 **Triage Report**: Extracted {original_count} raw IOCs. "
        f"Filtered out {dropped} (private/benign). "
        f"Selected top {selected_count} for analysis."
    )
