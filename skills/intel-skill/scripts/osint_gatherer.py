"""Intel Skill — OSINT Data Access Layer.

Async-unsafe (sync requests) because the original intel.py used requests.
All functions return JSON-ready dicts with 'available' flag.
Responsible only for: timeouts, rate-limit awareness, caching.
No scoring, no enrichment, no business logic.
"""

from __future__ import annotations

import os
from typing import Any

import requests
from _utils import cache_get, cache_set
from vt_rate_limiter import acquire as vt_acquire

_TIMEOUT = 3
_TIMEOUT_IPAPI = 5
_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")

_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
_VT_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
_SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")


def abuseipdb(ip: str) -> dict[str, Any]:
    """AbuseIPDB Check endpoint. Without a key, returns empty stub."""
    if not _ABUSEIPDB_KEY:
        return {"available": False, "reason": "ABUSEIPDB_API_KEY not set"}
    if (cached := cache_get("abuseipdb", ip)) is not None:
        return cached
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        result = {
            "available": True,
            "abuse_confidence": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "total_reports": d.get("totalReports", 0),
            "usage_type": d.get("usageType"),
        }
        cache_set("abuseipdb", ip, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def maltiverse_ip(ip: str) -> dict[str, Any]:
    """Query Maltiverse IP API (no auth). Returns classification + tags."""
    if (cached := cache_get("maltiverse_ip", ip)) is not None:
        return cached
    try:
        r = requests.get(
            f"https://api.maltiverse.com/ip/{ip}",
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result = {"available": True, "found": False, "classification": "unknown"}
            cache_set("maltiverse_ip", ip, result)
            return result
        if r.status_code == 429:
            return {
                "available": False,
                "reason": "Maltiverse rate limit (429). Retry later.",
            }
        r.raise_for_status()
        d = r.json()
        result = {
            "available": True,
            "found": True,
            "classification": d.get("classification", "unknown"),
            "blacklist_count": len(d.get("blacklist", [])),
            "tags": d.get("tag", []),
            "asn": d.get("asn"),
            "asn_cidr": d.get("asn_cidr"),
            "country_code": d.get("country_code"),
        }
        cache_set("maltiverse_ip", ip, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def maltiverse_hash(sha256: str) -> dict[str, Any]:
    """Query Maltiverse sample/hash API (no auth)."""
    if (cached := cache_get("maltiverse_hash", sha256)) is not None:
        return cached
    try:
        r = requests.get(
            f"https://api.maltiverse.com/sample/{sha256}",
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result = {"available": True, "found": False, "classification": "unknown"}
            cache_set("maltiverse_hash", sha256, result)
            return result
        if r.status_code == 429:
            return {
                "available": False,
                "reason": "Maltiverse rate limit (429). Retry later.",
            }
        r.raise_for_status()
        d = r.json()
        result = {
            "available": True,
            "found": True,
            "classification": d.get("classification", "unknown"),
            "score": d.get("score"),
            "type": d.get("type"),
            "tags": d.get("tag", []),
        }
        cache_set("maltiverse_hash", sha256, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def virustotal(target: str, kind: str) -> dict[str, Any]:
    """VirusTotal v3 lookup. kind ∈ {ip_addresses, domains, files}.

    Rate-limited via disk-persisted token bucket (4 req/min free tier).
    429 responses return a structured fallback dict so callers can degrade
    gracefully to Maltiverse/AbuseIPDB without crashing enrichment.
    """
    if not _VT_KEY:
        return {"available": False, "reason": "VIRUSTOTAL_API_KEY not set"}
    cache_key = f"{kind}_{target}"
    if (cached := cache_get("virustotal", cache_key)) is not None:
        return cached
    # Token-bucket: blocks until a slot is available (cross-process safe)
    if not vt_acquire():
        return {
            "available": False,
            "error": "VirusTotal rate-limit bucket exhausted (timeout)",
            "fallback": True,
        }
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{kind}/{target}",
            headers={"x-apikey": _VT_KEY, "User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        if r.status_code == 404:
            result = {"available": True, "found": False}
            cache_set("virustotal", cache_key, result)
            return result
        if r.status_code == 429:
            # Server-side rate limit hit despite token bucket — degrade gracefully.
            # Do NOT cache (window may reset soon); caller falls back to other sources.
            retry_after = r.headers.get("Retry-After")
            return {
                "available": False,
                "error": "VirusTotal rate limit (4/min, 500/day)",
                "fallback": True,
                "retry_after": int(retry_after) if retry_after and retry_after.isdigit() else None,
            }
        r.raise_for_status()
        attr = (r.json().get("data") or {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        votes = attr.get("total_votes", {})
        result = {
            "available": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attr.get("reputation", 0),
            "community_score": attr.get("reputation", 0),
            "tags": attr.get("tags", []),
            "network_asn": str(attr.get("asn") or "")[:32],
            "network_as_owner": str(attr.get("as_owner") or "")[:64],
            "regional_internet_registry": attr.get("regional_internet_registry"),
            "last_analysis_date": attr.get("last_analysis_date"),
            "total_votes": {
                "harmless": votes.get("harmless", 0),
                "malicious": votes.get("malicious", 0),
            },
        }
        cache_set("virustotal", cache_key, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e), "fallback": True}


def ipapi_co(ip: str) -> dict[str, Any]:
    """ipapi.co lookup over HTTPS. No key required. 45K/month free.
    Returns proxy/VPN/TOR/hosting detection + ASN/ISP/location.
    """
    if (cached := cache_get("ipapi_co", ip)) is not None:
        return cached
    try:
        r = requests.get(
            f"https://ipapi.co/{ip}/json/",
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT_IPAPI,
        )
        r.raise_for_status()
        d = r.json()
        if d.get("error"):
            return {"available": False, "error": d["error"]}
        threat = d.get("threat", {})
        asn = d.get("asn")
        if isinstance(asn, str) and asn.upper().startswith("AS"):
            asn = asn[2:]
        result = {
            "available": True,
            "country": d.get("country_name"),
            "country_code": d.get("country_code"),
            "city": d.get("city"),
            "region": d.get("region"),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
            "asn": asn,
            "org": d.get("org"),
            "proxy": bool(threat.get("is_proxy")),
            "vpn": bool(threat.get("is_vpn")),
            "tor": bool(threat.get("is_tor")),
            "hosting": bool(threat.get("is_datacenter")),
        }
        cache_set("ipapi_co", ip, result)
        return result
    except Exception as e:
        return {"available": False, "error": f"{type(e).__name__}: {e}"}


def shodan(ip: str) -> dict[str, Any]:
    """Shodan host lookup. Requires SHODAN_API_KEY (free tier: 100 credits/month).
    Returns open ports, CVEs, OS, org, ASN, tags.
    """
    if not _SHODAN_KEY:
        return {
            "available": False,
            "reason": "SHODAN_API_KEY not set. Add it to .env or system env vars.",
        }
    if (cached := cache_get("shodan", ip)) is not None:
        return cached
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={_SHODAN_KEY}",
            headers={"User-Agent": _UA},
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json()
        vulns = list(d.get("vulns", {}).keys()) if d.get("vulns") else []
        ports = [m.get("port") for m in d.get("data", []) if m.get("port")]
        result = {
            "available": True,
            "ports": sorted(set(ports)),
            "os": d.get("os"),
            "org": d.get("org"),
            "isp": d.get("isp"),
            "asn": d.get("asn"),
            "hostnames": d.get("hostnames", []),
            "tags": d.get("tags", []),
            "vulns": vulns,
            "vuln_count": len(vulns),
            "last_update": d.get("last_update"),
        }
        cache_set("shodan", ip, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def cert_il_feed() -> dict[str, Any]:
    """CERT-IL threat feed — delegates to cert_il_feed module (RSS + IOC extraction)."""
    from cert_il_feed import cert_il_feed as _cert_il_feed

    return _cert_il_feed()


def urlhaus_feed(limit: int = 100) -> dict[str, Any]:
    """URLhaus threat feed — delegates to urlhaus_feed module (CSV + IOC extraction)."""
    from urlhaus_feed import fetch_urlhaus_csv, extract_urlhaus_iocs

    rows = fetch_urlhaus_csv(limit)
    iocs = extract_urlhaus_iocs(rows)
    return {
        "available": True,
        "count": len(rows),
        "iocs": {k: sorted(v) for k, v in iocs.items()},
    }


def threatfox_feed(days: int = 1) -> dict[str, Any]:
    """ThreatFox threat feed — delegates to threatfox_feed module (JSON + IOC extraction)."""
    from threatfox_feed import fetch_threatfox_iocs, extract_threatfox_iocs

    rows = fetch_threatfox_iocs(days)
    extracted = extract_threatfox_iocs(rows)
    return {
        "available": True,
        "count": len(rows),
        "iocs": {
            "urls": sorted(extracted["urls"]),
            "domains": sorted(extracted["domains"]),
            "ips": sorted(extracted["ips"]),
            "hashes": sorted(extracted["hashes"]),
        },
        "malware_map": extracted["malware_map"],
    }
