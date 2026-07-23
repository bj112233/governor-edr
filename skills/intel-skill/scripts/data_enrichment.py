"""Intel Skill — Data Enrichment Layer.

Local-only enrichment: DNS, RDAP/WHOIS, reverse DNS, Israeli heuristics.
No external network calls beyond RDAP (which is infrastructure lookup).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

import requests
from _utils import cache_get, cache_set

_TIMEOUT = 3
_UA = __import__("os").getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")

# ─────────────── Geo / ASN heuristics ───────────────

_KNOWN_GOOD_ASNS = {
    "15169",  # Google
    "16509",  # Amazon AWS
    "8075",   # Microsoft
    "13335",  # Cloudflare
    "20940",  # Akamai
    "54113",  # Fastly
    "32934",  # Facebook/Meta
    "36459",  # GitHub
    "14618",  # Amazon
    "174",    # Cogent
    "7922",   # Comcast
    "7018",   # AT&T
    "701",    # Verizon
    "3356",   # Level 3
}

_KNOWN_GOOD_ORGS = {
    "google", "microsoft", "amazon", "cloudflare", "akamai",
    "fastly", "github", "facebook", "apple", "oracle",
}

_HIGH_RISK_COUNTRIES = {"CN", "RU", "IR", "KP", "BY", "AF", "SY"}


def is_known_good_asn(asn: str | None, org: str | None) -> bool:
    """Heuristic: known-good CDN/cloud providers rarely need deep VT/Shodan."""
    if asn:
        asn_str = str(asn).strip().upper().lstrip("AS")
        if asn_str in _KNOWN_GOOD_ASNS:
            return True
    if org:
        org_lower = org.lower()
        if any(k in org_lower for k in _KNOWN_GOOD_ORGS):
            return True
    return False


def is_high_risk_country(cc: str | None) -> bool:
    return bool(cc and cc.upper() in _HIGH_RISK_COUNTRIES)


# ─────────────── DNS / WHOIS / Reverse DNS ───────────────


def dns_lookup(host: str) -> dict[str, Any]:
    """Resolve common record types. Uses dnspython if available, else socket A/AAAA."""
    out: dict[str, Any] = {"host": host}
    try:
        import dns.resolver  # type: ignore

        resolver = dns.resolver.Resolver()
        resolver.lifetime = _TIMEOUT
        for rtype in ("A", "AAAA", "MX", "TXT", "NS"):
            try:
                ans = resolver.resolve(host, rtype)
                out[rtype] = [r.to_text() for r in ans]
            except Exception:
                out[rtype] = []
    except ImportError:
        out["note"] = "dnspython not installed — only A records via socket"
        try:
            infos = socket.getaddrinfo(host, None)
            ips = sorted({i[4][0] for i in infos})
            out["A"] = [ip for ip in ips if ":" not in ip]
            out["AAAA"] = [ip for ip in ips if ":" in ip]
        except Exception as e:
            out["error"] = str(e)
    return out


def rdap(target: str) -> dict[str, Any]:
    """RDAP lookup via rdap.org redirector (works for IPs and domains)."""
    if (cached := cache_get("rdap", target)) is not None:
        return cached
    try:
        try:
            ipaddress.ip_address(target)
            kind = "ip"
        except ValueError:
            kind = "domain"
        r = requests.get(
            f"https://rdap.org/{kind}/{target}",
            headers={"Accept": "application/json", "User-Agent": _UA},
            timeout=_TIMEOUT,
            allow_redirects=True,
        )
        r.raise_for_status()
        d = r.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        result = {
            "available": True,
            "handle": d.get("handle"),
            "name": d.get("name") or d.get("ldhName"),
            "registered": events.get("registration"),
            "expires": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "status": d.get("status"),
        }
        cache_set("rdap", target, result)
        return result
    except Exception as e:
        return {"available": False, "error": str(e)}


def reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ─────────────── Israeli Threat Intelligence ───────────────


def hebrew_phishing_detection(text: str) -> dict[str, Any]:
    """זיהוי פישינג בעברית"""
    hebrew_patterns = [
        r"בנק.*לאומי.*אבטחה",
        r"הפועל.*מיידי",
        r"דואר.*ישראלי.*אישור",
        r"מספר.*חשבון.*ננעל",
        r"הזמנה.*מיידית",
        r"אימות.*חשבון",
        r"כניסה.*בטוחה",
    ]

    matches = []
    for pattern in hebrew_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matches.append(pattern)

    return {
        "hebrew_detected": bool(matches),
        "patterns_found": matches,
        "risk_score": len(matches) * 20,
    }


def israeli_domain_monitoring(domain: str) -> dict[str, Any]:
    """מעקב אחר דומיינים ישראליים חשודים"""
    if (cached := cache_get("il_domain", domain)) is not None:
        return cached

    result = {
        "available": True,
        "is_il_domain": domain.lower().endswith(".il"),
        "suspicious_indicators": [],
    }

    if result["is_il_domain"]:
        suspicious_chars = ["-", "_", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
        if any(c in domain for c in suspicious_chars):
            result["suspicious_indicators"].append("contains_numbers_or_hyphens")

        if len(domain) > 20:
            result["suspicious_indicators"].append("unusually_long")

        known_brands = [
            "bank", "leumi", "hapoalim", "discount", "mizrahi",
            "bezeq", "hot", "cellcom",
        ]
        for brand in known_brands:
            if brand in domain.lower() and domain != f"{brand}.il":
                result["suspicious_indicators"].append(f"brand_impersonation_{brand}")

    cache_set("il_domain", domain, result)
    return result
