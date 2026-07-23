"""ThreatFox threat feed — abuse.ch IOC sharing platform.

Fetches recent IOCs (botnet C2, malware payloads) from ThreatFox API,
filters by confidence level, and maps to standard IOC types.

Sync (runs as subprocess skill). Cached 24h via _utils.
Graceful degradation: if no Auth-Key, attempts request with rate limits.
If all fails, returns empty list.

API docs: https://threatfox.abuse.ch/api/
"""

from __future__ import annotations

import logging
import os
from typing import Any

import requests
from _utils import cache_get, cache_set

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")
_CACHE_SOURCE = "threatfox"
_CACHE_TTL = 86400  # 24h

_THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
_THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY", "").strip()

# ThreatFox threat_type → MITRE technique ID
THREAT_TYPE_MITRE_MAP: dict[str, str] = {
    "botnet_cc": "T1071",
    "payload_delivery": "T1566",
    "malware_artefact": "T1055",
    "c2": "T1071",
}


def fetch_threatfox_iocs(days: int = 1) -> list[dict[str, Any]]:
    """Fetch recent ThreatFox IOCs via POST. Filters confidence >= 50.

    Returns list of IOC dicts. Cached 24h.
    """
    cached = cache_get(_CACHE_SOURCE, f"days_{days}")
    if cached is not None:
        return cached.get("iocs", [])

    headers: dict[str, str] = {"User-Agent": _UA}
    if _THREATFOX_AUTH_KEY:
        headers["Auth-Key"] = _THREATFOX_AUTH_KEY
    else:
        logger.warning("[ThreatFox] No Auth-Key — rate limits will apply.")

    payload = {"query": "get_iocs", "days": min(max(days, 1), 7)}

    try:
        resp = requests.post(
            _THREATFOX_API_URL, json=payload, headers=headers, timeout=_TIMEOUT
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("[ThreatFox] Fetch failed: %s", exc)
        return []

    try:
        data = resp.json()
    except Exception as exc:
        logger.error("[ThreatFox] JSON parse failed: %s", exc)
        return []

    if data.get("query_status") != "ok":
        logger.error("[ThreatFox] API status: %s", data.get("query_status"))
        return []

    raw_iocs = data.get("data", [])
    if not isinstance(raw_iocs, list):
        return []

    high_confidence = [
        ioc
        for ioc in raw_iocs
        if isinstance(ioc, dict)
        and isinstance(ioc.get("confidence_level"), int)
        and ioc["confidence_level"] >= 50
    ]

    cache_set(_CACHE_SOURCE, f"days_{days}", {"iocs": high_confidence})
    return high_confidence


def extract_threatfox_iocs(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Map ThreatFox native fields to standard IOC schema + malware mapping.

    Returns: {urls, domains, ips, hashes, malware_map}
    where malware_map[ioc_value] = malware_printable (for MITRE enrichment).
    """
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    hashes: set[str] = set()
    malware_map: dict[str, str] = {}

    for row in rows:
        ioc_val = (row.get("ioc") or "").strip()
        ioc_type = (row.get("ioc_type") or "").lower()
        malware = (row.get("malware_printable") or row.get("malware") or "unknown").lower()

        if not ioc_val:
            continue

        if "url" in ioc_type:
            urls.add(ioc_val)
        elif "domain" in ioc_type:
            domains.add(ioc_val)
        elif "ip" in ioc_type:
            ips.add(ioc_val.split(":")[0])  # strip port if attached
        elif "hash" in ioc_type or ioc_type in ("md5_hash", "sha256_hash"):
            hashes.add(ioc_val)

        malware_map[ioc_val] = malware

    return {
        "urls": urls,
        "domains": domains,
        "ips": ips,
        "hashes": hashes,
        "malware_map": malware_map,
    }
