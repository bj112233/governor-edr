"""URLhaus threat feed — abuse.ch malicious URL database.

Fetches live malicious URLs from URLhaus (CSV format), parses rows,
and extracts IOCs via skill_ioc_extractor. Cached 24h via _utils.

Sync (runs as subprocess skill). Graceful degradation: if no Auth-Key,
falls back to legacy CSV endpoint. If all fails, returns empty list.

API docs: https://urlhaus.abuse.ch/api/
"""

from __future__ import annotations

import csv
import io
import logging
import os
from typing import Any

import requests
from _utils import cache_get, cache_set

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")
_CACHE_SOURCE = "urlhaus"
_CACHE_TTL = 86400  # 24h

_URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
_URLHAUS_V2_URL = (
    f"https://urlhaus-api.abuse.ch/v2/files/exports/{_URLHAUS_AUTH_KEY}/recent.csv"
)
_URLHAUS_LEGACY_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"


def fetch_urlhaus_csv(limit: int = 100) -> list[dict[str, Any]]:
    """Fetch URLhaus live malicious URLs. Falls back to legacy CSV if no key.

    Returns list of parsed CSV rows (dicts). Cached 24h.
    """
    cached = cache_get(_CACHE_SOURCE, "recent")
    if cached is not None:
        rows = cached.get("rows", [])
        return rows[:limit]

    target_url = _URLHAUS_V2_URL if _URLHAUS_AUTH_KEY else _URLHAUS_LEGACY_URL
    if not _URLHAUS_AUTH_KEY:
        logger.warning("[URLhaus] No Auth-Key — using legacy CSV endpoint.")

    try:
        resp = requests.get(
            target_url, timeout=_TIMEOUT, headers={"User-Agent": _UA}
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.error("[URLhaus] Fetch failed: %s", exc)
        return []

    # URLhaus CSV has comment lines starting with # and NO header row.
    # Column order (per abuse.ch docs): id, dateadded, url, url_status,
    # last_online, threat, tags, urlhaus_link, reporter
    _URLHAUS_FIELDS = [
        "id", "dateadded", "url", "url_status",
        "last_online", "threat", "tags", "urlhaus_link", "reporter",
    ]
    clean_lines = [
        line for line in resp.text.splitlines() if not line.startswith("#")
    ]
    if not clean_lines:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(clean_lines)), fieldnames=_URLHAUS_FIELDS)
    parsed: list[dict[str, Any]] = []
    for row in reader:
        status = (row.get("url_status") or row.get("status") or "").lower()
        threat = row.get("threat") or row.get("tags") or ""
        if status == "online" and threat:
            parsed.append(row)

    cache_set(_CACHE_SOURCE, "recent", {"rows": parsed})
    return parsed[:limit]


def extract_urlhaus_iocs(rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Extract IOCs from URLhaus rows via skill_ioc_extractor.

    Returns deduped sets: {urls, domains, ips, hashes}.
    """
    from skill_ioc_extractor import extract_iocs

    combined = ""
    for row in rows:
        combined += f"{row.get('url', '')} {row.get('threat', '')} {row.get('tags', '')}\n"

    extracted = extract_iocs(combined)
    return {
        "urls": set(extracted.get("urls", [])),
        "domains": set(extracted.get("domains", [])),
        "ips": set(extracted.get("ips_v4", [])),
        "hashes": set(extracted.get("hashes", [])),
    }
