"""Threat feed lookup — Abuse.ch (URLhaus + ThreatFox) integration for services layer.

Canonical implementation used by intel_enricher.py for pre-hunt enrichment.
The skill layer (skills/intel-skill/scripts/) keeps its own copy for CLI use —
documented duplication (see lessons.md 2026-06-26, same pattern as ioc_extractor).

Cache: reads from the same disk cache as the skill (state/skills/intel_cache/),
so feed data fetched by the skill CLI is immediately available here and vice versa.
Async-friendly: network calls wrapped in asyncio.to_thread.
Never crashes — returns {matched: False} on any error.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

__all__ = ["check_target_in_feeds", "refresh_feeds"]

_TIMEOUT = 15
_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")

# Same cache dir as skill-level _utils.py — shared disk cache
_CACHE_DIR = (
    Path(os.getenv("SENTINEL_STATE_DIR") or Path(__file__).resolve().parents[1] / "state") / "skills" / "intel_cache"
)
_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_CACHE_TTL = 86400  # 24h

_URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()
_URLHAUS_V2_URL = f"https://urlhaus-api.abuse.ch/v2/files/exports/{_URLHAUS_AUTH_KEY}/recent.csv"
_URLHAUS_LEGACY_URL = "https://urlhaus.abuse.ch/downloads/csv_online/"
_THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
_THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY", "").strip()


def _cache_get(source: str, key: str) -> dict[str, Any] | None:
    safe_key = re.sub(r"[^a-zA-Z0-9._-]", "_", key)[:128]
    fpath = _CACHE_DIR / f"{source}_{safe_key}.json"
    if not fpath.exists():
        return None
    try:
        data = json.loads(fpath.read_text(encoding="utf-8"))
        if time.time() - float(data.get("_ts", 0)) > _CACHE_TTL:
            return None
        return data.get("value")
    except Exception:
        return None


def _cache_set(source: str, key: str, value: dict[str, Any]) -> None:
    safe_key = re.sub(r"[^a-zA-Z0-9._-]", "_", key)[:128]
    fpath = _CACHE_DIR / f"{source}_{safe_key}.json"
    try:
        fpath.write_text(
            json.dumps({"_ts": time.time(), "value": value}, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[ThreatFeeds] Cache write failed: %s", exc)


def _fetch_urlhaus_sync(limit: int = 500) -> list[dict[str, Any]]:
    """Fetch URLhaus CSV. Falls back to legacy if no Auth-Key. Cached 24h."""
    cached = _cache_get("urlhaus", "recent")
    if cached is not None:
        return cached.get("rows", [])[:limit]

    target_url = _URLHAUS_V2_URL if _URLHAUS_AUTH_KEY else _URLHAUS_LEGACY_URL
    try:
        resp = requests.get(target_url, timeout=_TIMEOUT, headers={"User-Agent": _UA})
        resp.raise_for_status()
    except Exception as exc:
        logger.error("[ThreatFeeds] URLhaus fetch failed: %s", exc)
        return []

    fields = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    clean = [ln for ln in resp.text.splitlines() if not ln.startswith("#")]
    if not clean:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(clean)), fieldnames=fields)
    parsed = [r for r in reader if (r.get("url_status") or "").lower() == "online" and r.get("threat")]
    _cache_set("urlhaus", "recent", {"rows": parsed})
    return parsed[:limit]


def _fetch_threatfox_sync(days: int = 1) -> list[dict[str, Any]]:
    """Fetch ThreatFox IOCs. Filters confidence >= 50. Cached 24h."""
    cached = _cache_get("threatfox", f"days_{days}")
    if cached is not None:
        return cached.get("iocs", [])

    headers: dict[str, str] = {"User-Agent": _UA}
    if _THREATFOX_AUTH_KEY:
        headers["Auth-Key"] = _THREATFOX_AUTH_KEY
    payload = {"query": "get_iocs", "days": min(max(days, 1), 7)}
    try:
        resp = requests.post(_THREATFOX_API_URL, json=payload, headers=headers, timeout=20)
        resp.raise_for_status()
    except Exception as exc:
        logger.error("[ThreatFeeds] ThreatFox fetch failed: %s", exc)
        return []
    try:
        data = resp.json()
    except Exception as exc:
        logger.error("[ThreatFeeds] ThreatFox JSON parse failed: %s", exc)
        return []
    if data.get("query_status") != "ok":
        logger.error("[ThreatFeeds] ThreatFox API status: %s", data.get("query_status"))
        return []
    raw = data.get("data", [])
    if not isinstance(raw, list):
        return []
    high = [
        i
        for i in raw
        if isinstance(i, dict) and isinstance(i.get("confidence_level"), int) and i["confidence_level"] >= 50
    ]
    _cache_set("threatfox", f"days_{days}", {"iocs": high})
    return high


def _check_target_sync(target: str, kind: str) -> dict[str, Any]:
    """Synchronous feed check. Returns structured dict. Never crashes."""
    result: dict[str, Any] = {
        "matched": False,
        "urlhaus": False,
        "threatfox": False,
        "malware": None,
        "threat_type": None,
    }
    target_lower = target.lower().strip()

    # ThreatFox
    try:
        tf_rows = _fetch_threatfox_sync(days=1)
        for row in tf_rows:
            ioc_val = (row.get("ioc") or "").strip().lower()
            ioc_type = (row.get("ioc_type") or "").lower()
            matches = False
            if ioc_val == target_lower:
                matches = True
            elif kind == "ip" and "ip" in ioc_type and ioc_val.split(":")[0] == target_lower:
                matches = True
            if matches:
                result["threatfox"] = True
                result["malware"] = row.get("malware_printable") or row.get("malware")
                result["threat_type"] = row.get("threat_type")
                break
    except Exception as exc:
        logger.warning("[ThreatFeeds] ThreatFox check failed: %s", exc)

    # URLhaus
    try:
        uh_rows = _fetch_urlhaus_sync(limit=500)
        for row in uh_rows:
            url = (row.get("url") or "").lower()
            if target_lower in url:
                result["urlhaus"] = True
                if not result["malware"]:
                    result["malware"] = row.get("threat") or row.get("tags")
                break
    except Exception as exc:
        logger.warning("[ThreatFeeds] URLhaus check failed: %s", exc)

    result["matched"] = result["urlhaus"] or result["threatfox"]
    return result


async def check_target_in_feeds(target: str, kind: str) -> dict[str, Any]:
    """Async: check if target (ip/domain/hash) appears in Abuse.ch feeds.

    Returns {matched, urlhaus, threatfox, malware, threat_type}.
    Never crashes — returns {matched: False} on any error.
    """
    return await asyncio.to_thread(_check_target_sync, target, kind)


async def refresh_feeds() -> dict[str, int]:
    """Pre-fetch both feeds into cache. Returns {urlhaus: N, threatfox: N}."""
    uh, tf = await asyncio.gather(
        asyncio.to_thread(_fetch_urlhaus_sync, 500),
        asyncio.to_thread(_fetch_threatfox_sync, 1),
    )
    logger.info("[ThreatFeeds] Refreshed: URLhaus=%d rows, ThreatFox=%d IOCs", len(uh), len(tf))
    return {"urlhaus": len(uh), "threatfox": len(tf)}
