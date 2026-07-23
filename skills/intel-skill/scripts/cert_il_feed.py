"""CERT-IL threat feed — Israeli National Cyber Directorate RSS.

Fetches the public RSS feed, parses alerts, and extracts IOCs from alert
text using the expanded ioc_extractor. Returns structured data for
rendering by cmd_cert_il.

Sync (runs as subprocess skill). Cached 1h via _utils.cache_get/set.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import feedparser
import requests
from _utils import cache_get, cache_set

logger = logging.getLogger(__name__)

_TIMEOUT = 10
_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelIntel/1.0")

# Configurable RSS URL — spec default is the gov.il cyber directorate feed.
# Users can override via env if the feed URL changes or a mirror is needed.
_CERT_IL_RSS_URL = os.getenv(
    "CERT_IL_RSS_URL",
    "https://www.gov.il/he/departments/cyber_national_directorate/rss",
)

_MAX_ALERTS = 10


def _extract_iocs_from_alerts(alerts: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Merge IOCs from all alert texts using the skill-level IOC extractor."""
    from skill_ioc_extractor import extract_iocs

    merged: dict[str, list[str]] = {
        "cves": [],
        "ips_v4": [],
        "domains": [],
        "urls": [],
        "hashes": [],
    }
    for alert in alerts:
        text = f"{alert.get('title', '')} {alert.get('summary', '')}"
        iocs = extract_iocs(text)
        for key in merged:
            merged[key] = list(dict.fromkeys(merged[key] + iocs.get(key, [])))
    return merged


def cert_il_feed() -> dict[str, Any]:
    """Fetch and parse CERT-IL RSS feed. Returns structured alert data + IOCs.

    Returns:
        {
            "available": True,
            "alerts": [{"title", "summary", "link", "date", "iocs"}, ...],
            "alerts_count": int,
            "all_iocs": {merged IOC dict across all alerts},
        }
        On failure: {"available": False, "error": str}
    """
    if (cached := cache_get("cert_il", "latest")) is not None:
        return cached

    try:
        resp = requests.get(
            _CERT_IL_RSS_URL,
            headers={"User-Agent": _UA, "Accept": "application/rss+xml, application/xml, text/xml"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
    except Exception as exc:
        logger.warning("[CERT-IL] Fetch failed: %s", exc)
        return {"available": False, "error": f"Fetch failed: {exc}"}

    parsed = feedparser.parse(resp.content)
    if not parsed.entries:
        logger.warning("[CERT-IL] No entries in feed")
        result = {"available": True, "alerts": [], "alerts_count": 0, "all_iocs": {}}
        cache_set("cert_il", "latest", result)
        return result

    alerts: list[dict[str, Any]] = []
    for entry in parsed.entries[:_MAX_ALERTS]:
        title = getattr(entry, "title", "") or ""
        summary = getattr(entry, "summary", "") or getattr(entry, "description", "") or ""
        link = getattr(entry, "link", "") or ""
        date = getattr(entry, "published", "") or getattr(entry, "updated", "") or ""
        alerts.append({
            "title": title,
            "summary": summary,
            "link": link,
            "date": date,
        })

    all_iocs = _extract_iocs_from_alerts(alerts)
    # Attach per-alert IOCs for granular rendering
    for alert in alerts:
        text = f"{alert['title']} {alert['summary']}"
        from skill_ioc_extractor import extract_iocs

        alert["iocs"] = extract_iocs(text)

    result = {
        "available": True,
        "alerts": alerts,
        "alerts_count": len(alerts),
        "all_iocs": all_iocs,
        "source_url": _CERT_IL_RSS_URL,
    }
    cache_set("cert_il", "latest", result)
    logger.info("[CERT-IL] Fetched %d alerts, %d total IOCs", len(alerts), sum(len(v) for v in all_iocs.values()))
    return result
