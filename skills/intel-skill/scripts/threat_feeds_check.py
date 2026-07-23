"""Threat feed lookup — checks if a target appears in Abuse.ch feeds.

Pure logic wrapper around urlhaus_feed + threatfox_feed.
Returns a structured dict for orchestrator injection.
Never crashes — returns {matched: False} on any error.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def check_target_in_feeds(target: str, kind: str) -> dict[str, Any]:
    """Check if target (ip/domain/hash) appears in URLhaus or ThreatFox.

    Returns:
        {
            "matched": bool,
            "urlhaus": bool,
            "threatfox": bool,
            "malware": str | None,  # malware family from ThreatFox
            "threat_type": str | None,  # from ThreatFox
        }
    """
    result: dict[str, Any] = {
        "matched": False,
        "urlhaus": False,
        "threatfox": False,
        "malware": None,
        "threat_type": None,
    }

    target_lower = target.lower().strip()

    # ── ThreatFox check ──
    try:
        from threatfox_feed import fetch_threatfox_iocs, extract_threatfox_iocs

        tf_rows = fetch_threatfox_iocs(days=1)
        tf_extracted = extract_threatfox_iocs(tf_rows)

        tf_match = False
        tf_malware = None
        tf_threat_type = None

        # Check against extracted IOC sets
        if kind == "ip" and target_lower in {ip.lower() for ip in tf_extracted["ips"]}:
            tf_match = True
        elif kind == "domain" and target_lower in {d.lower() for d in tf_extracted["domains"]}:
            tf_match = True
        elif kind == "hash" and target_lower in {h.lower() for h in tf_extracted["hashes"]}:
            tf_match = True
        elif target_lower in {u.lower() for u in tf_extracted["urls"]}:
            tf_match = True

        # If matched, find malware family + threat_type from raw rows
        if tf_match:
            for row in tf_rows:
                ioc_val = (row.get("ioc") or "").strip().lower()
                if ioc_val == target_lower:
                    tf_malware = row.get("malware_printable") or row.get("malware")
                    tf_threat_type = row.get("threat_type")
                    break

        result["threatfox"] = tf_match
        result["malware"] = tf_malware
        result["threat_type"] = tf_threat_type
    except Exception as exc:
        logger.warning("[threat_feeds] ThreatFox check failed: %s", exc)

    # ── URLhaus check ──
    try:
        from urlhaus_feed import fetch_urlhaus_csv, extract_urlhaus_iocs

        uh_rows = fetch_urlhaus_csv(limit=500)
        uh_extracted = extract_urlhaus_iocs(uh_rows)

        uh_match = False
        if kind == "ip" and target_lower in {ip.lower() for ip in uh_extracted["ips"]}:
            uh_match = True
        elif kind == "domain" and target_lower in {d.lower() for d in uh_extracted["domains"]}:
            uh_match = True
        elif target_lower in {u.lower() for u in uh_extracted["urls"]}:
            uh_match = True

        result["urlhaus"] = uh_match
    except Exception as exc:
        logger.warning("[threat_feeds] URLhaus check failed: %s", exc)

    result["matched"] = result["urlhaus"] or result["threatfox"]
    return result
