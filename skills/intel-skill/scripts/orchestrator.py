"""Intel Skill — Orchestrator (pure engine).

Responsible ONLY for: Fetch (I/O) -> Enrich -> Score.
Returns a standard payload dict. No Markdown, no Agent state, no globals.
Unit-testable by passing a bare target string.
"""

from __future__ import annotations

from typing import Any

from _utils import looks_like_domain, looks_like_hash, looks_like_ip
from data_enrichment import dns_lookup, rdap, reverse_dns
from mitre_mapping import map_payload_to_mitre
from osint_gatherer import (
    abuseipdb,
    ipapi_co,
    maltiverse_hash,
    maltiverse_ip,
    shodan,
    virustotal,
)
from threat_feeds_check import check_target_in_feeds
from threat_scoring import score_domain, score_hash, score_ip


class IntelOrchestrator:
    """Core threat-intel engine. Returns raw payload dicts only."""

    def analyze_ip(self, target: str) -> dict[str, Any]:
        target = target.strip().strip("\"'")
        if not looks_like_ip(target):
            return {
                "target": target,
                "kind": "ip",
                "status": "invalid",
                "error": f"IP לא תקין: {target}",
            }
        abuse = abuseipdb(target)
        maltiverse = maltiverse_ip(target)
        vt = virustotal(target, "ip_addresses")
        ipapi = ipapi_co(target)
        shodan_data = shodan(target)
        ptr = reverse_dns(target)
        score = score_ip(abuse, maltiverse, vt, ipapi, shodan_data)
        feed_hit = check_target_in_feeds(target, "ip")
        if feed_hit["matched"]:
            score = min(score + 20, 100)
        payload = {
            "target": target,
            "kind": "ip",
            "status": "success",
            "score": score,
            "ptr": ptr,
            "threat_feeds": feed_hit,
            "sources": {
                "abuseipdb": abuse,
                "maltiverse": maltiverse,
                "virustotal": vt,
                "ipapi_co": ipapi,
                "shodan": shodan_data,
            },
        }
        payload["mitre_techniques"] = [m.__dict__ for m in map_payload_to_mitre(payload)]
        return payload

    def analyze_domain(self, target: str) -> dict[str, Any]:
        target = target.strip().strip("\"'").lower()
        if not looks_like_domain(target):
            return {
                "target": target,
                "kind": "domain",
                "status": "invalid",
                "error": f"דומיין לא תקין: {target}",
            }
        maltiverse = maltiverse_ip(target)
        vt = virustotal(target, "domains")
        rdap_data = rdap(target)
        dns_rec = dns_lookup(target)
        score = score_domain(maltiverse, vt, rdap_data)
        feed_hit = check_target_in_feeds(target, "domain")
        if feed_hit["matched"]:
            score = min(score + 20, 100)
        payload = {
            "target": target,
            "kind": "domain",
            "status": "success",
            "score": score,
            "dns": dns_rec,
            "threat_feeds": feed_hit,
            "sources": {
                "maltiverse": maltiverse,
                "virustotal": vt,
                "rdap": rdap_data,
            },
        }
        payload["mitre_techniques"] = [m.__dict__ for m in map_payload_to_mitre(payload)]
        return payload

    def analyze_hash(self, target: str) -> dict[str, Any]:
        if not looks_like_hash(target):
            return {
                "target": target,
                "kind": "hash",
                "status": "invalid",
                "error": f"Hash לא תקין (md5/sha1/sha256): {target}",
            }
        maltiverse = maltiverse_hash(target)
        vt = virustotal(target, "files")
        score = score_hash(maltiverse, vt)
        feed_hit = check_target_in_feeds(target, "hash")
        if feed_hit["matched"]:
            score = min(score + 20, 100)
        payload = {
            "target": target,
            "kind": "hash",
            "status": "success",
            "score": score,
            "threat_feeds": feed_hit,
            "sources": {"maltiverse": maltiverse, "virustotal": vt},
        }
        payload["mitre_techniques"] = [m.__dict__ for m in map_payload_to_mitre(payload)]
        return payload
