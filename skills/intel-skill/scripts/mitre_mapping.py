"""MITRE ATT&CK mapping engine — deterministic, pure logic, no I/O.

Scans enriched OSINT payloads for signals (ports, tags, flags, CVEs,
domain age) and maps them to MITRE ATT&CK techniques with confidence scores.

Adapted to the real orchestrator payload structure:
  payload["sources"]["shodan"]["ports"]      → port signals
  payload["sources"]["ipapi_co"]["proxy/tor/vpn"] → proxy/TOR signals
  payload["sources"]["maltiverse"]["tags"]   → tag signals
  payload["sources"]["virustotal"]["tags"]   → tag signals
  payload["sources"]["rdap"]["registered"]   → domain age → phishing signal
  payload["sources"]["shodan"]["vulns"]      → CVE → exploit signals
  payload["threat_feeds"]["threat_type"]      → ThreatFox → MITRE technique
  payload["threat_feeds"]["malware"]          → malware name → TAG_MAP lookup
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timezone
from typing import Any, Optional

from mitre_attack_db import (
    CVE_TECHNIQUE_MAP,
    PORT_MAP,
    TAG_MAP,
    TECHNIQUES,
    Technique,
)


@dataclass
class MitreMatch:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    signals: list[str] = field(default_factory=list)


def lookup_technique(technique_id: str) -> Technique | None:
    """Retrieve full technique details by ID (case-insensitive)."""
    return TECHNIQUES.get(technique_id.upper())


def map_cves_to_mitre(cves: list[str]) -> list[MitreMatch]:
    """Direct mapping from known CVEs to MITRE techniques."""
    matches: dict[str, MitreMatch] = {}

    for cve in cves:
        cve_upper = cve.upper()
        if cve_upper in CVE_TECHNIQUE_MAP:
            tech_id = CVE_TECHNIQUE_MAP[cve_upper]
            tech = lookup_technique(tech_id)
            if tech:
                if tech_id not in matches:
                    matches[tech_id] = MitreMatch(
                        technique_id=tech.id,
                        name=tech.name,
                        tactic=tech.tactic,
                        confidence=1.0,
                        signals=[f"Exploits {cve_upper}"],
                    )
                else:
                    matches[tech_id].signals.append(f"Exploits {cve_upper}")

    return list(matches.values())


def _extract_all_tags(payload: dict[str, Any]) -> list[str]:
    """Collect tags from all sources in the payload."""
    raw_tags: list[str] = []
    for source, data in payload.get("sources", {}).items():
        if not isinstance(data, dict):
            continue
        if isinstance(data.get("tags"), list):
            raw_tags.extend(str(t) for t in data["tags"] if t)
        # Maltiverse classification counts as a tag signal
        cls = data.get("classification")
        if cls and data.get("found"):
            raw_tags.append(str(cls))
    return raw_tags


def _extract_ipapi_flags(payload: dict[str, Any]) -> list[str]:
    """Extract proxy/TOR/VPN flags from ipapi_co source."""
    ipapi = payload.get("sources", {}).get("ipapi_co", {})
    if not isinstance(ipapi, dict) or not ipapi.get("available"):
        return []
    flags: list[str] = []
    if ipapi.get("proxy"):
        flags.append("proxy")
    if ipapi.get("tor"):
        flags.append("tor")
    if ipapi.get("vpn"):
        flags.append("vpn")
    return flags


def _extract_domain_age_days(payload: dict[str, Any]) -> int | None:
    """Compute domain age in days from RDAP registration date."""
    rdap = payload.get("sources", {}).get("rdap", {})
    if not isinstance(rdap, dict) or not rdap.get("available"):
        return None
    reg = rdap.get("registered")
    if not reg or not reg[:4].isdigit():
        return None
    try:
        reg_date = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        return (datetime.now(UTC) - reg_date).days
    except Exception:
        return None


def _signals_from_ports(shodan: dict[str, Any]) -> dict[str, list[str]]:
    """Port Analysis — Shodan ports → PORT_MAP."""
    hits: dict[str, list[str]] = defaultdict(list)
    if not (isinstance(shodan, dict) and shodan.get("available")):
        return hits
    ports = shodan.get("ports", [])
    if not isinstance(ports, list):
        return hits
    for port in ports:
        if port in PORT_MAP:
            hits[PORT_MAP[port]].append(f"Port {port} open")
    return hits


def _signals_from_cves(shodan: dict[str, Any]) -> dict[str, list[str]]:
    """CVE Analysis — Shodan vulns → CVE_TECHNIQUE_MAP."""
    hits: dict[str, list[str]] = defaultdict(list)
    if not (isinstance(shodan, dict) and shodan.get("available")):
        return hits
    cve_matches = map_cves_to_mitre(shodan.get("vulns", []))
    for match in cve_matches:
        hits[match.technique_id].extend(match.signals)
    return hits


def _signals_from_tags(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Tag / Classification Analysis — Maltiverse, VT tags → TAG_MAP."""
    hits: dict[str, list[str]] = defaultdict(list)
    all_tags = _extract_all_tags(payload)
    clean_tags = {str(t).lower().strip() for t in all_tags if t}
    for tag in clean_tags:
        for known_tag, tech_id in TAG_MAP.items():
            if known_tag in tag:
                hits[tech_id].append(f"Tag matched: '{tag}'")
    return hits


def _signals_from_ipapi_flags(payload: dict[str, Any]) -> dict[str, list[str]]:
    """ipapi flags (proxy/TOR/VPN) → TAG_MAP."""
    hits: dict[str, list[str]] = defaultdict(list)
    for flag in _extract_ipapi_flags(payload):
        tech_id = TAG_MAP.get(flag)
        if tech_id:
            hits[tech_id].append(f"ipapi flag: {flag}")
    return hits


def _signals_from_domain_age(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Domain Age — newly registered (<30 days) → T1566 phishing."""
    hits: dict[str, list[str]] = defaultdict(list)
    domain_age = _extract_domain_age_days(payload)
    if domain_age is not None and domain_age < 30:
        hits["T1566"].append(f"Newly registered domain ({domain_age} days)")
    return hits


def _signals_from_shodan_vulns(shodan: dict[str, Any]) -> dict[str, list[str]]:
    """Shodan vulns count → T1190 (exploit public-facing app)."""
    hits: dict[str, list[str]] = defaultdict(list)
    if not (isinstance(shodan, dict) and shodan.get("available")):
        return hits
    vulns = shodan.get("vulns", [])
    if isinstance(vulns, list) and len(vulns) > 0:
        hits["T1190"].append(f"{len(vulns)} known vulnerabilities exposed")
    return hits


def _signals_from_threat_feeds(threat_feeds: dict[str, Any]) -> dict[str, list[str]]:
    """Threat Feeds — ThreatFox threat_type + malware name + URLhaus."""
    hits: dict[str, list[str]] = defaultdict(list)
    if not (isinstance(threat_feeds, dict) and threat_feeds.get("matched")):
        return hits

    threat_type = threat_feeds.get("threat_type")
    if threat_type:
        from threatfox_feed import THREAT_TYPE_MITRE_MAP
        tech_id = THREAT_TYPE_MITRE_MAP.get(threat_type)
        if tech_id:
            hits[tech_id].append(f"ThreatFox threat_type: {threat_type}")

    malware = threat_feeds.get("malware")
    if malware:
        malware_lower = str(malware).lower()
        for known_tag, tech_id in TAG_MAP.items():
            if known_tag in malware_lower:
                hits[tech_id].append(f"Malware family: {malware}")

    if threat_feeds.get("threatfox"):
        hits["T1071"].append("Target found in ThreatFox IOC database")
    if threat_feeds.get("urlhaus"):
        hits["T1566"].append("Target found in URLhaus malicious URL database")
    return hits


def _build_matches(signal_hits: dict[str, list[str]]) -> list[MitreMatch]:
    """Construct final MitreMatch list with confidence scoring."""
    final_matches: list[MitreMatch] = []
    for tech_id, signals in signal_hits.items():
        tech = lookup_technique(tech_id)
        if not tech:
            continue
        unique_signals = list(dict.fromkeys(signals))
        confidence = min(1.0, len(unique_signals) / max(1, tech.max_signals))
        final_matches.append(MitreMatch(
            technique_id=tech.id,
            name=tech.name,
            tactic=tech.tactic,
            confidence=round(confidence, 2),
            signals=unique_signals,
        ))
    return sorted(final_matches, key=lambda x: x.confidence, reverse=True)


def map_payload_to_mitre(payload: dict[str, Any]) -> list[MitreMatch]:
    """Deterministic pure-logic mapping engine.

    Scans enriched OSINT payload for signals and maps to MITRE techniques.
    Returns sorted list (confidence descending).
    """
    shodan = payload.get("sources", {}).get("shodan", {})
    signal_hits: dict[str, list[str]] = defaultdict(list)

    for partial in (
        _signals_from_ports(shodan),
        _signals_from_cves(shodan),
        _signals_from_tags(payload),
        _signals_from_ipapi_flags(payload),
        _signals_from_domain_age(payload),
        _signals_from_shodan_vulns(shodan),
        _signals_from_threat_feeds(payload.get("threat_feeds", {})),
    ):
        for tech_id, sigs in partial.items():
            signal_hits[tech_id].extend(sigs)

    return _build_matches(signal_hits)
