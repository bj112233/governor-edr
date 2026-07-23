"""MITRE ATT&CK mapping engine -- canonical services-layer implementation.

Pure logic, zero I/O, zero external dependencies. Scans enriched IOC
payloads for signals (ports, tags, flags, CVEs, feed hits) and maps
them to MITRE ATT&CK techniques with confidence scores.

The skill layer (skills/intel-skill/scripts/mitre_mapping.py) keeps its
own copy for CLI use -- documented duplication (same pattern as
ioc_extractor and threat_feeds).

Import direction: services <- skills (legal). Skills import services
forbidden by import-linter.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NamedTuple


class Technique(NamedTuple):
    id: str
    name: str
    tactic: str
    description: str
    max_signals: int


TECHNIQUES: dict[str, Technique] = {
    "T1059": Technique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        3,
    ),
    "T1059.001": Technique(
        "T1059.001",
        "PowerShell",
        "Execution",
        "Adversaries may use PowerShell for execution (obfuscation, encoded commands, download cradles, policy bypass).",
        4,
    ),
    "T1071": Technique(
        "T1071",
        "Application Layer Protocol",
        "Command and Control",
        "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.",
        3,
    ),
    "T1090": Technique(
        "T1090",
        "Proxy",
        "Command and Control",
        "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary.",
        3,
    ),
    "T1090.003": Technique(
        "T1090.003",
        "Tor",
        "Command and Control",
        "Adversaries may use the Tor network to hide the routing of network traffic.",
        2,
    ),
    "T1021.001": Technique(
        "T1021.001",
        "Remote Desktop Protocol",
        "Lateral Movement",
        "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP).",
        2,
    ),
    "T1021.002": Technique(
        "T1021.002",
        "SMB/Windows Admin Shares",
        "Lateral Movement",
        "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB).",
        2,
    ),
    "T1021.004": Technique(
        "T1021.004",
        "SSH",
        "Lateral Movement",
        "Adversaries may use Valid Accounts to log into remote machines via SSH.",
        2,
    ),
    "T1048": Technique(
        "T1048",
        "Exfiltration Over Alternative Protocol",
        "Exfiltration",
        "Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel.",
        2,
    ),
    "T1566": Technique(
        "T1566",
        "Phishing",
        "Initial Access",
        "Adversaries may send phishing messages to gain access to victim systems.",
        3,
    ),
    "T1190": Technique(
        "T1190",
        "Exploit Public-Facing Application",
        "Initial Access",
        "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program.",
        2,
    ),
    "T1055": Technique(
        "T1055",
        "Process Injection",
        "Defense Evasion",
        "Adversaries may inject code into processes to evade process-based defenses or elevate privileges.",
        2,
    ),
    "T1496": Technique(
        "T1496",
        "Resource Hijacking",
        "Impact",
        "Adversaries may leverage resources of co-opted systems for resource-intensive tasks (e.g. crypto-mining).",
        2,
    ),
    "T1046": Technique(
        "T1046",
        "Network Service Discovery",
        "Discovery",
        "Adversaries may attempt to get a listing of services running on remote hosts.",
        2,
    ),
}

PORT_MAP: dict[int, str] = {
    3389: "T1021.001",
    445: "T1021.002",
    139: "T1021.002",
    22: "T1021.004",
    21: "T1021.004",
    23: "T1021.004",
}

TAG_MAP: dict[str, str] = {
    "proxy": "T1090",
    "tor": "T1090.003",
    "vpn": "T1090",
    "botnet": "T1071",
    "c2": "T1071",
    "phishing": "T1566",
    "backdoor": "T1090",
    "miner": "T1496",
    "malicious": "T1055",
    "trojan": "T1055",
    "rat": "T1071",
    "worm": "T1055",
}

CVE_TECHNIQUE_MAP: dict[str, str] = {
    "CVE-2021-44228": "T1190",
    "CVE-2021-26855": "T1190",
    "CVE-2023-23397": "T1566",
    "CVE-2024-3094": "T1055",
    "CVE-2017-0144": "T1190",
    "CVE-2019-0708": "T1021.001",
}

# ThreatFox threat_type -> MITRE (mirrors threatfox_feed.THREAT_TYPE_MITRE_MAP)
THREAT_TYPE_MITRE_MAP: dict[str, str] = {
    "botnet_cc": "T1071",
    "payload_delivery": "T1566",
    "malware_artefact": "T1055",
    "c2": "T1071",
}


@dataclass
class MitreMatch:
    technique_id: str
    name: str
    tactic: str
    confidence: float
    signals: list[str] = field(default_factory=list)


def lookup_technique(technique_id: str) -> Technique | None:
    return TECHNIQUES.get(technique_id.upper())


def map_cves_to_mitre(cves: list[str]) -> list[MitreMatch]:
    matches: dict[str, MitreMatch] = {}
    for cve in cves:
        cve_upper = cve.upper()
        if cve_upper in CVE_TECHNIQUE_MAP:
            tech_id = CVE_TECHNIQUE_MAP[cve_upper]
            tech = lookup_technique(tech_id)
            if tech and tech_id not in matches:
                matches[tech_id] = MitreMatch(tech.id, tech.name, tech.tactic, 1.0, [f"Exploits {cve_upper}"])
            elif tech_id in matches:
                matches[tech_id].signals.append(f"Exploits {cve_upper}")
    return list(matches.values())


def _map_ports(shodan: dict[str, Any], hits: dict[str, list[str]]) -> None:
    if not (isinstance(shodan, dict) and shodan.get("available")):
        return
    ports = shodan.get("ports", [])
    if isinstance(ports, list):
        for port in ports:
            if port in PORT_MAP:
                hits[PORT_MAP[port]].append(f"Port {port} open")


def _map_cves(shodan: dict[str, Any], hits: dict[str, list[str]]) -> None:
    cves: list[str] = []
    if isinstance(shodan, dict) and shodan.get("available"):
        cves.extend(shodan.get("vulns", []))
    for match in map_cves_to_mitre(cves):
        hits[match.technique_id].extend(match.signals)


def _map_tags(payload: dict[str, Any], sources: dict[str, Any], hits: dict[str, list[str]]) -> None:
    raw_tags: list[str] = []
    for source_data in sources.values():
        if isinstance(source_data, dict):
            if isinstance(source_data.get("tags"), list):
                raw_tags.extend(str(t) for t in source_data["tags"] if t)
            cls = source_data.get("classification")
            if cls and source_data.get("found"):
                raw_tags.append(str(cls))
    for top_key in ("virustotal", "maltiverse", "abuse"):
        top_data = payload.get(top_key, {})
        if isinstance(top_data, dict) and isinstance(top_data.get("tags"), list):
            raw_tags.extend(str(t) for t in top_data["tags"] if t)
    clean_tags = {str(t).lower().strip() for t in raw_tags if t}
    for tag in clean_tags:
        for known_tag, tech_id in TAG_MAP.items():
            if known_tag in tag:
                hits[tech_id].append(f"Tag matched: '{tag}'")


def _map_ipapi_flags(payload: dict[str, Any], sources: dict[str, Any], hits: dict[str, list[str]]) -> None:
    ipapi = sources.get("ipapi_co", payload.get("ipapi", {}))
    if not (isinstance(ipapi, dict) and ipapi.get("available")):
        return
    for flag in ("proxy", "tor", "vpn"):
        if ipapi.get(flag):
            tech_id = TAG_MAP.get(flag)
            if tech_id:
                hits[tech_id].append(f"ipapi flag: {flag}")


def _map_domain_age(payload: dict[str, Any], sources: dict[str, Any], hits: dict[str, list[str]]) -> None:
    rdap = sources.get("rdap", payload.get("rdap", {}))
    if not (isinstance(rdap, dict) and rdap.get("available")):
        return
    reg = rdap.get("registered")
    if not (reg and reg[:4].isdigit()):
        return
    try:
        reg_date = datetime.fromisoformat(reg.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - reg_date).days
        if age_days < 30:
            hits["T1566"].append(f"Newly registered domain ({age_days} days)")
    except Exception:
        pass


def _map_shodan_vulns(shodan: dict[str, Any], hits: dict[str, list[str]]) -> None:
    if not (isinstance(shodan, dict) and shodan.get("available")):
        return
    vulns = shodan.get("vulns", [])
    if isinstance(vulns, list) and len(vulns) > 0:
        hits["T1190"].append(f"{len(vulns)} known vulnerabilities exposed")


def _map_threat_feeds(payload: dict[str, Any], hits: dict[str, list[str]]) -> None:
    threat_feeds = payload.get("threat_feeds", {})
    if not (isinstance(threat_feeds, dict) and threat_feeds.get("matched")):
        return
    threat_type = threat_feeds.get("threat_type")
    if threat_type:
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


def map_payload_to_mitre(payload: dict[str, Any]) -> list[MitreMatch]:
    """Deterministic mapping: enriched IOC payload -> MITRE techniques.

    Accepts the enrichment dict format from intel_enricher.py:
      {"score": N, "abuse": {...}, "virustotal": {...}, "threat_feeds": {...}, ...}
    Also accepts the orchestrator format with "sources" key.
    Returns sorted list (confidence descending).
    """
    signal_hits: dict[str, list[str]] = defaultdict(list)
    sources = payload.get("sources", {})
    shodan = sources.get("shodan", payload.get("shodan", {}))

    _map_ports(shodan, signal_hits)
    _map_cves(shodan, signal_hits)
    _map_tags(payload, sources, signal_hits)
    _map_ipapi_flags(payload, sources, signal_hits)
    _map_domain_age(payload, sources, signal_hits)
    _map_shodan_vulns(shodan, signal_hits)
    _map_threat_feeds(payload, signal_hits)

    final: list[MitreMatch] = []
    for tech_id, signals in signal_hits.items():
        tech = lookup_technique(tech_id)
        if not tech:
            continue
        unique = list(dict.fromkeys(signals))
        confidence = min(1.0, len(unique) / max(1, tech.max_signals))
        final.append(MitreMatch(tech.id, tech.name, tech.tactic, round(confidence, 2), unique))
    return sorted(final, key=lambda x: x.confidence, reverse=True)


def format_mitre_section(matches: list[MitreMatch]) -> str:
    """Format MITRE matches as a compact text block for hard facts injection."""
    if not matches:
        return ""
    lines = ["MITRE ATT&CK MAPPING (deterministic -- do not contradict):"]
    for m in matches:
        lines.append(f"  {m.technique_id} ({m.name}) [{m.tactic}] confidence={m.confidence}")
        for sig in m.signals[:3]:
            lines.append(f"    - {sig}")
    return "\n".join(lines)


def serialize_mitre(matches: list[MitreMatch]) -> list[dict[str, Any]]:
    """Serialize MitreMatch dataclasses to dicts for event bus / Telegram."""
    return [
        {
            "technique_id": m.technique_id,
            "name": m.name,
            "tactic": m.tactic,
            "confidence": m.confidence,
            "signals": m.signals,
        }
        for m in matches
    ]
