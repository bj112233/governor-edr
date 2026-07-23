"""S-8: IOC extraction with provenance tracking.

Extracted from pre_hunt_enricher.py to keep it under 300 LLOC.
Tracks the source (snapshot.suspicious_net / alert:trigger) of each IOC
for audit trail and false-positive root-cause analysis.
"""

import ipaddress
from typing import Any

from services.ioc_extractor import extract_all


def _tag_provenance(text: str, provenance: dict[str, str], source: str) -> None:
    """Extract IOCs from text and tag each with its source (first wins)."""
    found = extract_all(text)
    for ioc_list in (found.get("ips_v4", []), found.get("domains", []), found.get("hashes", [])):
        for ioc in ioc_list:
            if ioc not in provenance:
                provenance[ioc] = source


def extract_iocs_with_provenance(
    snapshot: dict[str, Any], alerts: list[tuple]
) -> tuple[list[str], list[str], list[str], list[str], dict[str, str]]:
    """Extract unique public IPs, internal IPs, domains, and hashes from snapshot + alert text.

    Returns (public_ips, internal_ips, domains, hashes, provenance).
    provenance: ioc_key -> source label (e.g. "snapshot.suspicious_net", "alert:cpu:cpu_spike").
    """
    provenance: dict[str, str] = {}
    texts: list[str] = []
    if snapshot:
        for conn in snapshot.get("suspicious_net", []):
            texts.append(str(conn))
            _tag_provenance(str(conn), provenance, "snapshot.suspicious_net")
    for _ts, trigger, report in alerts:
        text = f"{trigger} {report}"
        texts.append(text)
        _tag_provenance(text, provenance, f"alert:{trigger}")

    combined = "\n".join(texts)
    iocs = extract_all(combined)

    # IPs — split public vs internal
    public: list[str] = []
    internal: list[str] = []
    seen_ips: set[str] = set()
    for ip in iocs.get("ips_v4", []):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_loopback or addr.is_private or addr.is_link_local:
                internal.append(ip)
                continue
        except ValueError:
            continue
        public.append(ip)

    domains = list(iocs.get("domains", []))
    hashes = list(iocs.get("hashes", []))
    # Prune provenance to only IOCs that survived dedup+limits
    surviving = set(public[:10] + internal[:10] + domains[:10] + hashes[:10])
    provenance = {k: v for k, v in provenance.items() if k in surviving}
    return public[:10], internal[:10], domains[:10], hashes[:10], provenance
