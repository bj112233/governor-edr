"""Pre-hunt deterministic enrichment — extracts IOCs and queries threat-intel APIs BEFORE the LLM sees them.

Architecture (First Principles):
  The LLM cannot be trusted to decide whether to investigate IOCs.
  It will shortcut to "beaconing" conclusions from bare IPs.
  This module strips that decision: we extract IOCs from the snapshot,
  enrich them via intel_enricher (AbuseIPDB, VirusTotal, Maltiverse),
  and return HARD FACTS that get injected into the prompt.

The LLM then reads "IP 46.101.206.53: AbuseIPDB=0, VT=0/90" and cannot
hallucinate "C2 server" because the attention mechanism has concrete
contradicting data in its context window.

VT Quota Management (v3.1):
  VT free tier = 4 req/min. With 6 IOCs (3 IPs + 2 domains + 1 hash),
  naive gather would block 2 threads in time.sleep(60s) — zombie threads
  that survive the 7s asyncio timeout and cripple the thread pool.
  Solution: _allocate_quota() is a pure function that pre-assigns each IOC
  to either 'full_intel' (VT slot) or 'fallback_only' (Maltiverse/AbuseIPDB).
  Priority: Hash > Domain > IPv4 (fidelity over volume).
"""

import asyncio
import logging
from typing import Any

from services._ioc_provenance import extract_iocs_with_provenance
from services.intel_enricher import enrich_domain, enrich_hash, enrich_ip, is_clean_enrichment
from services.mitre_mapper import MitreMatch, format_mitre_section, map_payload_to_mitre

logger = logging.getLogger(__name__)


def _extract_iocs_from_context(
    snapshot: dict[str, Any], alerts: list[tuple]
) -> tuple[list[str], list[str], list[str], list[str]]:
    """Backward-compat 4-tuple wrapper around extract_iocs_with_provenance."""
    ips, internal, domains, hashes, _prov = extract_iocs_with_provenance(snapshot, alerts)
    return ips, internal, domains, hashes

__all__ = ["PreHuntReport", "enrich_iocs_from_context", "format_hard_facts", "any_ioc_malicious"]

_MAX_CONCURRENT_ENRICH = 5
_ENRICH_TIMEOUT_S = 8.0

# VT free tier quota allocation (4 req/min). Priority: Hash > Domain > IPv4.
_VT_QUOTA_HASH = 1
_VT_QUOTA_DOMAIN = 1
_VT_QUOTA_IP = 2
_VT_QUOTA_TOTAL = _VT_QUOTA_HASH + _VT_QUOTA_DOMAIN + _VT_QUOTA_IP  # = 4


class PreHuntReport:
    """Structured result of pre-hunt enrichment."""

    def __init__(self) -> None:
        self.enriched: dict[str, dict[str, Any]] = {}  # ioc_key -> enrichment dict
        self.failed: list[str] = []  # IOCs that timed out or errored
        self.skipped: list[str] = []  # IOCs routed to fallback_only (no VT slot)
        self.internal_ips_seen: list[str] = []  # RFC1918/link-local IPs found in context
        # Track IOC types for hard-facts formatting: ioc_key -> "ip"|"domain"|"hash"
        self.ioc_types: dict[str, str] = {}
        # MITRE ATT&CK matches aggregated across all enriched IOCs
        self.mitre_matches: list[MitreMatch] = []
        # S-8: IOC provenance — ioc_key -> source description (snapshot/alert/tool).
        # Tracks where each IOC was first observed, enabling audit trail for
        # threat-score disputes and false-positive root-cause analysis.
        self.provenance: dict[str, str] = {}

    @property
    def has_any_ioc(self) -> bool:
        return bool(self.enriched or self.failed)

    @property
    def has_external_ioc(self) -> bool:
        """True if at least one public IOC was extracted (enriched, failed, or skipped)."""
        return bool(self.enriched or self.failed or self.skipped)

    @property
    def has_malicious(self) -> bool:
        """True if at least one enriched IOC is confirmed malicious by intel."""
        for data in self.enriched.values():
            if _is_malicious(data):
                return True
        return False

    @property
    def all_clean(self) -> bool:
        """True if all enriched IOCs are confirmed clean by intel."""
        if not self.enriched:
            return False
        return all(is_clean_enrichment(d) for d in self.enriched.values())


def _is_malicious(enrichment: dict[str, Any]) -> bool:
    """Deterministic maliciousness check — score >= 50 OR VT malicious > 0 OR feed hit.

    Cross-validation guard: a trusted-ISP cloud IP with VT=0 is CLEAN per
    is_clean_enrichment, even when AbuseIPDB mass-reporting drives score to 100.
    Feed hits (URLhaus/ThreatFox) bypass the guard — confirmed active threats.
    """
    if not enrichment:
        return False
    # Feed hit (URLhaus/ThreatFox) = confirmed active threat
    feed = enrichment.get("threat_feeds") or {}
    if feed.get("matched"):
        return True
    # Trusted-ISP + VT=0 override — abuse-only score on cloud IPs is noise
    if is_clean_enrichment(enrichment):
        return False
    score = int(enrichment.get("score", 0))
    if score >= 50:
        return True
    vt = enrichment.get("virustotal") or {}
    vt_mal = int(vt.get("malicious", 0)) if vt.get("available") and vt.get("found") else 0
    return vt_mal > 0


def _allocate_quota(ips: list[str], domains: list[str], hashes: list[str]) -> dict[str, str]:
    """Pure function: assign each IOC to 'full_intel' or 'fallback_only'.

    VT free tier = 4 req/min. Priority: Hash > Domain > IPv4.
    Returns dict: ioc_key -> "full_intel" | "fallback_only".
    """
    allocation: dict[str, str] = {}
    remaining = _VT_QUOTA_TOTAL

    # Priority 1: Hashes (highest fidelity — unambiguous malware signature)
    for h in hashes[:_VT_QUOTA_HASH]:
        allocation[h] = "full_intel"
        remaining -= 1
    for h in hashes[_VT_QUOTA_HASH:]:
        allocation[h] = "fallback_only"

    # Priority 2: Domains (C2 infrastructure — high fidelity)
    domain_slots = min(_VT_QUOTA_DOMAIN, remaining)
    for d in domains[:domain_slots]:
        allocation[d] = "full_intel"
        remaining -= 1
    for d in domains[domain_slots:]:
        allocation[d] = "fallback_only"

    # Priority 3: IPv4 (shared hosting — lowest fidelity)
    ip_slots = min(_VT_QUOTA_IP, remaining)
    for ip in ips[:ip_slots]:
        allocation[ip] = "full_intel"
        remaining -= 1
    for ip in ips[ip_slots:]:
        allocation[ip] = "fallback_only"

    return allocation


async def _enrich_one_ioc(
    sem: asyncio.Semaphore,
    key: str,
    ioc_type: str,
) -> tuple[str, dict[str, Any] | None]:
    """Enrich a single IOC with timeout + fail-soft handling."""
    async with sem:
        try:
            if ioc_type == "ip":
                data = await asyncio.wait_for(enrich_ip(key), timeout=_ENRICH_TIMEOUT_S)
            elif ioc_type == "domain":
                data = await asyncio.wait_for(enrich_domain(key), timeout=_ENRICH_TIMEOUT_S)
            elif ioc_type == "hash":
                data = await asyncio.wait_for(enrich_hash(key), timeout=_ENRICH_TIMEOUT_S)
            else:
                return key, None
        except TimeoutError:
            logger.warning("[PreHunt] Enrichment timeout for %s", key)
            return key, None
        except Exception as exc:
            logger.warning("[PreHunt] Enrichment failed for %s: %s", key, exc)
            return key, None
    return key, data


def _build_enrichment_tasks(
    report: PreHuntReport,
    allocation: dict[str, str],
    sem: asyncio.Semaphore,
    iocs: list[str],
    ioc_type: str,
) -> list:
    """Build enrichment coroutines for IOCs that got full_intel allocation.

    IOCs without full_intel are appended to report.skipped.
    """
    tasks: list = []
    for key in iocs:
        report.ioc_types[key] = ioc_type
        if allocation.get(key) == "full_intel":
            tasks.append(_enrich_one_ioc(sem, key, ioc_type))
        else:
            report.skipped.append(key)
    return tasks


def _merge_mitre_match(seen_tech: dict[str, MitreMatch], match: MitreMatch) -> None:
    """Merge a MITRE match into the seen-tech dict (dedup signals, max confidence)."""
    if match.technique_id not in seen_tech:
        seen_tech[match.technique_id] = match
        return
    existing = seen_tech[match.technique_id]
    for sig in match.signals:
        if sig not in existing.signals:
            existing.signals.append(sig)
    existing.confidence = min(1.0, max(existing.confidence, match.confidence))


def _aggregate_mitre_matches(enriched: dict[str, dict[str, Any]]) -> list[MitreMatch]:
    """Aggregate MITRE ATT&CK signals across all enriched IOCs."""
    seen_tech: dict[str, MitreMatch] = {}
    for data in enriched.values():
        for match in map_payload_to_mitre(data):
            _merge_mitre_match(seen_tech, match)
    return sorted(seen_tech.values(), key=lambda x: x.confidence, reverse=True)


async def enrich_iocs_from_context(
    snapshot: dict[str, Any],
    alerts: list[tuple],
) -> PreHuntReport:
    """Extract IOCs from snapshot+alerts, enrich each via threat-intel APIs.

    VT quota is pre-allocated: Hash > Domain > IPv4. Overflow IOCs are
    marked 'skipped' (no VT slot) rather than 'failed' (timeout).
    Fail-soft: never raises, returns partial results on timeout.
    """
    report = PreHuntReport()
    ips, internal_ips, domains, hashes, provenance = extract_iocs_with_provenance(snapshot, alerts)
    report.internal_ips_seen = internal_ips
    report.provenance = provenance

    if not ips and not domains and not hashes:
        if internal_ips:
            logger.info(
                "[PreHunt] %d internal IP(s) found, 0 external IOCs — no enrichment needed.",
                len(internal_ips),
            )
        return report

    allocation = _allocate_quota(ips, domains, hashes)
    full_intel_count = sum(1 for v in allocation.values() if v == "full_intel")
    fallback_count = sum(1 for v in allocation.values() if v == "fallback_only")
    logger.info(
        "[PreHunt] Extracted %d IPs, %d domains, %d hashes — %d full_intel, %d fallback_only",
        len(ips),
        len(domains),
        len(hashes),
        full_intel_count,
        fallback_count,
    )

    sem = asyncio.Semaphore(_MAX_CONCURRENT_ENRICH)

    # Build enrichment tasks based on allocation (hash > domain > ip priority)
    tasks: list = []
    tasks += _build_enrichment_tasks(report, allocation, sem, hashes, "hash")
    tasks += _build_enrichment_tasks(report, allocation, sem, domains, "domain")
    tasks += _build_enrichment_tasks(report, allocation, sem, ips, "ip")

    if not tasks:
        logger.info("[PreHunt] All IOCs routed to fallback_only — no enrichment calls.")
        return report

    results = await asyncio.gather(*tasks)
    for key, data in results:
        if data is None:
            report.failed.append(key)
        else:
            report.enriched[key] = data

    # MITRE ATT&CK mapping — aggregate signals across all enriched IOCs
    report.mitre_matches = _aggregate_mitre_matches(report.enriched)

    mal_count = sum(1 for d in report.enriched.values() if _is_malicious(d))
    clean_count = sum(1 for d in report.enriched.values() if is_clean_enrichment(d))
    logger.info(
        "[PreHunt] Done: %d enriched (%d malicious, %d clean), %d failed, %d skipped, %d MITRE techniques",
        len(report.enriched),
        mal_count,
        clean_count,
        len(report.failed),
        len(report.skipped),
        len(report.mitre_matches),
    )
    return report


def _format_feed_stamp(data: dict[str, Any]) -> str:
    """Format URLhaus/ThreatFox feed hit stamp."""
    feed = data.get("threat_feeds") or {}
    if not feed.get("matched"):
        return ""
    malware = feed.get("malware") or "unknown"
    sources: list[str] = []
    if feed.get("threatfox"):
        sources.append("ThreatFox")
    if feed.get("urlhaus"):
        sources.append("URLhaus")
    return f" [Found in {'+'.join(sources)}: {malware}]"


def _format_hard_fact_ioc(key: str, data: dict[str, Any], ioc_type: str) -> str:
    """Format a single enriched IOC as a hard-fact line."""
    score = int(data.get("score", 0))
    vt = data.get("virustotal") or {}
    vt_mal = int(vt.get("malicious", 0)) if vt.get("available") and vt.get("found") else 0
    status = "MALICIOUS" if _is_malicious(data) else ("CLEAN" if is_clean_enrichment(data) else "SUSPICIOUS")
    feed_stamp = _format_feed_stamp(data)
    if ioc_type == "ip":
        abuse = data.get("abuse") or {}
        country = abuse.get("country") or "?"
        isp = abuse.get("isp") or "?"
        return f"  IP {key} ({country}, {isp}): AbuseIPDB={score} VT={vt_mal}/90 → {status}{feed_stamp}"
    if ioc_type == "domain":
        return f"  Domain {key}: VT={vt_mal}/90 score={score} → {status}{feed_stamp}"
    if ioc_type == "hash":
        short = key[:12] + "..." if len(key) > 12 else key
        return f"  Hash {short}: VT={vt_mal}/90 score={score} → {status}{feed_stamp}"
    return f"  {key}: score={score} VT={vt_mal}/90 → {status}{feed_stamp}"


def format_hard_facts(report: PreHuntReport) -> str:
    """Format pre-hunt enrichment results as HARD FACTS for prompt injection.

    The LLM reads this as immutable ground truth — it cannot hallucinate
    maliciousness when the intel says clean.
    """
    if not report.has_external_ioc:
        if report.internal_ips_seen:
            sample = ", ".join(report.internal_ips_seen[:5])
            return (
                "SYSTEM PRE-CHECK RESULTS (HARD FACTS — do not contradict):\n"
                f"  NO EXTERNAL IOCs detected. All IPs in logs are INTERNAL (RFC1918/link-local): {sample}\n"
                "  Do NOT call skill_intel-skill on these — they are private network addresses.\n"
                "  Internal LAN traffic (multicast, SSDP, link-local) is NOT a threat indicator.\n"
                "Analyze the situation based on these facts. Do NOT claim malicious without external IOC."
            )
        return ""

    lines = ["SYSTEM PRE-CHECK RESULTS (HARD FACTS — do not contradict):"]
    for key, data in report.enriched.items():
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(_format_hard_fact_ioc(key, data, ioc_type))
    for key in report.failed:
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(f"  {ioc_type.title()} {key}: enrichment FAILED (timeout) — treat as unknown")
    for key in report.skipped:
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(
            f"  {ioc_type.title()} {key}: VT quota reserved for higher-priority IOCs — "
            "no VirusTotal data (treat as unknown, NOT clean)"
        )
    lines.append("Analyze the situation based on these facts. Do NOT claim malicious without intel backing.")
    # MITRE ATT&CK section
    mitre_text = format_mitre_section(report.mitre_matches)
    if mitre_text:
        lines.append(mitre_text)
    # FIM+YARA hard facts — recent file integrity matches injected as ground truth
    fim_text = _format_fim_facts()
    if fim_text:
        lines.append(fim_text)
    return "\n".join(lines)


def _format_fim_facts() -> str:
    """Format recent FIM/YARA matches as hard facts for the agent's context.

    This bridges the passive FIM monitor into the active threat hunt —
    the agent sees YARA detections as pre-established facts without
    needing to call scan_file_yara itself.
    """
    try:
        from services.fim_engine import get_recent_yara_hits

        hits = get_recent_yara_hits(hours=1.0)
    except Exception:
        return ""

    if not hits:
        return ""

    lines = ["FIM+YARA RECENT DETECTIONS (HARD FACTS — file integrity matches from last hour):"]
    for hit in hits[-5:]:  # last 5 matches
        path = hit.get("path", "?")
        rules = hit.get("rules", [])
        mitre = hit.get("mitre_ids", [])
        severity = hit.get("severity", "high")
        import datetime as _dt

        ts = _dt.datetime.fromtimestamp(hit.get("timestamp", 0)).strftime("%H:%M")
        rule_str = ", ".join(rules[:3]) if rules else "unknown"
        mitre_str = f" | MITRE: {', '.join(mitre[:3])}" if mitre else ""
        lines.append(f"  [{ts}] {path}: YARA={rule_str} (severity={severity}){mitre_str}")
    lines.append("  These files were detected by the File IntegrityMonitor — correlate with network/process activity.")
    return "\n".join(lines)


def any_ioc_malicious(report: PreHuntReport) -> bool:
    """Scoring v3.1: IOC bonus only if intel confirms malicious (IP, domain, or hash)."""
    return report.has_malicious
