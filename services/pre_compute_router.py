# services/pre_compute_router.py
"""Pre-compute router — deterministic enrichment BEFORE the LLM sees the prompt.

Architecture (First Principles):
  The LLM cannot be trusted to decide whether to investigate IOCs found in a
  user query. This module strips that decision: we extract IOCs from the
  user's question, enrich them via intel_enricher (AbuseIPDB, VirusTotal,
  Maltiverse), and return HARD FACTS that get injected into the system prompt.

  Intent detection ALWAYS runs (zero I/O). Enrichment (AbuseIPDB/VT) runs
  ONLY when IOCs are detected — preserving the 4 req/min VT quota.

  This generalizes the pre_hunt_enricher pattern from threat_hunter.py to
  ALL agent queries, not just scheduled hunts.

The LLM then reads "IP 46.101.206.53: AbuseIPDB=0, VT=0/90" and cannot
hallucinate "C2 server" because the attention mechanism has concrete
contradicting data in its context window.
"""

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any

from services.agent.routing.intent_routers import detect_intent
from services.intel_enricher import enrich_domain, enrich_hash, enrich_ip, is_clean_enrichment
from services.ioc_extractor import extract_all
from services.pre_hunt_enricher import (
    _ENRICH_TIMEOUT_S,
    _MAX_CONCURRENT_ENRICH,
    _allocate_quota,
    _is_malicious,
)

logger = logging.getLogger(__name__)

__all__ = ["PreComputeReport", "pre_compute", "format_pre_compute_facts"]


@dataclass
class PreComputeReport:
    """Structured result of pre-compute enrichment for a user query."""

    intent: dict | None = None  # detect_intent() result (always populated if matched)
    enriched: dict[str, dict[str, Any]] = field(default_factory=dict)  # ioc_key -> enrichment dict
    failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    ioc_types: dict[str, str] = field(default_factory=dict)  # ioc_key -> "ip"|"domain"|"hash"
    internal_ips: list[str] = field(default_factory=list)

    @property
    def has_ioc(self) -> bool:
        return bool(self.enriched or self.failed or self.skipped or self.internal_ips)

    @property
    def has_malicious(self) -> bool:
        return any(_is_malicious(d) for d in self.enriched.values())

    @property
    def all_clean(self) -> bool:
        if not self.enriched:
            return False
        return all(is_clean_enrichment(d) for d in self.enriched.values())


def _extract_iocs_from_text(text: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Extract unique public IPs, internal IPs, domains, and hashes from free text.

    Returns (public_ips, internal_ips, domains, hashes).
    Mirrors pre_hunt_enricher._extract_iocs_from_context but works on a raw string.
    """
    iocs = extract_all(text)

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

    domains = list(dict.fromkeys(iocs.get("domains", [])))
    hashes = list(dict.fromkeys(iocs.get("hashes", [])))
    return public[:10], internal[:10], domains[:10], hashes[:10]


async def _enrich_iocs(
    ips: list[str], domains: list[str], hashes: list[str]
) -> tuple[dict[str, dict[str, Any]], list[str], list[str], dict[str, str]]:
    """Enrich IOCs with VT quota allocation. Returns (enriched, failed, skipped, ioc_types)."""
    allocation = _allocate_quota(ips, domains, hashes)
    enriched: dict[str, dict[str, Any]] = {}
    failed: list[str] = []
    skipped: list[str] = []
    ioc_types: dict[str, str] = {}

    sem = asyncio.Semaphore(_MAX_CONCURRENT_ENRICH)

    async def _enrich_one(key: str, ioc_type: str) -> tuple[str, dict[str, Any] | None]:
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
            except (TimeoutError, Exception) as exc:
                logger.warning("[PreCompute] Enrichment failed for %s: %s", key, exc)
                return key, None
        return key, data

    tasks: list = []
    for h in hashes:
        ioc_types[h] = "hash"
        if allocation.get(h) == "full_intel":
            tasks.append(_enrich_one(h, "hash"))
        else:
            skipped.append(h)
    for d in domains:
        ioc_types[d] = "domain"
        if allocation.get(d) == "full_intel":
            tasks.append(_enrich_one(d, "domain"))
        else:
            skipped.append(d)
    for ip in ips:
        ioc_types[ip] = "ip"
        if allocation.get(ip) == "full_intel":
            tasks.append(_enrich_one(ip, "ip"))
        else:
            skipped.append(ip)

    if not tasks:
        return enriched, failed, skipped, ioc_types

    results = await asyncio.gather(*tasks)
    for key, data in results:
        if data is None:
            failed.append(key)
        else:
            enriched[key] = data
    return enriched, failed, skipped, ioc_types


async def pre_compute(user_question: str) -> PreComputeReport:
    """Pre-compute deterministic enrichment for a user query.

    ALWAYS: intent detection (zero I/O).
    ONLY IF IOC found: enrichment via intel_enricher (with VT quota allocation).

    Fail-soft: never raises, returns partial results on timeout.
    """
    report = PreComputeReport()

    # 1. Intent detection — always runs (pure function, no I/O)
    report.intent = detect_intent(user_question)

    # 2. IOC extraction from the raw question text
    ips, internal_ips, domains, hashes = _extract_iocs_from_text(user_question)
    report.internal_ips = internal_ips

    if not ips and not domains and not hashes:
        if report.intent or internal_ips:
            logger.info(
                "[PreCompute] intent=%s, %d internal IPs, 0 external IOCs — no enrichment.",
                report.intent.get("intent") if report.intent else "none",
                len(internal_ips),
            )
        return report

    # 3. Enrichment — only when external IOCs detected
    logger.info(
        "[PreCompute] Extracted %d IPs, %d domains, %d hashes from query — enriching.",
        len(ips),
        len(domains),
        len(hashes),
    )
    enriched, failed, skipped, ioc_types = await _enrich_iocs(ips, domains, hashes)
    report.enriched = enriched
    report.failed = failed
    report.skipped = skipped
    report.ioc_types = ioc_types

    mal_count = sum(1 for d in enriched.values() if _is_malicious(d))
    logger.info(
        "[PreCompute] Done: %d enriched (%d malicious), %d failed, %d skipped",
        len(enriched),
        mal_count,
        len(failed),
        len(skipped),
    )
    return report


def _format_enriched_ioc(key: str, data: dict, ioc_type: str) -> str:
    """Format a single enriched IOC line based on its type."""
    score = int(data.get("score", 0))
    vt = data.get("virustotal") or {}
    vt_mal = int(vt.get("malicious", 0)) if vt.get("available") and vt.get("found") else 0
    status = "MALICIOUS" if _is_malicious(data) else ("CLEAN" if is_clean_enrichment(data) else "SUSPICIOUS")
    if ioc_type == "ip":
        abuse = data.get("abuse") or {}
        country = abuse.get("country") or "?"
        return f"  IP {key} ({country}): score={score} VT={vt_mal}/90 → {status}"
    if ioc_type == "domain":
        return f"  Domain {key}: score={score} VT={vt_mal}/90 → {status}"
    if ioc_type == "hash":
        short = key[:12] + "..." if len(key) > 12 else key
        return f"  Hash {short}: score={score} VT={vt_mal}/90 → {status}"
    return f"  {key}: score={score} VT={vt_mal}/90 → {status}"


def _format_no_enrichment(report: PreComputeReport) -> str:
    """Format the case where IOCs were found but none enriched/failed/skipped."""
    lines = ["[PRE-COMPUTED HARD FACTS — do NOT re-investigate these IOCs]"]
    if report.internal_ips:
        sample = ", ".join(report.internal_ips[:5])
        lines.append(f"  Only INTERNAL IPs found ({sample}) — private network, not a threat indicator.")
    lines.append("Analyze based on these facts. Do NOT claim malicious without external IOC.")
    return "\n".join(lines)


def format_pre_compute_facts(report: PreComputeReport) -> str:
    """Format pre-compute results as HARD FACTS for prompt injection.

    Returns empty string if no IOCs were found (no enrichment to report).
    The LLM reads this as immutable ground truth.
    """
    if not report.has_ioc:
        return ""

    if not report.enriched and not report.failed and not report.skipped:
        return _format_no_enrichment(report)

    lines = ["[PRE-COMPUTED HARD FACTS — do NOT re-investigate these IOCs]"]

    for key, data in report.enriched.items():
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(_format_enriched_ioc(key, data, ioc_type))

    for key in report.failed:
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(f"  {ioc_type.title()} {key}: enrichment FAILED — treat as unknown")

    for key in report.skipped:
        ioc_type = report.ioc_types.get(key, "ip")
        lines.append(f"  {ioc_type.title()} {key}: VT quota reserved — no data (treat as unknown)")

    if report.internal_ips:
        lines.append(f"  Internal IPs (ignored): {', '.join(report.internal_ips[:5])}")

    lines.append("Do NOT call skill_intel-skill on these — already enriched. Use this data directly.")
    return "\n".join(lines)
