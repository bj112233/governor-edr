"""LLM hallucination guard — score cap without external evidence.

The 4B model tends to give score=1.0 on any "suspicious" finding without
actually verifying via external sources. This module prevents false dispatch
by requiring 2+ distinct external intelligence sources to justify high scores.

v2 (HALLUCINATION_FIREWALL): if the report claims IOCs (IP/hash/URL) but the
deterministic pre-hunt enrichment found 0 IOCs, the score is forced to 0.0
regardless of LLM score. This is NOT a spam filter — it's a logical firewall.
The LLM cannot self-score its way past a missing evidence layer.
"""

import logging
import re

logger = logging.getLogger(__name__)

_SCORE_CAP_NO_EVIDENCE = 0.5  # below 0.6 dispatch threshold
_SCORE_CAP_BASE = 0.6  # max allowed without external evidence
_EVIDENCE_MIN_SOURCES = 2  # need 2+ distinct external sources to exceed cap

_EVIDENCE_PATTERNS = [
    re.compile(r"VirusTotal|VT\s|virustotal", re.IGNORECASE),
    re.compile(r"Shodan|shodan\.io", re.IGNORECASE),
    re.compile(r"AbuseIPDB|abuseipdb", re.IGNORECASE),
    re.compile(r"urlscan\.io|urlscan", re.IGNORECASE),
    re.compile(r"crt\.sh|certificate transparency", re.IGNORECASE),
    re.compile(r"Wayback|web\.archive\.org", re.IGNORECASE),
    re.compile(r"Abuse\.ch|ThreatFox|URLhaus", re.IGNORECASE),
    re.compile(r"MITRE|T\d{4}", re.IGNORECASE),  # MITRE ATT&CK technique IDs
]

# IOC claim patterns — if ANY of these appear in the report, the report
# is claiming an IOC exists. Used by the hallucination firewall.
_IOC_CLAIM_PATTERNS = [
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),  # IPv4
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),  # MD5/SHA1/SHA256 hashes
    re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE),  # URLs
    re.compile(r"\bAS\d{4,6}\b", re.IGNORECASE),  # ASN references
]

HALLUCINATION_FLAG = "[HALLUCINATION_FLAG]"


def count_external_evidence(report: str) -> int:
    """Count distinct external intelligence sources cited in the LLM report."""
    found: set[str] = set()
    for pat in _EVIDENCE_PATTERNS:
        if pat.search(report):
            found.add(pat.pattern[:20])
    return len(found)


def has_ioc_claims(report: str) -> bool:
    """Detect if the report claims any IOC (IP, hash, URL, ASN)."""
    return any(pat.search(report) for pat in _IOC_CLAIM_PATTERNS)


def clamp_llm_score(llm_score: float, report: str, iocs_enriched: int = -1) -> float:
    """Hallucination guard: cap LLM score if no external evidence supports it.

    Two layers:
    1. HALLUCINATION_FIREWALL (v2): if report claims IOCs but iocs_enriched == 0,
       force score to 0.0 — the LLM fabricated IOCs that the enrichment layer
       never saw. No minimum threshold, no bypass.
    2. EVIDENCE_CAP (v1): if score > 0.6 and < 2 external sources cited,
       clamp to 0.5 (below dispatch).

    Args:
        llm_score: The LLM's self-assigned threat score.
        report: The LLM-generated report text.
        iocs_enriched: Number of IOCs the deterministic pre-hunt enrichment
            found. -1 (default) = unknown/skip the firewall check.
    """
    # ── Layer 1: Hallucination firewall — zero tolerance ──
    if iocs_enriched == 0 and has_ioc_claims(report):
        logger.warning(
            "[ThreatHunter] HALLUCINATION_FIREWALL: report claims IOCs but "
            "enrichment found 0 — forcing score %.2f → 0.0 (fabricated IOCs).",
            llm_score,
        )
        return 0.0

    # ── Layer 2: Evidence cap (v1, preserved) ──
    if llm_score <= _SCORE_CAP_BASE:
        return llm_score
    evidence_count = count_external_evidence(report)
    if evidence_count >= _EVIDENCE_MIN_SOURCES:
        return llm_score
    logger.warning(
        "[ThreatHunter] Score cap: LLM gave %.2f but only %d external source(s) "
        "cited (need %d) — clamping to %.1f to prevent hallucination dispatch.",
        llm_score,
        evidence_count,
        _EVIDENCE_MIN_SOURCES,
        _SCORE_CAP_NO_EVIDENCE,
    )
    return _SCORE_CAP_NO_EVIDENCE


def flag_hallucination(answer: str, llm_score: float, has_any_ioc: bool) -> str:
    """Mark report with [HALLUCINATION_FLAG] if the firewall triggered.

    Triggered when: score clamped to 0.0 + no IOCs enriched + report claims IOCs.
    """
    if llm_score == 0.0 and not has_any_ioc and has_ioc_claims(answer):
        logger.warning("[ThreatHunter] Report flagged as hallucination — IOCs claimed but 0 enriched.")
        return f"{HALLUCINATION_FLAG} {answer}"
    return answer
