# services/nvd_enricher.py
"""NVD NIST CVE enrichment — CVSS, attack vector, affected products.

Free API (no key required, 50 req/30s without key, 500 req/30s with key).
Injects hard facts into SITREP reports when breaking news mentions a CVE.

NVD API v2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import asyncio
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 8.0
_NVD_KEY = os.getenv("NVD_API_KEY", "")  # optional — raises rate limit to 500/30s

# LRU cache: CVE ID → result. CVE data is immutable (published once).
_cache: dict[str, dict[str, Any]] = {}
_cache_lock = asyncio.Lock()
_MAX_CACHE = 100


async def _cache_get(cve_id: str) -> dict[str, Any] | None:
    async with _cache_lock:
        return _cache.get(cve_id)


async def _cache_set(cve_id: str, result: dict[str, Any]) -> None:
    async with _cache_lock:
        if len(_cache) >= _MAX_CACHE:
            _cache.pop(next(iter(_cache)))
        _cache[cve_id] = result


async def _fetch_nvd(cve_id: str) -> dict[str, Any] | str | None:
    """Fetch NVD JSON for a CVE. Returns dict, error string, or None (404)."""
    params = {"cveId": cve_id}
    headers = {"User-Agent": "Sentinel/1.0"}
    if _NVD_KEY:
        headers["apiKey"] = _NVD_KEY
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_NVD_BASE, params=params, headers=headers)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                logger.warning("[NVD] %s — rate limited", cve_id)
                return "NVD rate limit (50 req/30s without key)"
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("[NVD] %s — timeout after %.1fs", cve_id, _TIMEOUT)
        return f"NVD timeout after {_TIMEOUT}s"
    except Exception as exc:
        logger.warning("[NVD] %s — failed: %s", cve_id, exc)
        return str(exc)


def _parse_cvss(cve_data: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """Extract (cvss_score, cvss_severity, attack_vector) from CVE data."""
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0]
            cvss = cvss_data.get("cvssData", {})
            return (
                cvss.get("baseScore"),
                cvss_data.get("baseSeverity") or cvss.get("baseSeverity"),
                cvss.get("attackVector"),
            )
    return None, None, None


def _parse_affected_products(cve_data: dict[str, Any]) -> list[str]:
    """Extract CPE affected product strings from CVE configurations."""
    affected: list[str] = []
    for cfg in cve_data.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                if cpe and cpe not in affected:
                    affected.append(cpe)
    return affected[:20]


async def enrich_cve(cve_id: str) -> dict[str, Any]:
    """Query NVD NIST for CVE details — CVSS, attack vector, affected products.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2026-1234"). Normalized to uppercase.

    Returns:
        {
            "cve_id": str,
            "available": bool,
            "description": str | None,
            "cvss_score": float | None,
            "cvss_severity": str | None,       # LOW / MEDIUM / HIGH / CRITICAL
            "attack_vector": str | None,       # NETWORK / ADJACENT / LOCAL / PHYSICAL
            "affected_products": list[str],    # CPE strings
            "references": list[str],           # URLs
            "published": str | None,
            "last_modified": str | None,
            "error": str | None,
        }
    """
    cve_id = cve_id.upper().strip()
    if not cve_id.startswith("CVE-"):
        return {"cve_id": cve_id, "available": False, "error": "invalid CVE ID format"}

    cached = await _cache_get(cve_id)
    if cached is not None:
        return cached

    result: dict[str, Any] = {
        "cve_id": cve_id,
        "available": False,
        "description": None,
        "cvss_score": None,
        "cvss_severity": None,
        "attack_vector": None,
        "affected_products": [],
        "references": [],
        "published": None,
        "last_modified": None,
        "error": None,
    }

    fetched = await _fetch_nvd(cve_id)
    if fetched is None:
        result["error"] = "CVE not found in NVD"
        await _cache_set(cve_id, result)
        return result
    if isinstance(fetched, str):
        result["error"] = fetched
        return result

    vulnerabilities = fetched.get("vulnerabilities", [])
    if not vulnerabilities:
        result["error"] = "no vulnerabilities in NVD response"
        await _cache_set(cve_id, result)
        return result

    cve_data = vulnerabilities[0].get("cve", {})
    result["available"] = True
    result["published"] = cve_data.get("published")
    result["last_modified"] = cve_data.get("lastModified")

    # Description (English)
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            result["description"] = desc.get("value", "")
            break

    # CVSS + affected products (extracted to helpers)
    result["cvss_score"], result["cvss_severity"], result["attack_vector"] = _parse_cvss(cve_data)
    result["affected_products"] = _parse_affected_products(cve_data)

    # References
    result["references"] = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")][:10]

    await _cache_set(cve_id, result)
    logger.info(
        "[NVD] %s — CVSS=%s (%s), vector=%s, %d affected products",
        cve_id, result["cvss_score"], result["cvss_severity"],
        result["attack_vector"], len(result["affected_products"]),
    )
    return result


async def enrich_cves(cve_ids: list[str]) -> list[dict[str, Any]]:
    """Batch-enrich multiple CVEs in parallel (bounded concurrency)."""
    unique = list(dict.fromkeys(c.upper().strip() for c in cve_ids if c.upper().startswith("CVE-")))
    if not unique:
        return []

    semaphore = asyncio.Semaphore(3)  # NVD rate limit: 50/30s → 3 concurrent is safe
    async def _bounded(c: str) -> dict[str, Any]:
        async with semaphore:
            return await enrich_cve(c)

    results = await asyncio.gather(*[_bounded(c) for c in unique], return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


def format_cve_hard_facts(cve_result: dict[str, Any]) -> str:
    """Format NVD result as hard-facts string for LLM injection.

    Used by breaking news pipeline + OSINT ReAct loop to inject immutable
    CVE data into the LLM context as ground truth.
    """
    if not cve_result.get("available"):
        return ""

    lines = [f"[HARD FACTS — NVD NIST] {cve_result['cve_id']}"]
    if cve_result.get("cvss_score"):
        lines.append(f"CVSS: {cve_result['cvss_score']} ({cve_result.get('cvss_severity', '?')})")
    if cve_result.get("attack_vector"):
        lines.append(f"Attack Vector: {cve_result['attack_vector']}")
    if cve_result.get("description"):
        lines.append(f"Description: {cve_result['description'][:300]}")
    if cve_result.get("affected_products"):
        lines.append(f"Affected: {', '.join(cve_result['affected_products'][:5])}")
    if cve_result.get("references"):
        lines.append(f"Refs: {', '.join(cve_result['references'][:3])}")
    return "\n".join(lines)
