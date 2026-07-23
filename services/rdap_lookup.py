# services/rdap_lookup.py
"""Async RDAP domain age lookup — zero-day infrastructure detection.

Physical law: "A freshly registered domain (< 30 days) contacted by a
suspicious process is a C2 TTP, regardless of IP reputation." Attackers
use legit cloud IPs (Azure/AWS) that pass AbuseIPDB checks. The domain
age is the unforgeable signal — domain registrars don't lie.

Uses rdap.org redirector (free, no key, works for all gTLDs + most ccTLDs).
Async httpx — does NOT block the event loop.
"""

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_RDAP_BASE = "https://rdap.org/domain"
_TIMEOUT = 5.0
_CRITICAL_AGE_DAYS = 30  # < 30 days = CRITICAL (zero-day infrastructure)
_SUSPICIOUS_AGE_DAYS = 90  # < 90 days = suspicious (elevated)

# LRU cache: domain → result dict. Avoids repeated RDAP queries in same hunt.
_cache: dict[str, dict[str, Any]] = {}
_cache_lock = asyncio.Lock()
_MAX_CACHE = 200


async def _cache_get(domain: str) -> dict[str, Any] | None:
    async with _cache_lock:
        return _cache.get(domain)


async def _cache_set(domain: str, result: dict[str, Any]) -> None:
    async with _cache_lock:
        if len(_cache) >= _MAX_CACHE:
            _cache.pop(next(iter(_cache)))
        _cache[domain] = result


async def _fetch_rdap(domain: str) -> dict[str, Any] | None:
    """Fetch RDAP JSON for a domain. Returns None on error (caller handles)."""
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                f"{_RDAP_BASE}/{domain}",
                headers={"Accept": "application/json", "User-Agent": "Sentinel/1.0"},
                follow_redirects=True,
            )
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        logger.warning("[RDAP] %s — timeout after %.1fs", domain, _TIMEOUT)
        return None
    except Exception as exc:
        logger.warning("[RDAP] %s — failed: %s", domain, exc)
        return None


def _compute_age_flags(registered: str | None) -> tuple[int | None, bool, bool]:
    """Compute age_days + is_critical + is_suspicious from registration date."""
    if not registered:
        return None, False, False
    try:
        reg_dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
        age_days = (datetime.now(UTC) - reg_dt).days
        return age_days, age_days < _CRITICAL_AGE_DAYS, age_days < _SUSPICIOUS_AGE_DAYS
    except (ValueError, TypeError):
        return None, False, False


def _extract_registrar(data: dict[str, Any]) -> str | None:
    """Extract registrar name from RDAP entities."""
    for entity in data.get("entities", []):
        if "registrar" in (entity.get("roles") or []):
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and vcard[1]:
                return vcard[1][0][1] if vcard[1][0] else None
            return None
    return None


async def lookup_domain_age(domain: str) -> dict[str, Any]:
    """Query RDAP for domain registration date + compute age in days.

    Returns:
        {
            "domain": str,
            "available": bool,
            "registered": str | None,  # ISO date
            "age_days": int | None,
            "is_critical": bool,       # age < 30 days
            "is_suspicious": bool,     # age < 90 days
            "registrar": str | None,
            "status": list[str] | None,
            "error": str | None,
        }
    """
    domain = domain.lower().strip()
    if not domain or "." not in domain:
        return {"domain": domain, "available": False, "error": "invalid domain"}

    cached = await _cache_get(domain)
    if cached is not None:
        return cached

    result: dict[str, Any] = {
        "domain": domain,
        "available": False,
        "registered": None,
        "age_days": None,
        "is_critical": False,
        "is_suspicious": False,
        "registrar": None,
        "status": None,
        "error": None,
    }

    data = await _fetch_rdap(domain)
    if data is None:
        result["error"] = "domain not found in RDAP or fetch failed"
        await _cache_set(domain, result)
        return result

    # Extract events: registration, expiration, last changed
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registered = events.get("registration")
    result["registered"] = registered
    result["available"] = True
    result["status"] = data.get("status")

    # Extract registrar from entities
    result["registrar"] = _extract_registrar(data)

    # Compute age + critical/suspicious flags
    age_days, is_crit, is_susp = _compute_age_flags(registered)
    result["age_days"] = age_days
    result["is_critical"] = is_crit
    result["is_suspicious"] = is_susp

    if is_crit and age_days is not None:
        logger.critical(
            "[RDAP] %s — CRITICAL: domain age %d days (< %d). Zero-day infra.",
            domain, age_days, _CRITICAL_AGE_DAYS,
        )
    elif is_susp and age_days is not None:
        logger.warning("[RDAP] %s — SUSPICIOUS: domain age %d days (< %d).", domain, age_days, _SUSPICIOUS_AGE_DAYS)

    await _cache_set(domain, result)
    return result


async def check_domains_age(domains: list[str]) -> dict[str, Any]:
    """Batch-check domain ages. Returns unified report.

    Returns:
        {
            "checked": int,
            "critical_domains": list[dict],   # age < 30 days
            "suspicious_domains": list[dict],  # age < 90 days
            "all_results": list[dict],
            "has_critical": bool,
        }
    """
    # Dedup + filter empty
    unique = list(dict.fromkeys(d.lower().strip() for d in domains if d and "." in d))
    if not unique:
        return {"checked": 0, "critical_domains": [], "suspicious_domains": [], "all_results": [], "has_critical": False}

    # Parallel lookups (bounded concurrency to avoid RDAP rate limits)
    semaphore = asyncio.Semaphore(5)
    async def _bounded(d: str) -> dict[str, Any]:
        async with semaphore:
            return await lookup_domain_age(d)

    results = await asyncio.gather(*[_bounded(d) for d in unique], return_exceptions=True)

    all_results: list[dict[str, Any]] = []
    critical: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []

    for r in results:
        if isinstance(r, BaseException):
            logger.warning("[RDAP] batch error: %s", r)
            continue
        all_results.append(r)
        if r.get("is_critical"):
            critical.append(r)
        elif r.get("is_suspicious"):
            suspicious.append(r)

    return {
        "checked": len(all_results),
        "critical_domains": critical,
        "suspicious_domains": suspicious,
        "all_results": all_results,
        "has_critical": len(critical) > 0,
    }
