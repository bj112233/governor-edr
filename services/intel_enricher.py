# services/intel_enricher.py
"""Auto-Enrichment Pipeline for network alerts using intel-skill.
In-flight enrichment with strict timeout and fail-soft behavior.
"""

import asyncio
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional

from services.agent._helpers import _fire_and_forget
from services.threat_feeds import check_target_in_feeds

logger = logging.getLogger(__name__)

# Dynamically add intel-skill scripts to path for import
_INTEL_SKILL_DIR = Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts"
sys.path.insert(0, str(_INTEL_SKILL_DIR))

try:
    from intel import (
        _IPV4_RE,
        _abuseipdb,
        _maltiverse_ip,
        _score_ip,
        _virustotal,
        maltiverse_hash,
        rdap,
        score_domain,
        score_hash,
    )
except Exception as exc:  # pragma: no cover
    logger.warning("[IntelEnricher] Failed to import intel-skill: %s", exc)
    _abuseipdb = None
    _maltiverse_ip = None
    _virustotal = None
    _score_ip = None
    _IPV4_RE = None
    maltiverse_hash = None
    rdap = None
    score_domain = None
    score_hash = None

# Strict ceiling: enrichment must NEVER block alert delivery.
_ENRICHMENT_TIMEOUT = 7.0

# Concurrency cap: VT free tier is 4 req/min. The skill's token-bucket handles
# the rate; this semaphore limits concurrent enrichment calls so burst alerts
# don't fan out into a rate-limit storm.
_VT_CONCURRENCY = asyncio.Semaphore(4)

# Domain validation regex: must have at least 2 parts, TLD must be alphabetic (2+ chars)
_VALID_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$")


def _is_valid_domain(domain: str) -> bool:
    """Defensive validation — rejects invalid domains before API calls.

    Prevents version numbers (9.2), decimals (0.5), and log fragments
    from being sent to VirusTotal/URLhaus and generating false positives.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(_VALID_DOMAIN_RE.match(domain.strip()))


def _lookup_sync(ip: str) -> dict[str, Any] | None:
    """Synchronous enrichment lookup via intel-skill APIs (parallel)."""
    if _abuseipdb is None:
        return None
    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3) as pool:
            abuse_f = pool.submit(_abuseipdb, ip)
            maltiverse_f = pool.submit(_maltiverse_ip, ip)
            vt_f = pool.submit(_virustotal, ip, "ip_addresses")

            abuse = abuse_f.result()
            maltiverse = maltiverse_f.result()
            vt = vt_f.result()

        # _score_ip v2 expects 5 args (ipapi + shodan are optional; empty dicts for fast path)
        score = _score_ip(abuse, maltiverse, vt, {}, {})
        return {
            "abuse": abuse,
            "maltiverse": maltiverse,
            "virustotal": vt,
            "score": score,
        }
    except Exception as exc:
        logger.debug("[IntelEnricher] Sync lookup failed for %s: %s", ip, exc)
        return None


async def enrich_ip(ip: str) -> dict[str, Any] | None:
    """Enrich a single IP with threat intel + feed check. Hard-capped at 7s.

    Returns None on timeout or failure (fail-soft).  Never raises.
    """
    if not ip or _IPV4_RE is None or not _IPV4_RE.match(ip):
        return None

    # M4: Skip only loopback — LAN IPs are now enriched for lateral
    # movement detection. Private IPs won't have VT/AbuseIPDB data, but
    # the enrichment attempt itself records the IP in the threat context.
    try:
        import ipaddress

        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None

    try:
        async with _VT_CONCURRENCY:
            data = await asyncio.wait_for(
                asyncio.to_thread(_lookup_sync, ip),
                timeout=_ENRICHMENT_TIMEOUT,
            )
        if data is None:
            return None
        # Feed check (async, reads disk cache — fast if pre-fetched)
        feed_hit = await asyncio.wait_for(check_target_in_feeds(ip, "ip"), timeout=3.0)
        if feed_hit.get("matched"):
            data["score"] = min(int(data.get("score", 0)) + 20, 100)
            data["threat_feeds"] = feed_hit

        # Temporal correlation: recall decayed historical score
        try:
            from services.ioc_memory_store import recall_decayed_score, save_score

            historical = await recall_decayed_score(ip, "ip")
            if historical > 0:
                original = int(data.get("score", 0))
                boosted = min(100, int(round(original + historical)))
                if boosted > original:
                    data["score"] = boosted
                    data["historical_boost"] = round(historical, 1)
                    logger.debug(
                        "[IntelEnricher] %s temporal boost: %d + %.1f (history) = %d",
                        ip,
                        original,
                        historical,
                        boosted,
                    )
            # Fire-and-forget: save current score for future recall
            _fire_and_forget(save_score(ip, "ip", int(data.get("score", 0)), "intel_enricher"))
        except Exception as exc:
            logger.debug("[IntelEnricher] IOC memory recall failed for %s: %s", ip, exc)

        return data
    except TimeoutError:
        logger.warning(
            "[IntelEnricher] Timeout enriching %s after %.1fs",
            ip,
            _ENRICHMENT_TIMEOUT,
        )
        return None
    except Exception as exc:
        logger.warning("[IntelEnricher] Enrichment failed for %s: %s", ip, exc)
        return None


def _lookup_domain_sync(domain: str) -> dict[str, Any] | None:
    """Synchronous domain enrichment: Maltiverse + VT + RDAP (parallel)."""
    if _virustotal is None:
        return None
    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3) as pool:
            vt_f = pool.submit(_virustotal, domain, "domains")
            rdap_f = pool.submit(rdap, domain) if rdap else pool.submit(lambda: {})
            # Maltiverse has no domain endpoint — use VT + RDAP only
            vt = vt_f.result()
            rdap_data = rdap_f.result()
        score = score_domain({}, vt, rdap_data) if score_domain else 0
        return {"virustotal": vt, "rdap": rdap_data, "score": score}
    except Exception as exc:
        logger.debug("[IntelEnricher] Domain lookup failed for %s: %s", domain, exc)
        return None


async def enrich_domain(domain: str) -> dict[str, Any] | None:
    """Enrich a domain with VT + RDAP + feed check. Hard-capped at 7s. Fail-soft."""
    if not domain or _virustotal is None:
        return None
    # Defensive validation: reject invalid domains before any API call
    # Prevents version numbers (9.2), decimals, and log fragments from
    # being sent to VirusTotal/URLhaus and generating false positives.
    if not _is_valid_domain(domain):
        logger.debug("[IntelEnricher] Rejected invalid domain format: '%s'", domain)
        return None
    try:
        async with _VT_CONCURRENCY:
            data = await asyncio.wait_for(
                asyncio.to_thread(_lookup_domain_sync, domain),
                timeout=_ENRICHMENT_TIMEOUT,
            )
        if data is None:
            return None
        feed_hit = await asyncio.wait_for(check_target_in_feeds(domain, "domain"), timeout=3.0)
        if feed_hit.get("matched"):
            data["score"] = min(int(data.get("score", 0)) + 20, 100)
            data["threat_feeds"] = feed_hit
        return data
    except TimeoutError:
        logger.warning("[IntelEnricher] Timeout enriching domain %s", domain)
        return None
    except Exception as exc:
        logger.warning("[IntelEnricher] Domain enrichment failed for %s: %s", domain, exc)
        return None


def _lookup_hash_sync(file_hash: str) -> dict[str, Any] | None:
    """Synchronous hash enrichment: Maltiverse + VT (parallel)."""
    if _virustotal is None:
        return None
    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            vt_f = pool.submit(_virustotal, file_hash, "files")
            mal_f = pool.submit(maltiverse_hash, file_hash) if maltiverse_hash else pool.submit(lambda: {})
            vt = vt_f.result()
            mal = mal_f.result()
        score = score_hash(mal, vt) if score_hash else 0
        return {"virustotal": vt, "maltiverse": mal, "score": score}
    except Exception as exc:
        logger.debug("[IntelEnricher] Hash lookup failed for %s: %s", file_hash[:12], exc)
        return None


async def enrich_hash(file_hash: str) -> dict[str, Any] | None:
    """Enrich a file hash with VT + Maltiverse + feed check. Hard-capped at 7s. Fail-soft."""
    if not file_hash or _virustotal is None:
        return None
    try:
        async with _VT_CONCURRENCY:
            data = await asyncio.wait_for(
                asyncio.to_thread(_lookup_hash_sync, file_hash),
                timeout=_ENRICHMENT_TIMEOUT,
            )
        if data is None:
            return None
        feed_hit = await asyncio.wait_for(check_target_in_feeds(file_hash, "hash"), timeout=3.0)
        if feed_hit.get("matched"):
            data["score"] = min(int(data.get("score", 0)) + 20, 100)
            data["threat_feeds"] = feed_hit
        return data
    except TimeoutError:
        logger.warning("[IntelEnricher] Timeout enriching hash %s...", file_hash[:12])
        return None
    except Exception as exc:
        logger.warning("[IntelEnricher] Hash enrichment failed for %s: %s", file_hash[:12], exc)
        return None


# Trusted ISP/ASN patterns — cloud providers that get false-positive abuse
# scores from privacy advocates reporting telemetry as "spyware".
# AbuseIPDB returns `isp` field; we match case-insensitively.
_TRUSTED_ISP_PATTERNS = (
    "microsoft",
    "google",
    "amazon",
    "apple",
    "cloudflare",
    "akamai",
    "mozilla",
)


def _is_trusted_isp(abuse: dict[str, Any]) -> bool:
    """Check if the ISP matches a trusted cloud/provider pattern."""
    isp = (abuse.get("isp") or "").lower()
    if not isp:
        return False
    return any(p in isp for p in _TRUSTED_ISP_PATTERNS)


def is_clean_enrichment(enrichment: dict[str, Any]) -> bool:
    """Return True if IOC is safe to whitelist.

    Three paths:
    1. Score is 0 (clean) AND no feed hit — standard path.
    2. ISP matches a trusted cloud provider (Microsoft, Google, etc.)
       AND VirusTotal shows 0 malicious — overrides low abuse scores
       caused by privacy advocates flagging telemetry as "spyware".
    3. Feed hit (URLhaus/ThreatFox) → NEVER clean (confirmed active threat).
    """
    # Feed hit = confirmed active threat — never clean
    feed = enrichment.get("threat_feeds") or {}
    if feed.get("matched"):
        return False

    score = int(enrichment.get("score", 100))
    if score == 0:
        return True

    # Trusted ISP override: cloud telemetry gets false-positive abuse scores.
    # AbuseIPDB=100 on a multi-tenant cloud IP (Azure/AWS/GCP) is noise from
    # automated Fail2Ban-style mass reporting — VT=0 from a trusted ISP wins,
    # regardless of how high the abuse-driven score is. VT must have actually
    # returned data (available+found) — absence of VT data is NOT corroboration.
    abuse = enrichment.get("abuse") or {}
    vt = enrichment.get("virustotal") or {}
    vt_checked = bool(vt.get("available") and vt.get("found"))
    vt_mal = int(vt.get("malicious", 0)) if vt_checked else 0
    if _is_trusted_isp(abuse) and vt_checked and vt_mal == 0:
        logger.debug(
            "[IntelEnricher] Trusted ISP override: isp=%s score=%d abuse=%d → whitelist",
            abuse.get("isp"),
            score,
            abuse.get("abuse_confidence", 0),
        )
        return True

    return False


def format_enrichment_summary(enrichment: dict[str, Any]) -> str:
    """Format enrichment dict into Hebrew Markdown for Telegram."""
    score = int(enrichment.get("score", 0))
    abuse = enrichment.get("abuse") or {}
    vt = enrichment.get("virustotal") or {}

    abuse_conf = int(abuse.get("abuse_confidence", 0)) if abuse.get("available") else 0
    country = abuse.get("country") or "N/A"
    total_reports = int(abuse.get("total_reports", 0)) if abuse.get("available") else 0

    vt_mal = int(vt.get("malicious", 0)) if vt.get("available") and vt.get("found") else 0
    vt_susp = int(vt.get("suspicious", 0)) if vt.get("available") and vt.get("found") else 0

    # Emoji from SSOT (services.telegram.severity); Hebrew label paired inline.
    from services.telegram.severity import severity_emoji_by_score

    _SCORE_LABEL = {
        "🔴": "זדוני / Malicious",
        "🟠": "חשוד / Suspicious",
        "🟡": "לא ידוע / Unknown",
        "🟢": "נקי / Clean",
    }
    emoji = severity_emoji_by_score(score)
    classification = f"{emoji} {_SCORE_LABEL[emoji]}"

    lines = [
        "🌐 **מודיעין סייבר (Sentinel Intel):**",
        f"├─ ציון סיכון (Score): `{score}/100`",
        f"├─ Abuse Score: `{abuse_conf}%` ({total_reports} דיווחים)",
        f"├─ מדינה: `{country}`",
        f"└─ סיווג משוער: {classification}",
    ]
    if vt_mal or vt_susp:
        lines.insert(-1, f"├─ VirusTotal: `{vt_mal} malicious / {vt_susp} suspicious`")

    return "\n".join(lines)
