# services/leak_scanner.py
"""Leak & Infrastructure Scanner — crt.sh + Wayback Machine + urlscan.io.

Free APIs, no keys required. Discovers subdomains, archived URLs,
and passive scan data for domains and IPs.

All new files < 300 lines (SRP).
"""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_CRTSH_TIMEOUT = 30  # crt.sh can be very slow for popular domains
_HEADERS = {"User-Agent": "Sentinel-OSINT/1.0 (threat-intel research)"}


# ── crt.sh — Certificate Transparency ────────────────────────────


async def scan_crtsh(domain: str, limit: int = 50) -> dict[str, Any]:
    """Query crt.sh for certificate transparency records.

    Returns subdomains, cert fingerprints, and issuers.
    Free, no key. Rate-limited (~10 req/min).
    """
    if not domain or "." not in domain:
        return {"source": "crt.sh", "domain": domain, "subdomains": [], "certs": [], "error": "invalid domain"}

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[LeakScanner] crt.sh failed for %s: %s", domain, exc)
        return {"source": "crt.sh", "domain": domain, "subdomains": [], "certs": [], "error": str(exc)}

    subdomains: set[str] = set()
    certs: list[dict[str, str]] = []

    for entry in data[: limit * 2]:
        name = (entry.get("name_value") or "").strip()
        cert_id = entry.get("id")
        issuer = entry.get("issuer_name") or ""

        # name_value can contain multiple domains (newline-separated)
        for name_part in name.split("\n"):
            name_part = name_part.strip().lower()
            if name_part and domain in name_part and "*" not in name_part:
                subdomains.add(name_part)

        if cert_id and len(certs) < limit:
            certs.append(
                {
                    "id": str(cert_id),
                    "issuer": issuer[:100],
                    "not_before": entry.get("not_before", ""),
                    "not_after": entry.get("not_after", ""),
                }
            )

    logger.info("[LeakScanner] crt.sh: %d subdomains, %d certs for %s", len(subdomains), len(certs), domain)

    return {
        "source": "crt.sh",
        "domain": domain,
        "subdomains": sorted(subdomains)[:limit],
        "certs": certs[:limit],
        "error": None,
    }


# ── Wayback Machine — Archived URL History ───────────────────────


async def scan_wayback(domain: str, limit: int = 50) -> dict[str, Any]:
    """Query Wayback Machine CDX API for archived URLs.

    Returns list of archived snapshots with timestamps and status codes.
    Free, no key.
    """
    if not domain:
        return {"source": "wayback", "domain": domain, "snapshots": [], "error": "invalid domain"}

    # Normalize: strip protocol, keep domain+path
    clean = domain.replace("https://", "").replace("http://", "").rstrip("/")
    url = f"https://web.archive.org/cdx/search/cdx?url={clean}/*&output=json&limit={limit}&collapse=urlkey"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[LeakScanner] Wayback failed for %s: %s", domain, exc)
        return {"source": "wayback", "domain": domain, "snapshots": [], "error": str(exc)}

    # CDX returns: [["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"], ...]
    # First row is the header
    snapshots: list[dict[str, str]] = []
    if len(data) < 2:
        logger.info("[LeakScanner] Wayback: 0 snapshots for %s", domain)
        return {"source": "wayback", "domain": domain, "snapshots": [], "error": None}

    header = data[0]
    for row in data[1 : limit + 1]:
        try:
            row_dict = dict(zip(header, row))
            snapshots.append(
                {
                    "url": row_dict.get("original", ""),
                    "timestamp": row_dict.get("timestamp", ""),
                    "status": row_dict.get("statuscode", ""),
                    "mimetype": row_dict.get("mimetype", ""),
                }
            )
        except Exception:
            continue

    logger.info("[LeakScanner] Wayback: %d snapshots for %s", len(snapshots), domain)

    return {
        "source": "wayback",
        "domain": domain,
        "snapshots": snapshots,
        "error": None,
    }


# ── urlscan.io — Passive Scan Results ────────────────────────────


async def scan_urlscan(target: str, limit: int = 20) -> dict[str, Any]:
    """Query urlscan.io for passive scan results.

    Free, no key (rate-limited ~100/day). Searches by domain or IP.
    Returns scan results with IPs, page URLs, and threat indicators.
    """
    if not target:
        return {"source": "urlscan.io", "target": target, "scans": [], "error": "invalid target"}

    # Detect target type: IP vs domain
    import re

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    query_field = "ip" if is_ip else "domain"
    url = f"https://urlscan.io/api/v1/search/?q={query_field}:{target}&size={limit}"

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=_HEADERS)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("[LeakScanner] urlscan.io failed for %s: %s", target, exc)
        return {"source": "urlscan.io", "target": target, "scans": [], "error": str(exc)}

    results = data.get("results", [])
    scans: list[dict[str, Any]] = []

    for entry in results[:limit]:
        task = entry.get("task", {})
        page = entry.get("page", {})
        scans.append(
            {
                "url": task.get("url", ""),
                "domain": task.get("domain", ""),
                "ip": task.get("ip", ""),
                "time": task.get("time", ""),
                "score": entry.get("scores", {}).get("phishing", 0),
                "screenshot": page.get("screenshot", ""),
                "title": page.get("title", ""),
                "malicious": bool(entry.get("verdicts", {}).get("overall", {}).get("malicious")),
            }
        )

    logger.info("[LeakScanner] urlscan.io: %d scans for %s", len(scans), target)

    return {
        "source": "urlscan.io",
        "target": target,
        "scans": scans,
        "total": data.get("total", 0),
        "error": None,
    }


# ── Orchestrator ─────────────────────────────────────────────────


async def scan_leaks(query: str, target_type: str = "auto") -> dict[str, Any]:
    """Orchestrate leak scanning across all sources.

    Auto-detects target type:
    - domain → crt.sh + wayback + urlscan
    - IP → urlscan only
    - other → wayback (URL search)

    Returns dict with per-source results.
    """
    import re

    clean = query.strip().replace("https://", "").replace("http://", "").rstrip("/")
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean))
    is_domain = bool(
        re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$", clean)
    )

    results: dict[str, Any] = {"query": query, "target": clean, "sources": {}}

    if is_ip or (target_type == "ip"):
        # IP → urlscan only
        results["sources"]["urlscan"] = await scan_urlscan(clean)
    elif is_domain or (target_type == "domain"):
        # Domain → all three sources in parallel
        import asyncio

        crtsh_task = scan_crtsh(clean)
        wayback_task = scan_wayback(clean)
        urlscan_task = scan_urlscan(clean)
        gathered: tuple[Any, ...] = await asyncio.gather(
            crtsh_task,
            wayback_task,
            urlscan_task,
            return_exceptions=True,
        )
        crtsh, wayback, urlscan = gathered[0], gathered[1], gathered[2]
        if isinstance(crtsh, dict):
            results["sources"]["crt_sh"] = crtsh
        if isinstance(wayback, dict):
            results["sources"]["wayback"] = wayback
        if isinstance(urlscan, dict):
            results["sources"]["urlscan"] = urlscan
    else:
        # URL or generic → wayback
        results["sources"]["wayback"] = await scan_wayback(clean)

    return results


def format_leak_results(results: dict[str, Any]) -> str:
    """Format leak scan results as text for ReAct observation."""
    lines: list[str] = []
    target = results.get("target", "?")
    sources = results.get("sources", {})
    if not sources:
        return "No leak data found."

    lines.append(f"Leak scan for: {target}")

    for source_name, source_data in sources.items():
        if isinstance(source_data, Exception):
            lines.append(f"\n[{source_name}] Error: {source_data}")
            continue
        error = source_data.get("error")
        if error:
            lines.append(f"\n[{source_name}] Error: {error}")
            continue

        if source_name == "crt_sh":
            subs = source_data.get("subdomains", [])
            certs = source_data.get("certs", [])
            lines.append(f"\n[crt.sh] {len(subs)} subdomains, {len(certs)} certificates")
            for s in subs[:10]:
                lines.append(f"  subdomain: {s}")
            if len(subs) > 10:
                lines.append(f"  ... and {len(subs) - 10} more")

        elif source_name == "wayback":
            snaps = source_data.get("snapshots", [])
            lines.append(f"\n[Wayback] {len(snaps)} archived snapshots")
            for snap in snaps[:10]:
                lines.append(
                    f"  {snap.get('timestamp', '?')} | {snap.get('status', '?')} | {snap.get('url', '?')[:80]}"
                )
            if len(snaps) > 10:
                lines.append(f"  ... and {len(snaps) - 10} more")

        elif source_name == "urlscan":
            scans = source_data.get("scans", [])
            total = source_data.get("total", 0)
            lines.append(f"\n[urlscan.io] {len(scans)} scans (total: {total})")
            for scan in scans[:10]:
                malicious = "MALICIOUS" if scan.get("malicious") else "clean"
                lines.append(f"  {scan.get('time', '?')[:10]} | {malicious} | {scan.get('url', '?')[:70]}")
            if len(scans) > 10:
                lines.append(f"  ... and {len(scans) - 10} more")

    return "\n".join(lines) if lines else "No leak data found."
