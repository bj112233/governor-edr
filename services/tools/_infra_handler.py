# services/tools/_infra_handler.py
"""Infrastructure discovery handler — isolated from system_tools.py for SRP.

Refactored (Phase 2): extract per-source formatters to reduce CC.
"""

from services.leak_scanner import scan_crtsh, scan_urlscan, scan_wayback


def _format_crtsh(result) -> list[str]:
    """Format crt.sh result (Certificate Transparency)."""
    if isinstance(result, Exception):
        return [f"\n**[crt.sh]** ❌ Error: {result}"]
    if not isinstance(result, dict):
        return []
    err = result.get("error")
    if err:
        return [f"\n**[crt.sh]** ⚠️ {err}"]
    subs = result.get("subdomains", [])
    lines = [f"\n**[crt.sh]** {len(subs)} subdomains"]
    for s in subs[:10]:
        lines.append(f"  - {s}")
    if len(subs) > 10:
        lines.append(f"  ... and {len(subs) - 10} more")
    return lines


def _format_wayback(result) -> list[str]:
    """Format Wayback result (Archived URLs)."""
    if isinstance(result, Exception):
        return [f"\n**[Wayback]** ❌ Error: {result}"]
    if not isinstance(result, dict):
        return []
    err = result.get("error")
    if err:
        return [f"\n**[Wayback]** ⚠️ {err}"]
    snaps = result.get("snapshots", [])
    lines = [f"\n**[Wayback]** {len(snaps)} archived snapshots"]
    for snap in snaps[:5]:
        lines.append(f"  - {snap.get('timestamp', '?')} | {snap.get('url', '?')[:60]}")
    if len(snaps) > 5:
        lines.append(f"  ... and {len(snaps) - 5} more")
    return lines


def _format_urlscan(result) -> list[str]:
    """Format urlscan.io result (Passive Scan)."""
    if isinstance(result, Exception):
        return [f"\n**[urlscan.io]** ❌ Error: {result}"]
    if not isinstance(result, dict):
        return []
    err = result.get("error")
    if err:
        return [f"\n**[urlscan.io]** ⚠️ {err}"]
    scans = result.get("scans", [])
    lines = [f"\n**[urlscan.io]** {len(scans)} passive scans"]
    for sc in scans[:5]:
        malicious = "🚨" if sc.get("malicious") else "✅"
        lines.append(f"  {malicious} {sc.get('ip', '?')} | {sc.get('domain', '?')} | {sc.get('url', '?')[:50]}")
    if len(scans) > 5:
        lines.append(f"  ... and {len(scans) - 5} more")
    return lines


async def scan_infrastructure_handler(domain: str) -> str:
    """Discover infrastructure via crt.sh + Wayback + urlscan.io.

    Fault-isolated: each source runs independently with return_exceptions=True.
    If crt.sh crashes (502), Wayback and urlscan results still return.
    25s timeout per source, graceful degradation per-source.
    """
    import asyncio as _aio

    clean = str(domain).strip().replace("https://", "").replace("http://", "").rstrip("/")
    if not clean or "." not in clean:
        return f"❌ Invalid domain: '{domain}'"

    try:
        crtsh_r, wayback_r, urlscan_r = await _aio.wait_for(
            _aio.gather(
                scan_crtsh(clean),
                scan_wayback(clean),
                scan_urlscan(clean),
                return_exceptions=True,
            ),
            timeout=25.0,
        )
    except TimeoutError:
        return f"⏱️ Infrastructure scan timed out (>25s) for domain: {domain}"

    lines = [f"🔍 **Infrastructure Discovery: {clean}**"]
    lines.extend(_format_crtsh(crtsh_r))
    lines.extend(_format_wayback(wayback_r))
    lines.extend(_format_urlscan(urlscan_r))

    return "\n".join(lines)
