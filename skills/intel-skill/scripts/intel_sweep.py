"""Intel skill sweep command — network connection triage funnel.

Extracted from intel_facade.py. cmd_sweep was F(52) CC — split into
7 focused helpers.
"""
from __future__ import annotations

import json
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from _utils import is_private_ip
from data_enrichment import is_high_risk_country, is_known_good_asn
from osint_gatherer import abuseipdb, ipapi_co, maltiverse_ip, shodan, virustotal
from threat_scoring import score_ip


def _collect_connections() -> tuple[set[str], dict[str, dict[str, Any]]]:
    """Gather ESTABLISHED connections from psutil, return (unique_ips, conn_info)."""
    try:
        import psutil
    except ImportError:
        return set(), {}

    unique_ips: set[str] = set()
    conn_info: dict[str, dict[str, Any]] = {}

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
            continue
        ip = conn.raddr.ip
        if is_private_ip(ip):
            continue
        unique_ips.add(ip)
        if ip not in conn_info:
            conn_info[ip] = {"procs": set(), "ports": set(), "laddrs": set()}
        proc_name = "Unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        conn_info[ip]["procs"].add(proc_name)
        conn_info[ip]["ports"].add(conn.raddr.port)
        conn_info[ip]["laddrs"].add(f"{conn.laddr.ip}:{conn.laddr.port}")

    return unique_ips, conn_info


def _light_enrich_batch(unique_ips: set[str]) -> dict[str, dict[str, Any]]:
    """Parallel light enrichment (maltiverse + ipapi) for all IPs."""
    def _light_enrich(ip: str) -> tuple[str, dict[str, Any]]:
        return ip, {"maltiverse": maltiverse_ip(ip), "ipapi": ipapi_co(ip)}

    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_light_enrich, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip, result = future.result()
            results[ip] = result
    return results


def _classify_ips(
    unique_ips: set[str], light_results: dict[str, dict[str, Any]]
) -> tuple[list[str], list[str]]:
    """Split IPs into (deep_ips, safe_ips) based on light enrichment."""
    deep_ips: list[str] = []
    safe_ips: list[str] = []

    for ip in unique_ips:
        maltiverse = light_results[ip]["maltiverse"]
        ipapi = light_results[ip]["ipapi"]
        needs_deep = False

        if maltiverse.get("found") and maltiverse.get("classification") in ("malicious", "suspicious"):
            needs_deep = True
        if ipapi.get("vpn") or ipapi.get("tor") or ipapi.get("proxy"):
            needs_deep = True
        cc = maltiverse.get("country_code") or ipapi.get("country_code")
        if is_high_risk_country(cc):
            needs_deep = True

        asn = maltiverse.get("asn") or ipapi.get("asn")
        org = maltiverse.get("org") or ipapi.get("org")
        if is_known_good_asn(asn, org) and not needs_deep:
            safe_ips.append(ip)
            continue

        if needs_deep:
            deep_ips.append(ip)
        else:
            safe_ips.append(ip)

    return deep_ips, safe_ips


def _deep_enrich_batch(deep_ips: list[str]) -> dict[str, dict[str, Any]]:
    """Deep enrichment (VT + Shodan) for flagged IPs."""
    results: dict[str, dict[str, Any]] = {}
    for ip in deep_ips:
        results[ip] = {
            "virustotal": virustotal(ip, "ip_addresses"),
            "shodan": shodan(ip),
        }
        _time.sleep(2)
    return results


def _build_sweep_reports(
    unique_ips: set[str],
    conn_info: dict[str, dict[str, Any]],
    light_results: dict[str, dict[str, Any]],
    deep_results: dict[str, dict[str, Any]],
    threshold: int,
) -> list[dict[str, Any]]:
    """Build report dicts for IPs exceeding threshold."""
    reports: list[dict[str, Any]] = []
    for ip in unique_ips:
        info = conn_info[ip]
        maltiverse = light_results[ip]["maltiverse"]
        ipapi = light_results[ip]["ipapi"]
        vt = deep_results.get(ip, {}).get("virustotal", {})
        shodan_data = deep_results.get(ip, {}).get("shodan", {})
        abuse = abuseipdb(ip)
        score = score_ip(abuse, maltiverse, vt, ipapi, shodan_data)

        if score >= threshold:
            reports.append({
                "ip": ip, "score": score,
                "procs": sorted(info["procs"]),
                "ports": sorted(info["ports"]),
                "laddrs": sorted(info["laddrs"]),
                "sources": {
                    "abuseipdb": abuse, "maltiverse": maltiverse,
                    "ipapi_co": ipapi, "virustotal": vt, "shodan": shodan_data,
                },
            })
    reports.sort(key=lambda r: r["score"], reverse=True)
    return reports


def _format_ipapi_section(ipapi: dict[str, Any]) -> list[str]:
    """Format ipapi.co location + flags section."""
    if not ipapi.get("available"):
        return []
    lines: list[str] = []
    loc_parts = [p for p in [ipapi.get("city"), ipapi.get("region"), ipapi.get("country")] if p]
    if loc_parts:
        lines.append(f"- **Location:** {', '.join(loc_parts)}")
    flags = []
    if ipapi.get("vpn"):
        flags.append("🔴 VPN")
    if ipapi.get("tor"):
        flags.append("🔴 Tor")
    if ipapi.get("proxy"):
        flags.append("🟠 Proxy")
    if ipapi.get("hosting"):
        flags.append("🟡 Hosting")
    if flags:
        lines.append(f"- **Flags:** {', '.join(flags)}")
    return lines


def _format_maltiverse_section(maltiverse: dict[str, Any]) -> list[str]:
    """Format Maltiverse classification + blacklists + tags."""
    if not (maltiverse.get("available") and maltiverse.get("found")):
        return []
    lines = [
        f"- **Maltiverse:** {maltiverse.get('classification')} "
        f"({maltiverse.get('blacklist_count', 0)} blacklists)"
    ]
    if maltiverse.get("tags"):
        lines.append(f"- **Tags:** {', '.join(maltiverse['tags'][:5])}")
    return lines


def _format_vt_section(vt: dict[str, Any]) -> list[str]:
    """Format VirusTotal malicious/harmless counts."""
    if not (vt.get("available") and vt.get("found")):
        return []
    return [f"- **VT:** {vt.get('malicious', 0)} malicious / {vt.get('harmless', 0)} harmless"]


def _format_shodan_section(shodan_data: dict[str, Any]) -> list[str]:
    """Format Shodan ports + CVEs."""
    if not shodan_data.get("available"):
        return []
    lines: list[str] = []
    ports = shodan_data.get("ports", [])
    if ports:
        lines.append(f"- **Shodan ports:** {', '.join(str(p) for p in ports[:8])}")
    vulns = shodan_data.get("vulns", [])
    if vulns:
        lines.append(f"- **CVEs:** {', '.join(vulns[:5])}")
    return lines


def _format_single_report(r: dict[str, Any]) -> list[str]:
    """Format one flagged IP report entry."""
    emoji = "🔴" if r["score"] >= 70 else ("🟠" if r["score"] >= 40 else "🟡")
    lines = [
        f"\n## {emoji} {r['ip']} — Score: {r['score']}/100",
        f"- **Processes:** {', '.join(r['procs'])}",
        f"- **Local:** {', '.join(r['laddrs'])}",
        f"- **Remote ports:** {', '.join(str(p) for p in r['ports'])}",
    ]
    sources = r["sources"]
    lines.extend(_format_ipapi_section(sources["ipapi_co"]))
    lines.extend(_format_maltiverse_section(sources["maltiverse"]))
    lines.extend(_format_vt_section(sources["virustotal"]))
    lines.extend(_format_shodan_section(sources["shodan"]))
    return lines


def _format_sweep_report(
    reports: list[dict[str, Any]],
    unique_ips: set[str],
    deep_ips: list[str],
    threshold: int,
    fmt: str,
) -> str:
    """Format sweep results as JSON or Markdown."""
    if fmt == "json":
        return json.dumps({
            "kind": "sweep",
            "total_connections": len(unique_ips),
            "deep_enriched": len(deep_ips),
            "threshold": threshold,
            "flagged": len(reports),
            "reports": reports,
        }, ensure_ascii=False, indent=2)

    lines = [
        "# 🛰️ Network Sweep Report",
        f"**Total unique IPs:** {len(unique_ips)}  |  "
        f"**Deep enriched:** {len(deep_ips)}  |  "
        f"**Flagged (≥{threshold}):** {len(reports)}",
    ]

    for r in reports:
        lines.extend(_format_single_report(r))

    if not reports:
        lines.append("\n✅ No connections exceeded the threat threshold.")

    return "\n".join(lines)


def cmd_sweep(threshold: int, fmt: str) -> str:
    """Triage funnel sweep of active ESTABLISHED connections."""
    unique_ips, conn_info = _collect_connections()
    if not unique_ips:
        return "✅ No external connections detected."

    light_results = _light_enrich_batch(unique_ips)
    deep_ips, _safe_ips = _classify_ips(unique_ips, light_results)
    deep_results = _deep_enrich_batch(deep_ips)
    reports = _build_sweep_reports(
        unique_ips, conn_info, light_results, deep_results, threshold
    )
    return _format_sweep_report(reports, unique_ips, deep_ips, threshold, fmt)
