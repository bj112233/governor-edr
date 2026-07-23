"""Intel Skill — Renderer (presentation layer).

Pure function: payload(dict) -> Markdown(str). No I/O, no scoring, no globals.
"""

from __future__ import annotations

from typing import Any

from threat_scoring import verdict_emoji


def _render_header(payload: dict[str, Any]) -> list[str]:
    """Header: title, score, verdict, reverse DNS, A records."""
    score = payload["score"]
    target = payload["target"]
    kind = payload["kind"]
    lines = [
        f"# 🛰️ Intel Report — {target}",
        f"**Kind:** {kind}  |  **Score:** {score}/100  |  {verdict_emoji(score)}",
        "",
    ]
    if payload.get("ptr"):
        lines.append(f"**Reverse DNS:** `{payload['ptr']}`")
    if dns_rec := payload.get("dns"):
        a_rec = dns_rec.get("A") or []
        if a_rec:
            lines.append(f"**A:** {', '.join(a_rec[:5])}")
    return lines


def _render_shodan(shodan: dict[str, Any]) -> list[str]:
    """Shodan network exposure section."""
    if not shodan.get("available"):
        return []
    lines = ["\n## 🔍 Network Exposure (Shodan)"]
    ports = shodan.get("ports", [])
    if ports:
        lines.append(f"- **Ports:** {', '.join(str(p) for p in ports)}")
    if shodan.get("os"):
        lines.append(f"- **OS:** {shodan['os']}")
    if shodan.get("org"):
        lines.append(f"- **Org:** {shodan['org']}")
    if shodan.get("asn"):
        lines.append(f"- **ASN:** AS{shodan['asn']}")
    vulns = shodan.get("vulns", [])
    if vulns:
        lines.append(f"- **CVEs ({len(vulns)}):** {', '.join(vulns[:8])}")
    tags = shodan.get("tags", [])
    if tags:
        lines.append(f"- **Tags:** {', '.join(tags[:5])}")
    return lines


def _render_ipapi(ipapi: dict[str, Any]) -> list[str]:
    """ipapi.co IP metadata section."""
    if not ipapi.get("available"):
        return []
    lines = ["\n## 🌍 IP Metadata"]
    cc = ipapi.get("country") or ipapi.get("country_code")
    city = ipapi.get("city")
    region = ipapi.get("region")
    loc_parts = [p for p in [city, region, cc] if p]
    if loc_parts:
        lines.append(f"- **Location:** {', '.join(loc_parts)}")
    if ipapi.get("asn"):
        lines.append(f"- **ASN:** AS{ipapi['asn']}")
    if ipapi.get("org"):
        lines.append(f"- **Org:** {ipapi['org']}")
    flags = []
    if ipapi.get("proxy"):
        flags.append("🟠 Proxy")
    if ipapi.get("vpn"):
        flags.append("🔴 VPN")
    if ipapi.get("tor"):
        flags.append("🔴 Tor")
    if ipapi.get("hosting"):
        flags.append("🟡 Hosting/Datacenter")
    if flags:
        lines.append(f"- **Flags:** {', '.join(flags)}")
    return lines


def _render_virustotal(vt: dict[str, Any]) -> list[str]:
    """VirusTotal section."""
    if not (vt.get("available") and vt.get("found")):
        return []
    lines = ["\n## 🛡️ VirusTotal"]
    votes = vt.get("total_votes", {})
    if votes:
        lines.append(
            f"- **Community Votes:** harmless={votes.get('harmless', 0)}, "
            f"malicious={votes.get('malicious', 0)}"
        )
    tags = vt.get("tags", [])
    if tags:
        lines.append(f"- **Tags:** {', '.join(tags[:6])}")
    asn = vt.get("network_asn")
    owner = vt.get("network_as_owner")
    rir = vt.get("regional_internet_registry")
    net_parts = [f"AS{asn}" if asn else None, owner, rir]
    if any(net_parts):
        lines.append(f"- **Network:** {', '.join(p for p in net_parts if p)}")
    if lad := vt.get("last_analysis_date"):
        lines.append(f"- **Last Scan:** {lad}")
    return lines


def _render_maltiverse(maltiverse: dict[str, Any]) -> list[str]:
    """Maltiverse section."""
    if not (maltiverse.get("available") and maltiverse.get("found")):
        return []
    lines = ["\n## 🛡️ Maltiverse"]
    cls = maltiverse.get("classification", "unknown")
    emoji = "🔴" if cls == "malicious" else ("🟠" if cls == "suspicious" else "🟢")
    lines.append(f"- **Classification:** {emoji} {cls}")
    if maltiverse.get("blacklist_count"):
        lines.append(f"- **Blacklists:** {maltiverse['blacklist_count']}")
    if maltiverse.get("tags"):
        lines.append(f"- **Tags:** {', '.join(maltiverse['tags'][:8])}")
    if maltiverse.get("score"):
        lines.append(f"- **Score:** {maltiverse['score']}")
    return lines


def _render_israeli_sources(sources: dict[str, Any]) -> list[str]:
    """Israeli source indicators: .il domain, Hebrew phishing, AbuseIPDB."""
    lines = ["\n## 🇮🇱 מקורות ישראליים"]
    for name, src in sources.items():
        lines.extend(_render_single_israeli_source(name, src))
    return lines


def _render_single_israeli_source(name: str, src: dict[str, Any]) -> list[str]:
    """Render one Israeli source entry."""
    if name == "il_domain":
        return _render_il_domain(src)
    if name == "hebrew_phishing":
        return _render_hebrew_phishing(src)
    if name == "abuseipdb" and src.get("available"):
        return [
            f"- **AbuseIPDB**: confidence={src.get('abuse_confidence')}/100, "
            f"reports={src.get('total_reports')}"
        ]
    return []


def _render_il_domain(src: dict[str, Any]) -> list[str]:
    """Render .il domain indicator."""
    if not src.get("is_il_domain"):
        return []
    if src.get("suspicious_indicators"):
        lines = ["- **Israeli Domain**: דומיין .il מזוהה"]
        for indicator in src["suspicious_indicators"]:
            lines.append(f"  - ⚠️ {indicator}")
        return lines
    return ["- **Israeli Domain**: דומיין .il תקין"]


def _render_hebrew_phishing(src: dict[str, Any]) -> list[str]:
    """Render Hebrew phishing detection."""
    if not src.get("hebrew_detected"):
        return ["- **Hebrew Phishing**: לא זוהה"]
    lines = ["- **Hebrew Phishing**: זוהה פישינג בעברית"]
    lines.append(f"  - 🎯 Risk Score: {src.get('risk_score', 0)}")
    for pattern in src.get("patterns_found", []):
        lines.append(f"  - 📝 Pattern: {pattern}")
    return lines


def _render_mitre(mitre: list[dict[str, Any]]) -> list[str]:
    """MITRE ATT&CK mapping section."""
    if not mitre:
        return []
    lines = ["\n## 🎯 MITRE ATT&CK Mapping"]
    for m in mitre:
        conf = m.get("confidence", 0)
        bar = "█" * int(conf * 5) + "░" * (5 - int(conf * 5))
        lines.append(
            f"- **{m['technique_id']}** {m['name']} "
            f"({m['tactic']}) [{bar} {conf:.0%}]"
        )
        for sig in m.get("signals", []):
            lines.append(f"  - 📡 {sig}")
    return lines


class IntelRenderer:
    """Formats raw intel payloads into Markdown. Stateless."""

    def render(self, payload: dict[str, Any]) -> str:
        if payload.get("status") == "invalid":
            return f"❌ {payload.get('error', 'קלט לא תקין')}"

        sources = payload.get("sources", {})
        lines = [
            *_render_header(payload),
            *_render_shodan(sources.get("shodan", {})),
            *_render_ipapi(sources.get("ipapi_co", {})),
            *_render_virustotal(sources.get("virustotal", {})),
            *_render_maltiverse(sources.get("maltiverse", {})),
            *_render_israeli_sources(sources),
            *_render_mitre(payload.get("mitre_techniques", [])),
        ]
        return "\n".join(lines)
