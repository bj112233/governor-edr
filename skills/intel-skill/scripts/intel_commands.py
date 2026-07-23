"""Intel skill secondary commands — dns, whois, israeli monitor, cert, cluster.

Extracted from intel_facade.py (SRP).
"""
from __future__ import annotations

import json
from typing import Any

from _utils import cosine_similarity, embed_texts, looks_like_domain, looks_like_hash, looks_like_ip
from data_enrichment import (
    dns_lookup,
    hebrew_phishing_detection,
    israeli_domain_monitoring,
    rdap,
    reverse_dns,
)
from osint_gatherer import abuseipdb
from threat_scoring import score_ip, score_with_israeli_factors


def cmd_dns(target: str, fmt: str) -> str:
    rec = dns_lookup(target)
    if fmt == "json":
        return json.dumps(rec, ensure_ascii=False, indent=2)
    lines = [f"# 🛰️ DNS — {target}"]
    for k in ("A", "AAAA", "MX", "TXT", "NS"):
        vals = rec.get(k) or []
        if vals:
            lines.append(f"## {k}")
            for v in vals:
                lines.append(f"- `{v}`")
    if rec.get("note"):
        lines.append(f"\n_{rec['note']}_")
    if rec.get("error"):
        lines.append(f"\n❌ {rec['error']}")
    return "\n".join(lines)


def cmd_whois(target: str, fmt: str) -> str:
    rdap_data = rdap(target)
    if fmt == "json":
        return json.dumps(rdap_data, ensure_ascii=False, indent=2)
    if not rdap_data.get("available"):
        return f"❌ RDAP נכשל: {rdap_data.get('error', 'unknown')}"
    return (
        f"# 📜 WHOIS (RDAP) — {target}\n\n"
        f"- **Handle:** `{rdap_data.get('handle') or '—'}`\n"
        f"- **שם רשום:** {rdap_data.get('name') or '—'}\n"
        f"- **נרשם ב:** {rdap_data.get('registered') or '—'}\n"
        f"- **פג תוקף:** {rdap_data.get('expires') or '—'}\n"
        f"- **שינוי אחרון:** {rdap_data.get('last_changed') or '—'}\n"
        f"- **Status:** {', '.join(rdap_data.get('status') or []) or '—'}"
    )


def cmd_israeli_monitor(target: str, fmt: str, render_fn=None) -> str:
    """פקודת מעקב ישראלי משודרגת"""
    if looks_like_ip(target):
        abuse = abuseipdb(target)
        base_score = score_ip(abuse, {}, {}, {}, {})
        reverse = reverse_dns(target)
        hebrew_phish = hebrew_phishing_detection(reverse or "")
        il_domain_check = {"is_il_domain": False, "suspicious_indicators": []}
        final_score = score_with_israeli_factors(base_score, il_domain_check, hebrew_phish)
        payload = {
            "target": target, "kind": "ip", "score": final_score,
            "ptr": reverse, "dns": dns_lookup(target) if reverse else {},
            "sources": {"abuseipdb": abuse, "hebrew_phishing": hebrew_phish, "il_domain": il_domain_check},
        }
    else:
        il_domain_check = israeli_domain_monitoring(target)
        hebrew_phish = hebrew_phishing_detection(target)
        dns_rec = dns_lookup(target)
        base_score = 0
        if il_domain_check.get("suspicious_indicators"):
            base_score += len(il_domain_check["suspicious_indicators"]) * 20
        if hebrew_phish.get("hebrew_detected"):
            base_score += hebrew_phish.get("risk_score", 0)
        final_score = min(base_score, 100)
        payload = {
            "target": target, "kind": "domain", "score": final_score,
            "sources": {"il_domain": il_domain_check, "hebrew_phishing": hebrew_phish},
            "dns": dns_rec,
        }

    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2)
    if render_fn:
        return render_fn(payload)
    return json.dumps(payload, ensure_ascii=False, indent=2)


def cmd_cert_il(fmt: str) -> str:
    """פקודת CERT-IL feed — מציג התראות אחרונות + IOCs שחולצו."""
    from cert_il_feed import cert_il_feed

    feed = cert_il_feed()
    if fmt == "json":
        return json.dumps(feed, ensure_ascii=False, indent=2)
    if not feed.get("available"):
        return f"❌ CERT-IL feed לא זמין: {feed.get('error', 'unknown')}"

    alerts = feed.get("alerts", [])
    if not alerts:
        return "✅ CERT-IL: אין התראות חדשות."

    all_iocs = feed.get("all_iocs", {})
    lines = [
        f"# 🇮🇱 CERT-IL — {feed.get('alerts_count', 0)} התראות אחרונות",
        f"_מקור: {feed.get('source_url', 'N/A')}_\n",
    ]

    for i, alert in enumerate(alerts, 1):
        lines.append(f"## {i}. {alert['title']}")
        if alert.get("date"):
            lines.append(f"📅 {alert['date']}")
        if alert.get("summary"):
            # Truncate long summaries
            summary = alert["summary"][:300]
            if len(alert["summary"]) > 300:
                summary += "..."
            lines.append(f"\n{summary}")
        if alert.get("link"):
            lines.append(f"\n🔗 {alert['link']}")

        iocs = alert.get("iocs", {})
        ioc_parts = []
        for label, key in [("IPs", "ips_v4"), ("Domains", "domains"), ("CVEs", "cves"),
                           ("URLs", "urls"), ("Hashes", "hashes"), ("CIDRs", "cidrs"),
                           ("ASNs", "asns"), ("Emails", "emails")]:
            vals = iocs.get(key, [])
            if vals:
                ioc_parts.append(f"**{label}**: {', '.join(vals[:5])}")
        if ioc_parts:
            lines.append("\n**IOCs שחולצו:**")
            for p in ioc_parts:
                lines.append(f"- {p}")
        lines.append("")

    # Summary of all merged IOCs
    total_iocs = sum(len(v) for v in all_iocs.values())
    if total_iocs:
        lines.append("---")
        lines.append(f"**סה\"כ IOCs שחולצו: {total_iocs}**")
        for label, key in [("IPs", "ips_v4"), ("Domains", "domains"), ("CVEs", "cves"),
                           ("URLs", "urls"), ("Hashes", "hashes")]:
            vals = all_iocs.get(key, [])
            if vals:
                lines.append(f"- {label}: {len(vals)}")

    return "\n".join(lines)


def cmd_cluster(
    targets: list[str],
    threshold: float,
    fmt: str,
    cmd_ip_fn=None,
    cmd_domain_fn=None,
    cmd_hash_fn=None,
) -> str:
    """Cluster multiple IOCs by semantic similarity of their intel reports."""
    reports: list[tuple[str, str]] = []
    for t in targets:
        t = t.strip().strip("\"'")
        if not t:
            continue
        if looks_like_ip(t):
            r = (cmd_ip_fn or (lambda x, f: ""))(t, "markdown")
        elif looks_like_domain(t):
            r = (cmd_domain_fn or (lambda x, f: ""))(t, "markdown")
        elif looks_like_hash(t):
            r = (cmd_hash_fn or (lambda x, f: ""))(t, "markdown")
        else:
            r = f"❌ לא זוהה סוג IOC: {t}"
        reports.append((t, r))

    if len(reports) < 2:
        return "❌ דרושים לפחות 2 targets ל-clustering"

    vectors = embed_texts([r for _, r in reports])
    if not vectors or len(vectors) != len(reports):
        lines = ["# 🛰️ Threat Clustering (fallback — no embeddings)\n"]
        for t, r in reports:
            lines.append(f"## {t}")
            lines.append(r)
            lines.append("")
        return "\n".join(lines)

    clusters: list[list[tuple[str, str]]] = []
    assigned = [False] * len(reports)
    for i in range(len(reports)):
        if assigned[i]:
            continue
        cluster = [reports[i]]
        assigned[i] = True
        for j in range(i + 1, len(reports)):
            if not assigned[j] and cosine_similarity(vectors[i], vectors[j]) >= threshold:
                cluster.append(reports[j])
                assigned[j] = True
        clusters.append(cluster)

    if fmt == "json":
        payload = {
            "clusters": [{"members": [t for t, _ in c], "count": len(c)} for c in clusters],
            "threshold": threshold,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    lines = [f"# 🛰️ Threat Clustering ({len(reports)} IOCs, threshold={threshold})\n"]
    for idx, cluster in enumerate(clusters, 1):
        lines.append(f"## Cluster {idx} ({len(cluster)} members)")
        for t, r in cluster:
            lines.append(f"### {t}")
            lines.append(r)
            lines.append("")
    return "\n".join(lines)


def cmd_attack(technique_id: str, fmt: str) -> str:
    """MITRE ATT&CK technique lookup — returns details + signal mapping.

    Always returns JSON when called from the agent (skill sandbox requires JSON).
    The `fmt` parameter defaults to "json" in the facade argparse; markdown is
    only for direct CLI use by humans.
    """
    from mitre_attack_db import CVE_TECHNIQUE_MAP, PORT_MAP, TAG_MAP
    from mitre_mapping import lookup_technique

    tech = lookup_technique(technique_id)
    if not tech:
        # Always return JSON for unknown techniques — the skill sandbox validator
        # rejects non-JSON output, leaving the agent blind to the error.
        return json.dumps({"available": False, "error": f"Unknown technique: {technique_id}"}, ensure_ascii=False)

    # Reverse-lookup which signals map to this technique
    signals = {
        "ports": [str(p) for p, t in PORT_MAP.items() if t == tech.id],
        "tags": [t for t, tid in TAG_MAP.items() if tid == tech.id],
        "cves": [c for c, tid in CVE_TECHNIQUE_MAP.items() if tid == tech.id],
    }

    if fmt == "json":
        return json.dumps({
            "available": True,
            "technique_id": tech.id,
            "name": tech.name,
            "tactic": tech.tactic,
            "description": tech.description,
            "max_signals": tech.max_signals,
            "trigger_signals": signals,
        }, ensure_ascii=False, indent=2)

    lines = [
        f"# 🎯 MITRE ATT&CK — {tech.id}",
        f"**Name:** {tech.name}",
        f"**Tactic:** {tech.tactic}",
        f"**Description:** {tech.description}",
        f"**Max signals (confidence denominator):** {tech.max_signals}",
        "",
        "## Trigger Signals",
    ]
    if signals["ports"]:
        lines.append(f"- **Ports:** {', '.join(signals['ports'])}")
    if signals["tags"]:
        lines.append(f"- **Tags/Flags:** {', '.join(signals['tags'])}")
    if signals["cves"]:
        lines.append(f"- **Known CVEs:** {', '.join(signals['cves'])}")
    if not any(signals.values()):
        lines.append("- (no direct signal mappings — triggered via domain age or other heuristics)")
    return "\n".join(lines)


def cmd_feeds(source: str, fmt: str, limit: int = 50) -> str:
    """Live threat feeds — URLhaus + ThreatFox IOC display."""
    from osint_gatherer import threatfox_feed, urlhaus_feed

    if source == "urlhaus":
        data = urlhaus_feed(limit)
        return _render_feed("URLhaus", data, fmt)
    elif source == "threatfox":
        data = threatfox_feed(1)
        return _render_feed("ThreatFox", data, fmt)
    elif source == "all":
        uh = urlhaus_feed(limit)
        tf = threatfox_feed(1)
        if fmt == "json":
            return json.dumps(
                {"urlhaus": uh, "threatfox": tf},
                ensure_ascii=False, indent=2,
            )
        parts = [_render_feed("URLhaus", uh, "markdown"), "", _render_feed("ThreatFox", tf, "markdown")]
        return "\n".join(parts)
    if fmt == "json":
        return json.dumps({"available": False, "error": f"Unknown source: {source}"}, ensure_ascii=False)
    return f"❌ מקור לא מוכר: {source}. אפשרויות: urlhaus, threatfox, all"


def _render_feed(name: str, data: dict, fmt: str) -> str:
    """Render a single feed's data as Markdown or JSON."""
    if fmt == "json":
        return json.dumps(data, ensure_ascii=False, indent=2)

    iocs = data.get("iocs", {})
    count = data.get("count", 0)
    lines = [
        f"# 🛰️ {name} — Live Threat Feed",
        f"**IOCs fetched:** {count}",
        "",
    ]
    for ioc_type in ("urls", "domains", "ips", "hashes"):
        values = iocs.get(ioc_type, [])
        if values:
            label = {"urls": "URLs", "domains": "Domains", "ips": "IPs", "hashes": "Hashes"}[ioc_type]
            lines.append(f"## {label} ({len(values)})")
            for v in values[:20]:
                lines.append(f"- `{v}`")
            if len(values) > 20:
                lines.append(f"- ... and {len(values) - 20} more")
            lines.append("")

    malware_map = data.get("malware_map", {})
    if malware_map:
        lines.append(f"## Malware Families ({len(malware_map)})")
        for ioc, malware in list(malware_map.items())[:10]:
            lines.append(f"- `{ioc}` → **{malware}**")
        if len(malware_map) > 10:
            lines.append(f"- ... and {len(malware_map) - 10} more")

    if not any(iocs.values()):
        lines.append("(no IOCs in feed — check Auth-Key or try again later)")

    return "\n".join(lines)
