"""Report Maker security templates — watchlist, incident, security audit, timeline.

Extracted from report_templates.py (SRP).
"""
from datetime import datetime


def _parse_watchlist_values(it: dict) -> tuple[float | None, float | None, float | None]:
    """Parse current/previous/target as floats — returns None tuple on failure."""
    try:
        cur_val = float(it.get("current")) if it.get("current") is not None else None
        prev_val = float(it.get("previous")) if it.get("previous") is not None else None
        target_val = float(it.get("target")) if it.get("target") is not None else None
    except (TypeError, ValueError):
        return None, None, None
    return cur_val, prev_val, target_val


def _calc_delta_str(cur_val: float | None, prev_val: float | None) -> str:
    """Calculate percentage delta string with arrow."""
    if cur_val is not None and prev_val is not None and prev_val != 0:
        delta_pct = 100 * (cur_val - prev_val) / prev_val
        return f"{'📈' if delta_pct > 0 else '📉'} {delta_pct:+.1f}%"
    return "—"


def _calc_target_status(
    cur_val: float | None, target_val: float | None, name: str
) -> tuple[str, str | None]:
    """Returns (status_str, triggered_name_or_None)."""
    if cur_val is None or target_val is None:
        return "—", None
    if cur_val <= target_val:
        return "🎯 הגיע ליעד!", name
    gap_pct = 100 * (cur_val - target_val) / target_val
    return f"⏳ {gap_pct:+.1f}% מעל היעד", None


def _format_watchlist_row(it: dict) -> tuple[str, str | None]:
    """Format one watchlist row — returns (table_line, triggered_name_or_None)."""
    name = it.get("name", "—")
    cur_val, prev_val, target_val = _parse_watchlist_values(it)
    delta_str = _calc_delta_str(cur_val, prev_val)
    status, triggered = _calc_target_status(cur_val, target_val, name)
    url = it.get("url", "")
    name_md = f"[{name}]({url})" if url else name
    line = f"| {name_md} | {it.get('current')} | {it.get('previous')} | {delta_str} | {it.get('target')} | {status} |"
    return line, triggered


def _watchlist_template(items, raw: str) -> str:
    """R3: Price/asset watchlist report with delta tracking."""
    if not isinstance(items, list) or not items:
        return raw[:2000]
    lines = [
        f"# 👁️ Watchlist — {datetime.now().strftime('%d/%m/%Y %H:%M')}\n",
        "| פריט | נוכחי | קודם | שינוי | יעד | סטטוס |",
        "|------|-------|------|--------|-----|--------|",
    ]

    triggered: list[str] = []
    for it in items:
        line, trig = _format_watchlist_row(it)
        lines.append(line)
        if trig:
            triggered.append(trig)

    if triggered:
        lines.append(f"\n## 🚨 הופעלו ({len(triggered)})")
        lines.extend(f"- {t}" for t in triggered)

    return "\n".join(lines)


_INCIDENT_SEV_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def _format_incident_header(items: dict) -> list[str]:
    """Format incident header with severity icon."""
    inc_id = items.get("incident_id", "—")
    sev = (items.get("severity") or "info").upper()
    sev_icon = _INCIDENT_SEV_ICONS.get(sev, "⚪")
    return [
        f"# 🛡️ Sentinel Incident Report — {inc_id}",
        f"**Severity:** {sev_icon} {sev}  |  **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
    ]


def _format_incident_alerts(alerts: list) -> list[str]:
    """Format alerts table section."""
    if not alerts:
        return []
    lines = ["## 🚨 Alerts", "| Time | Severity | Type | Message |", "|------|----------|------|---------|"]
    for a in alerts[:25]:
        asev = (a.get("severity") or "info").upper()
        asev_icon = _INCIDENT_SEV_ICONS.get(asev, "⚪")
        msg = (a.get("message") or "")[:120].replace("|", "\\|")
        lines.append(f"| {a.get('ts', '—')} | {asev_icon} {asev} | {a.get('type', '—')} | {msg} |")
    lines.append("")
    return lines


def _format_incident_iocs(iocs: list) -> list[str]:
    """Format IOCs table with score-based verdict."""
    if not iocs:
        return []
    lines = ["## 🛰 Indicators of Compromise (IOCs)", "| Kind | Value | Score | Verdict |", "|------|-------|-------|---------|"]
    for ioc in iocs[:30]:
        score = int(ioc.get("score") or 0)
        verdict = (
            "🔴 malicious" if score >= 75
            else ("🟠 suspicious" if score >= 40
                  else ("🟡 review" if score >= 10 else "🟢 clean"))
        )
        lines.append(f"| {ioc.get('kind', '—')} | `{ioc.get('value', '—')}` | {score}/100 | {verdict} |")
    lines.append("")
    return lines


def _format_incident_remediation(rem: list) -> list[str]:
    """Format remediation actions table."""
    if not rem:
        return []
    lines = ["## 🛠 Remediation Actions", "| Time | Action | Target | Result |", "|------|--------|--------|--------|"]
    for r in rem[:25]:
        lines.append(
            f"| {r.get('ts', '—')} | {r.get('action', '—')} | "
            f"`{r.get('target', '—')}` | {r.get('result', '—')} |"
        )
    lines.append("")
    return lines


def _format_incident_timeline(tl: list) -> list[str]:
    """Format timeline section (sorted by timestamp)."""
    if not tl:
        return []
    lines = ["## ⏱ Timeline"]
    for t in sorted(tl, key=lambda x: str(x.get("ts", ""))):
        lines.append(f"- **{t.get('ts', '—')}** — {t.get('event', '')}")
    return lines


def _incident_report_template(items, raw: str) -> str:
    """R4: Sentinel SOC incident report."""
    if not isinstance(items, dict):
        return raw[:2000]
    lines = _format_incident_header(items)
    if summary := items.get("summary"):
        lines.append(f"## Executive Summary\n\n{summary}\n")
    lines.extend(_format_incident_alerts(items.get("alerts")))
    lines.extend(_format_incident_iocs(items.get("iocs")))
    lines.extend(_format_incident_remediation(items.get("remediation")))
    lines.extend(_format_incident_timeline(items.get("timeline")))
    return "\n".join(lines)


def _audit_firewall_section(fw: dict) -> list[str]:
    if not fw:
        return []
    lines = ["## 🔥 Firewall"]
    lines.append(f"- **Active blocks:** {fw.get('active_blocks', 0)}")
    lines.append(f"- **DROP events (24h):** {fw.get('drops_24h', 0)}")
    if top := fw.get("top_sources"):
        lines.append("- **Top sources:**")
        for src, n in top[:5]:
            lines.append(f"  - `{src}` × {n}")
    lines.append("")
    return lines


def _audit_defender_section(df: dict) -> list[str]:
    if not df:
        return []
    lines = ["## 🛡 Windows Defender"]
    lines.append(f"- **Last scan:** {df.get('last_scan', '—')}")
    threats = df.get("threats_found", 0)
    threat_icon = "🔴" if threats else "✅"
    lines.append(f"- **Threats found:** {threat_icon} {threats}")
    age = df.get("definitions_age_h")
    if age is not None:
        age_icon = "✅" if age < 24 else ("🟡" if age < 72 else "🔴")
        lines.append(f"- **Definitions age:** {age_icon} {age}h")
    lines.append("")
    return lines


def _audit_users_section(us: dict) -> list[str]:
    if not us:
        return []
    lines = ["## 👥 Users / Sessions"]
    lines.append(f"- **Local users:** {us.get('local', 0)}")
    lines.append(f"- **Active sessions:** {us.get('active_sessions', 0)}")
    if us.get("rdp_active"):
        lines.append("- **RDP:** ⚠️ פעיל")
    lines.append("")
    return lines


def _audit_iocs_section(iocs) -> list[str]:
    if not iocs:
        return []
    lines = ["## 🛰 IOCs (יום אחרון)", "| Kind | Value | Score |", "|------|-------|-------|"]
    for ioc in iocs[:20]:
        lines.append(f"| {ioc.get('kind', '—')} | `{ioc.get('value', '—')}` | {ioc.get('score', 0)} |")
    lines.append("")
    return lines


def _audit_patches_section(patches: dict) -> list[str]:
    if not patches:
        return []
    miss = patches.get("missing", 0)
    icon = "✅" if miss == 0 else ("🟡" if miss < 5 else "🔴")
    return ["## 🩹 Patches", f"- **Missing:** {icon} {miss}", f"- **Last install:** {patches.get('last_install', '—')}"]


def _security_audit_template(items, raw: str) -> str:
    """R5: Daily security posture report."""
    if not isinstance(items, dict):
        return raw[:2000]
    host = items.get("host", "—")
    ts = items.get("ts", datetime.now().strftime("%Y-%m-%d %H:%M"))
    lines = [f"# 🛡️ Daily Security Audit — {host}", f"_Generated: {ts}_\n"]

    lines += _audit_firewall_section(items.get("firewall") or {})
    lines += _audit_defender_section(items.get("defender") or {})
    lines += _audit_users_section(items.get("users") or {})
    lines += _audit_iocs_section(items.get("iocs"))
    lines += _audit_patches_section(items.get("patches") or {})

    return "\n".join(lines)


def _timeline_template(items, raw: str) -> str:
    """Chronological events. Sorts by 'date'/'timestamp'/'published' if present."""
    if not items:
        return raw[:2000]

    def _key(it):
        if not isinstance(it, dict):
            return ""
        return str(it.get("date") or it.get("timestamp") or it.get("time") or it.get("published") or "")

    sorted_items = sorted(items, key=_key)
    lines = ["## ⏱ ציר זמן\n"]
    for it in sorted_items:
        if isinstance(it, dict):
            ts = _key(it) or "—"
            title = it.get("title") or it.get("event") or it.get("name") or ""
            desc = it.get("description") or it.get("summary") or ""
            lines.append(f"- **{ts}** — {title}")
            if desc:
                lines.append(f"  - {str(desc)[:300]}")
        else:
            lines.append(f"- {it}")
    return "\n".join(lines)
