# services/formatters.py
"""
UI/Presentation formatters for Sentinel events.
Strict separation from orchestration logic (main.py).
Outputs Markdown; converted to MessageEntity by the sender layer.
"""

import re

from services.ip_enrich import enrich_ip
from services.net_parser import extract_ip_from_conn_string
from services.sentinel_events import SentinelEvent
from services.telegram.headers import SEPARATOR
from services.time_format import format_event_time

# First-line severity emoji emitted by `alert_dispatcher._format_alert`
# (🔴 critical / malicious, 🟠 warn, 🟡 suspicious, 🟢 ok, ⚪ info).
# We surface it in the message header so the top-of-message indicator
# matches the underlying assessment instead of always showing 🚨.
_SEVERITY_EMOJI_RE = re.compile(r"^(🔴|🟠|🟡|🟢|⚪)")


def _header_emoji(analysis: str) -> str:
    """Pick the header emoji based on the dispatched alert severity."""
    if analysis:
        m = _SEVERITY_EMOJI_RE.match(analysis.lstrip())
        if m:
            return m.group(1)
    return "🚨"


def _format_proc(p: dict) -> str:
    """Format a single top-procs entry: `name:pid (cpu%)`. PID always shown
    for consistency with the `Net:` line. CPU appended when available."""
    name = p.get("name") or "?"
    pid = p.get("pid")
    cpu = p.get("cpu_percent")
    head = f"{name}:{pid}" if pid is not None else str(name)
    if isinstance(cpu, (int, float)) and cpu > 0:
        return f"{head} ({cpu:.1f}%)"
    return head


def _enrich_conn_line(line: str) -> str:
    """Enrich a `ip:port (proc:pid)` line with GeoIP/ASN context.

    O(1) cache hit when the IP was already enriched upstream by
    `threat_classifier.ConnectionAnalyzer`. Silently returns the original
    line when enrichment yields nothing (e.g. private IPs, missing DBs).
    """
    if not line or "(" not in line:
        return line
    ip = extract_ip_from_conn_string(line)
    if not ip:
        return line
    info = enrich_ip(ip)
    if not info:
        return line
    # Prefer org > country for compact display. Org alone is most
    # informative ("Amazon.com" reveals AWS without needing the IP block).
    label = info.get("org") or info.get("country")
    if not label:
        return line
    # Inject the label right before `(proc:pid)` for visual alignment.
    head, sep, tail = line.partition(" (")
    if not sep:
        return f"{line} [{label}]"
    return f"{head} [{label}] ({tail}"


def _build_remediation_line(rem: dict) -> str:
    """Build the proposed-action line (Block IP / Kill PID) from remediation."""
    if not isinstance(rem, dict):
        return ""
    parts: list[str] = []

    # Standard net-alert actions (Block IP / Kill PID)
    actions = rem.get("actions")
    if actions and isinstance(actions, dict):
        act_parts = []
        if actions.get("ip"):
            act_parts.append(f"Block IP {actions['ip']}")
        if actions.get("pid") is not None:
            act_parts.append(f"Kill PID {actions['pid']}")
        if act_parts:
            parts.append(" | ".join(act_parts))

    # TTP context block for auto-queued kill_process (behavioral detection)
    if rem.get("kill_process_queued"):
        score = rem.get("kill_ttp_score", 0)
        tid = rem.get("kill_technique_id", "?")
        pid = rem.get("kill_pid", "?")
        name = rem.get("kill_process_name", "?")
        signals = rem.get("kill_signals", [])
        cmdline = rem.get("kill_cmdline", "")
        signal_str = "; ".join(signals[:3]) if signals else ""
        lines = [
            f"💀 **Auto-Kill Queued** — PID `{pid}` ({name})",
            f"🎯 MITRE: `{tid}` | Score: `{score}`",
        ]
        if signal_str:
            lines.append(f"🔍 Signals: {signal_str}")
        if cmdline:
            # Truncate cmdline for Telegram readability
            lines.append(f"📋 Cmd: `{cmdline[:150]}`")
        parts.append("\n".join(lines))

    if not parts:
        return ""
    return "\n\n🛠️ **פעולה מוצעת:**\n" + "\n\n".join(parts)


def _build_intel_line(rem: dict) -> str:
    """Build the auto-enrichment (intel-skill) block from remediation.intel."""
    if not isinstance(rem, dict):
        return ""
    intel_data = rem.get("intel")
    if not intel_data:
        return ""
    from services.intel_enricher import format_enrichment_summary

    return "\n\n" + format_enrichment_summary(intel_data)


def _format_alert_event(d: dict, ts: str) -> str:
    """Format an `alert` SentinelEvent into a structured Markdown message."""
    snap = d.get("snapshot", {}) or {}
    # Disk line is rendered ONLY when alerts exist — a literal "OK"
    # adds no value and clutters the header.
    disk_alerts = snap.get("disk_alerts") or []
    # Top procs: enrich each entry with PID + CPU%. The collector
    # filters at >5% normalized CPU, so the count reflects truly
    # heavy processes; label is pluralized accordingly.
    top_procs = (snap.get("top_procs") or [])[:5]
    procs_raw = ", ".join(_format_proc(p) for p in top_procs) or "—"
    procs_label = "תהליכים כבדים" if len(top_procs) != 1 else "תהליך כבד"
    suspicious_lines = snap.get("suspicious_net") or []
    suspicious_raw = ", ".join(_enrich_conn_line(line) for line in suspicious_lines) or "אין"

    cpu = str(d.get("cpu", "?"))
    ram = str(d.get("ram", "?"))
    analysis = (d.get("analysis") or "").strip() or "(ללא ניתוח)"
    emoji = _header_emoji(analysis)

    rem = d.get("remediation") or {}
    rem_line = _build_remediation_line(rem)
    intel_line = _build_intel_line(rem)

    disk_line = f"> 💽 **Disk:** `{', '.join(disk_alerts)}`\n" if disk_alerts else ""

    return (
        f"{emoji} **Sentinel Alert**\n\n"
        f"> ⏱️ **זמן:** `{ts}`\n"
        f"> 💻 **CPU:** `{cpu}%`\n"
        f"> 🧠 **RAM:** `{ram}%`\n"
        f"{disk_line}\n"
        f"🔝 **{procs_label}:** `{procs_raw}`\n"
        f"🌐 **Net:** `{suspicious_raw}`\n"
        f"{intel_line}\n\n"
        f"🧠 **הערכה:**\n"
        f"{analysis}"
        f"{rem_line}"
    )


def _format_critical_override(d: dict, ts: str) -> str:
    """Format a `critical_override` SentinelEvent."""
    cpu = str(d.get("cpu", "?"))
    ram = str(d.get("ram", "?"))
    msg = d.get("message", "Persistent anomaly")

    return (
        f"🔴 **CRITICAL OVERRIDE**\n\n"
        f"> ⏱️ **זמן:** `{ts}`\n"
        f"> 💻 **CPU:** `{cpu}%`\n"
        f"> 🧠 **RAM:** `{ram}%`\n\n"
        f"⚠️ **סטטוס:**\n{msg}"
    )


def _format_threat_hunt(d: dict, ts: str) -> str:
    """Format a `threat_hunt` SentinelEvent for Telegram.

    Extracts the LLM analysis (already a formatted Hebrew report) and
    prefixes it with a severity header + system metrics.
    """
    score = d.get("threat_score", 0.0)
    cpu = d.get("cpu", "?")
    ram = d.get("ram", "?")
    analysis = d.get("analysis", "")
    conns = d.get("suspicious_connections", [])

    # Severity emoji based on score
    if score >= 0.8:
        emoji = "🔴"
        label = "CRITICAL"
    elif score >= 0.6:
        emoji = "🟠"
        label = "HIGH"
    else:
        emoji = "🟡"
        label = "ELEVATED"

    header = (
        f"{emoji} **THREAT HUNT — {label}**\n"
        f"> ⏱️ `{ts}`  |  💻 CPU: `{cpu}%`  |  🧠 RAM: `{ram}%`\n"
        f"> 🎯 **Score:** `{score:.2f}`  |  🌐 חשודים: `{len(conns)}`\n"
        f"{SEPARATOR}\n\n"
    )

    # The analysis is already a formatted report from the LLM.
    # Strip the <SCORE> tag — it's redundant with the header.
    clean = re.sub(r"<SCORE>.*?</SCORE>", "", analysis, flags=re.IGNORECASE).strip()

    # MITRE ATT&CK section (deterministic — from pre-hunt enrichment)
    mitre_techniques = d.get("mitre_techniques", [])
    mitre_block = ""
    if mitre_techniques:
        mitre_lines = [f"\n{SEPARATOR}\n🎯 **MITRE ATT&CK Mapping:**\n"]
        for tech in mitre_techniques[:5]:  # cap at 5 techniques
            tid = tech.get("technique_id", "?")
            name = tech.get("name", "?")
            tactic = tech.get("tactic", "?")
            conf = tech.get("confidence", 0.0)
            mitre_lines.append(f"  `{tid}` {name} [{tactic}] (conf: {conf:.0%})\n")
        mitre_block = "".join(mitre_lines)

    return header + clean + mitre_block


def format_event_for_telegram(event: SentinelEvent) -> str:
    """Format a SentinelEvent into a structured Markdown Telegram message."""
    d = event.data or {}
    et = event.event_type
    ts = format_event_time(event.timestamp)

    if et == "alert":
        return _format_alert_event(d, ts)
    if et == "critical_override":
        return _format_critical_override(d, ts)
    if et == "threat_hunt":
        return _format_threat_hunt(d, ts)
    if et == "daily_digest":
        return d.get("report") or "📅 Daily digest (ריק)"
    if et == "weekly_reflection":
        return d.get("report") or "🧠 Weekly reflection (ריק)"

    return f"[{et}] {d}"
