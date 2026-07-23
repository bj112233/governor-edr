# services/telegram/handlers_render.py
"""Pure rendering functions for Telegram command handlers.

Separated from handlers.py (Controller) to enforce SRP:
- handlers.py: orchestration, API calls, message routing
- handlers_render.py: pure functions for text/UI rendering (testable without mocks)
"""

import re

from services.telegram.headers import SEPARATOR

# ── Constants ──
SKILL_CATEGORIES: dict[str, list[str]] = {
    "🛡️ אבטחה ומודיעין": ["crypto-skill", "firewall-skill", "intel-skill"],
    "📊 נתונים וכלכלה": ["currency-skill", "report-maker", "stocks-skill"],
    "🌐 מדיה ותקשורת": ["news-monitor", "translator-skill", "web-scraper"],
    "🔧 כלים ושירותים": ["file-analyst", "geocode-skill", "weather-skill"],
}

METRIC_HEBREW: dict[str, str] = {
    "cpu": "מעבד",
    "ram": "זיכרון",
    "disk": "דיסק",
    "net": "רשת",
    "proc": "תהליכים",
}


def build_skill_meta(engine) -> dict[str, dict[str, str]]:
    """Build skill metadata dict from loaded skills (DRY — no hard-coding)."""
    from services._skills_engine.parser import extract_commands

    meta: dict[str, dict[str, str]] = {}
    for name, skill in engine._skills.items():
        cmds = extract_commands(skill)[:3]
        meta[name] = {
            "name": f"{skill.emoji} {name.replace('-', ' ').title()}",
            "desc": skill.description or "",
            "examples": ", ".join(cmds) if cmds else "",
        }
    return meta


def _render_category(cat_name: str, present: list[str], skill_meta: dict) -> list[str]:
    """Render a single skill category with tree prefixes."""
    lines = [cat_name]
    for i, skill_name in enumerate(present):
        meta = skill_meta.get(skill_name, {})
        name = meta.get("name", skill_name)
        examples = meta.get("examples", "")
        is_last = i == len(present) - 1
        prefix = "└─" if is_last else "├─"
        cmd_str = f" · {examples}" if examples else ""
        lines.append(f"{prefix} {name}{cmd_str}")
    lines.append("")
    return lines


def _render_uncategorized(engine, uncategorized: list[str]) -> list[str]:
    """Render uncategorized skills with tree prefixes."""
    from services._skills_engine.parser import extract_commands

    lines = ["🔧 כלים נוספים"]
    for i, name in enumerate(uncategorized):
        skill = engine._skills[name]
        cmds = extract_commands(skill)[:3]
        is_last = i == len(uncategorized) - 1
        prefix = "└─" if is_last else "├─"
        cmd_str = " · ".join(cmds) if cmds else ""
        cmd_part = f" · {cmd_str}" if cmd_str else ""
        lines.append(f"{prefix} {skill.emoji} {name}{cmd_part}")
    lines.append("")
    return lines


def render_skill_categories(engine, skill_meta: dict[str, dict[str, str]]) -> list[str]:
    """Render categorized + uncategorized skills as line list."""
    lines: list[str] = [
        "🤖 Claw 🐾 — Skills זמינים",
        "",
        SEPARATOR,
        "📄 שלח קובץ PDF או תמונה — מנותח אוטומטית",
        SEPARATOR,
        "",
    ]

    for cat_name, skill_names in SKILL_CATEGORIES.items():
        present = [n for n in skill_names if n in engine._skills]
        if present:
            lines.extend(_render_category(cat_name, present, skill_meta))

    categorized = {n for names in SKILL_CATEGORIES.values() for n in names}
    uncategorized = [n for n in sorted(engine._skills.keys()) if n not in categorized]
    if uncategorized:
        lines.extend(_render_uncategorized(engine, uncategorized))

    lines.extend(
        [
            "💡 שיחה טבעית — אין צורך בפקודה",
            'פשוט בקש בעברית: "חסום IP הזה", "כמה שווה ביטקוין",',
            '"תרגם לי את הטקסט", "נתח את הקובץ הזה".',
        ]
    )
    return lines


def _render_new_external_ip(report: str) -> list[str]:
    """Render new_external_ip alert lines."""
    ip_match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", report) or re.search(r"[0-9a-fA-F:]{8,}", report)
    ip = ip_match.group(0) if ip_match else "לא ידוע"
    return [
        f"  • כתובת: {ip}",
        "  💡 הסבר: חיבור חדש — נדרר בדיקה (ייתכן עדכון, OneDrive, או תקשורת חשודה)",
    ]


def _render_new_heavy_process(report: str) -> list[str]:
    """Render new_heavy_process alert lines."""
    proc_match = re.search(r"([\w\.-]+)\s*\(PID", report)
    proc = proc_match.group(1) if proc_match else "לא ידוע"
    cpu_match = re.search(r"(\d+\.?\d*)%\s*CPU", report)
    cpu = float(cpu_match.group(1)) if cpu_match else 0
    return [
        f"  • תהליך: {proc}",
        f"  • שימוש CPU: {cpu:.1f}%",
        "  💡 הסבר: תהליך כבד — נדררת בדיקה (ייתכן דפדפן, עדכון, או פעילות חשודה)",
    ]


def _render_process_cpu_spike(report: str, parsed: dict) -> list[str]:
    """Render process_cpu_spike alert lines."""
    proc_match = re.search(r"([\w\.-]+)\s*\(PID", report)
    proc = proc_match.group(1) if proc_match else "לא ידוע"
    lines = [f"  • תהליך: {proc}"]
    if parsed["current"] is not None:
        lines.append(f"  • CPU: {parsed['current']:.1f}%")
    if parsed["z"] is not None:
        lines.append(f"  • z={parsed['z']:.1f}")
    return lines


def _render_structured_metric(metric: str, parsed: dict) -> list[str]:
    """Render CPU/RAM/Disk spike/drop/zscore with structured Sentinel header."""
    lines = [f"  • ערך: {parsed['current']:.1f}%"]
    if parsed["z"] is not None:
        lines.append(f"  • z={parsed['z']:.1f}")
    if parsed["mu"] is not None and parsed["sigma"] is not None:
        lines.append(f"  • בסיס: μ={parsed['mu']:.1f} σ={parsed['sigma']:.1f}")
    if metric.endswith("_drop"):
        lines.append("  💡 הסבר: צניחה מתחת לבסיס — ייתכן פינוי זיכרון/סגירת תהליך")
    else:
        lines.append("  💡 הסבר: מעל הממוצע, אך KoboldCpp טעון — תקין")
    return lines


def _render_threat_detail(metric: str, report: str, parsed: dict) -> list[str]:
    """Route to metric-specific renderer. Returns detail lines (without header)."""
    if metric == "new_external_ip":
        return _render_new_external_ip(report)
    if metric == "new_heavy_process":
        return _render_new_heavy_process(report)
    if metric == "process_cpu_spike":
        return _render_process_cpu_spike(report, parsed)
    if parsed["current"] is not None:
        return _render_structured_metric(metric, parsed)
    # Unknown metric without structured header — clean single-line fallback.
    reason = report.replace("━", "").replace("\n", " ").strip()
    return [f"  • {reason[:100]}"]


def render_threat_row(row) -> list[str]:
    """Format a single threat alert row as compact Hebrew lines.

    Uses _parse_alert_report (shared with the daily report) to extract
    severity, current value, baseline μ/σ, and z-score from the stored
    `report` text — instead of ad-hoc regex per metric. Falls back to
    metric-specific extraction for net/proc alerts that lack the
    structured Sentinel header.
    """
    from services.alert_history_query import _parse_alert_report

    trigger = str(row["trigger"])
    report = str(row["report"])
    ts = str(row["ts"])

    cat = trigger.split(":")[0] if ":" in trigger else trigger
    metric = trigger.split(":")[1] if ":" in trigger else trigger
    cat_hebrew = METRIC_HEBREW.get(cat, cat.upper())

    parsed = _parse_alert_report(report)
    lines = [f"{parsed['sev_icon']} {cat_hebrew} — {ts}"]
    lines.extend(_render_threat_detail(metric, report, parsed))
    lines.append("")
    return lines
