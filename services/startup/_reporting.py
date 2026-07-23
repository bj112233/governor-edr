"""Daily report builder + digest emitter. Leaf module."""

import logging

from config import DAILY_REPORT_INCLUDE_TOP_PROCS, DAILY_REPORT_MAX_ALERTS, LLM_TIMEOUT
from services.alert_history import format_daily_summary, get_alerts_last_24h
from services.alert_history_query import _label_for, _parse_alert_report
from services.monitor_engine import get_system_snapshot
from services.sentinel_events import send_daily_digest_event

logger = logging.getLogger(__name__)


async def generate_security_sitrep(alerts: list, sys_status: str) -> str:
    """LLM-generated security SITREP — executive summary of 24h alerts.

    Feeds parsed alert fields (severity, metric, value, z, baseline, time)
    to the LLM and asks for a concise Hebrew intelligence summary:
    trends, anomalies, severity breakdown, recommendations.

    Returns empty string on failure (caller skips silently).
    """
    if not alerts:
        return ""

    # Build compact alert digest for the LLM (not the full report text).
    block_lines = []
    for ts, trigger, report in alerts:
        p = _parse_alert_report(report)
        label = _label_for(trigger, p)
        parts = [f"[{ts}] {label}"]
        if p["sev"]:
            parts.append(f"sev={p['sev']}")
        if p["current"] is not None:
            parts.append(f"val={p['current']:.1f}%")
        if p["z"] is not None:
            parts.append(f"z={p['z']:.1f}")
        if p["mu"] is not None and p["sigma"] is not None:
            parts.append(f"μ={p['mu']:.1f} σ={p['sigma']:.1f}")
        block_lines.append(" | ".join(parts))
    block = f"System: {sys_status}\nAlerts ({len(alerts)}):\n" + "\n".join(block_lines)
    if len(block) > 12000:
        block = block[:12000] + "\n...[truncated]"

    instructions = (
        "אתה אנליסט אבטחת מידע בכיר. סכם את התראות האבטחה מה-24 שעות "
        "האחרונות לדו\u05f4ח מצב (SITREP) בעברית.\n"
        "הדגש: מגמות חומרה, חריגות משמעותיות (z-score גבוה), "
        "פילוח לפי סוג מדד, והמלצות פעולה.\n"
        "אל תמציא מידע שלא מופיע בנתונים. "
        "השתמש בשפה עניינית ותמציתית. "
        "חובה: פורמט Markdown חוקי, ללא הקדמות. מקסימום 15 שורות."
    )
    try:
        from services.llm_bridge import LLMBridge

        bridge = LLMBridge.get_instance()
        sitrep = await bridge.complete(
            system_prompt=instructions,
            user_input=block,
            temperature=0.2,
            max_tokens=1024,
            timeout=float(LLM_TIMEOUT * 2),
        )
        return (sitrep or "").strip()
    except Exception as exc:
        logger.warning("[DailyDigest] Security SITREP generation failed: %s", exc)
        return ""


async def build_daily_report() -> str:
    """Build structured daily report with SITREP, system status, processes and alerts."""
    snapshot = await get_system_snapshot()

    # First Principles: Defensive dict access to prevent KeyError crashes
    disk_alerts = snapshot.get("disk_alerts", [])
    disk_str = ", ".join(disk_alerts) if disk_alerts else "OK"
    cpu = snapshot.get("cpu", 0)
    mem = snapshot.get("mem", 0)

    sys_status = f"• CPU: {cpu}% | RAM: {mem}% | Disk: {disk_str}"

    procs_section = ""
    if DAILY_REPORT_INCLUDE_TOP_PROCS:
        top_procs = snapshot.get("top_procs", [])[:5]
        procs_lines = []
        for p in top_procs:
            pid = p.get("pid", "?")
            name = p.get("name", "unknown")
            proc_cpu = p.get("cpu_percent", 0)
            procs_lines.append(f"• {name} (PID {pid}) - {proc_cpu}%")
        procs_section = "\n".join(procs_lines) if procs_lines else "אין תהליכים משמעותיים"

    alerts = await get_alerts_last_24h()
    alerts_section = format_daily_summary(alerts, max_alerts=DAILY_REPORT_MAX_ALERTS)

    from services.reports.env import get_report_env
    from services.time_format import format_report_date

    hunt_line = await _get_hunt_summary_line()
    sitrep = await generate_security_sitrep(alerts, sys_status)

    report = (
        get_report_env()
        .get_template("daily.j2")
        .render(
            emoji="📅",
            title=f"דוח אבטחה יומי [{format_report_date()}]",
            sys_status=sys_status,
            include_procs=DAILY_REPORT_INCLUDE_TOP_PROCS,
            procs_section=procs_section,
            hunt_line=hunt_line,
            sitrep=sitrep,
            alerts_section=alerts_section,
        )
    )
    return report


async def _get_hunt_summary_line() -> str:
    """One-line OSINT hunt summary for the daily report.

    Returns a focused single line: count + avg score + top topic.
    Empty string if no hunts in 24h.
    """
    try:
        from services.memory_db import get_hunts_last_24h

        hunts = await get_hunts_last_24h()
        if not hunts:
            return ""
        count = len(hunts)
        avg_score = sum(h["threat_score"] for h in hunts) / count
        dispatched = sum(1 for h in hunts if h["dispatched"])
        # Top hunt = highest score
        top = max(hunts, key=lambda h: h["threat_score"])
        top_summary = (top["summary"] or "").replace("\n", " ").strip()[:80]
        return f"• {count} הנטים | דירוג ממוצע: {avg_score:.1f} | שוגרו: {dispatched} | עליון: {top_summary}"
    except Exception as exc:
        logger.debug("[DailyDigest] Hunt summary failed: %s", exc)
        return ""


async def _send_sitrep_document(report: str) -> None:
    """Save SITREP .md file and send as Telegram document (mirrors CTI/News)."""
    from pathlib import Path

    from services.time_format import format_report_date

    try:
        out_dir = Path("downloads/reports")
        out_dir.mkdir(parents=True, exist_ok=True)
        filepath = out_dir / f"security_sitrep_{format_report_date()}.md"
        filepath.write_text(report, encoding="utf-8")
        logger.info("[DailyDigest] SITREP saved -> %s", filepath)

        from services.interfaces import get_message_gateway

        channel = get_message_gateway()
        bot = getattr(channel, "bot", None) if channel else None
        if bot:
            from config import TELEGRAM_CHAT_ID

            chat_id = str(TELEGRAM_CHAT_ID) if TELEGRAM_CHAT_ID else ""
            if chat_id:
                from aiogram.types import FSInputFile

                await bot.send_document(
                    chat_id=chat_id,
                    document=FSInputFile(str(filepath)),
                    caption="📅 דו\u05f4ח אבטחה יומי (SITREP)",
                )
                logger.info("[DailyDigest] SITREP document sent to Telegram.")
            else:
                logger.warning("[DailyDigest] TELEGRAM_CHAT_ID not set — document not sent.")
        else:
            logger.warning("[DailyDigest] Telegram channel unavailable — document not sent.")
    except Exception as exc:
        logger.warning("[DailyDigest] SITREP document delivery failed: %s", exc)


async def send_daily_digest() -> None:
    """APScheduler hook: build and emit daily digest to event bus + send SITREP document."""
    try:
        logger.info("[DailyDigest] Generating Security Digest...")
        structured_report = await build_daily_report()
        await send_daily_digest_event(structured_report, "AI analysis")
        logger.info("[DailyDigest] Emitted to event bus.")
        await _send_sitrep_document(structured_report)
    except Exception as e:
        logger.error("[DailyDigest] Error: %s", e, exc_info=True)
