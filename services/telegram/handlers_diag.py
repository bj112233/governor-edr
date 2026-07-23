"""Telegram diagnostic command handlers — /status, /stats, /intel.

Extracted from handlers.py (SRP). These commands query system metrics,
telemetry, and threat intel for display.
"""

import logging
from typing import Any

from aiogram.types import Message
from aiogram.utils.formatting import Bold, Text

from services.alert_history import (
    get_latest_intel_alerts,
    get_latest_system_metrics,
)
from services.telegram.formatting import chunk_text
from services.telegram.handlers_render import render_threat_row
from services.telegram.headers import safe_answer

logger = logging.getLogger(__name__)


async def cmd_status(message: Message) -> None:
    """Handle /status — latest system metrics with Z-Scores."""
    try:
        rows = await get_latest_system_metrics()
    except Exception as exc:
        logger.warning("[Telegram/status] DB query failed: %s", exc)
        await message.answer("❌ שגיאה בקריאת נתוני מערכת.")
        return

    parts: list[Any] = ["🟢 ", Bold("SYSTEM STATUS"), "\n"]
    for row in rows:
        mean = row["mean"] or 0.0
        std = row["std"] or 0.0
        z = 0.0
        if std and std > 0:
            z = (row["value"] - mean) / std

        metric = str(row["metric"]).upper()
        val_str = str(round(row["value"], 1))
        z_str = str(round(z, 2))

        parts.append(f"{metric}: {val_str}% (Z: {z_str})\n")

    content = Text(*parts)
    await message.answer(**content.as_kwargs())


async def cmd_stats(message: Message) -> None:
    """Handle /stats — bot self-telemetry snapshot (single-user)."""
    from services.telemetry import get_telemetry

    try:
        snap = get_telemetry().snapshot()
    except Exception as exc:
        logger.warning("[Telegram/stats] snapshot failed: %s", exc)
        await message.answer("❌ שגיאה בקריאת טלמטריה.")
        return

    proc = snap["proc"]
    llm = snap["llm"]
    tools = snap["tools"]

    up_h, rem = divmod(proc["uptime_s"], 3600)
    up_m, _ = divmod(rem, 60)

    parts: list[Any] = [
        "📊 ",
        Bold("Bot Telemetry"),
        "\n\n",
        Bold("💾 Process"),
        "\n",
        f"• RSS: {proc['rss_mb']} MB\n",
        f"• CPU: {proc['cpu_pct']}%\n",
        f"• Uptime: {up_h}h {up_m}m\n\n",
        Bold("🧠 LLM"),
        f" (window n={llm['window_n']})\n",
        f"• calls: {llm['calls']}  errors: {llm['errors']}\n",
        f"• p50: {llm['p50_ms']}ms | p95: {llm['p95_ms']}ms | avg: {llm['avg_ms']}ms\n",
        f"• TPOT: {llm['tpot_tps']} tok/s (p50: {llm['tpot_p50_ms']}ms/tok)\n",
        f"• Context: {llm['ctx_avg']}/{llm['ctx_max']} tok ({llm['ctx_sat_pct']}% saturation)\n\n",
        Bold("⚡ Event Loop"),
        f"\n• lag p50: {snap['loop_lag_ms']}ms | p95: {snap['loop_lag_p95_ms']}ms\n\n",
        Bold("🔧 Tools"),
        "\n",
        f"• calls: {tools['calls']}  errors: {tools['errors']}\n",
    ]

    top = sorted(
        tools["per_tool"].items(),
        key=lambda kv: kv[1]["p95_ms"],
        reverse=True,
    )[:5]
    if top:
        parts.append(Bold("  Top 5 (by p95):"))
        parts.append("\n")
        for name, st in top:
            parts.append(f"  └─ {name}: p95={st['p95_ms']}ms (n={st['n']})\n")
    else:
        parts.append("  (אין מדידות עדיין)\n")

    content = Text(*parts)
    await message.answer(**content.as_kwargs())


async def cmd_intel(message: Message) -> None:
    """Handle /intel — top 5 recent threats, human-readable format."""
    try:
        rows = await get_latest_intel_alerts(limit=5)
    except Exception as exc:
        logger.warning("[Telegram/intel] DB query failed: %s", exc)
        await message.answer("❌ שגיאה בקריאת התראות.")
        return

    if not rows:
        await message.answer("✅ Sector Clear — אין התראות ב-24 שעות האחרונות.")
        return

    lines: list[str] = ["🔴 THREAT INTEL", ""]
    for row in rows:
        lines.extend(render_threat_row(row))

    text = "\n".join(lines)
    await safe_answer(message, text)


async def cmd_threatscan(message: Message) -> None:
    """Handle /threatscan — force-trigger threat_hunt_job in the daemon.

    Runs threat_hunt_job() with _FORCE_HUNT=True (bypasses cooldown/dedup).
    The hunt uses the live system snapshot — suspicious_procs, network IOCs,
    and the TTP Override gate. Result is sent back to Telegram.
    """
    import asyncio
    import time

    import services.threat_hunter as th

    await message.answer("🛡️ **Threat Scan** — מפעיל ציד איומים מערכתי (force=True)…")
    logger.info("[Telegram/threatscan] Forced hunt triggered by operator.")

    th._FORCE_HUNT = True
    t0 = time.monotonic()
    try:
        await asyncio.wait_for(th.threat_hunt_job(), timeout=420.0)
    except TimeoutError:
        await message.answer("⏱️ ציד האיומים נמשך מעל 7 דקות — הופסק. בדוק לוגים.")
        return
    except Exception as exc:
        logger.error("[Telegram/threatscan] Hunt failed: %s", exc)
        await message.answer(f"❌ שגיאה בציד: {exc}")
        return

    elapsed = time.monotonic() - t0
    status = th.get_hunt_status()
    score = status.get("last_score", 0.0) if isinstance(status, dict) else 0.0
    dispatched = status.get("last_dispatched", False) if isinstance(status, dict) else False
    skip = status.get("last_skip_reason", "") if isinstance(status, dict) else ""

    if score >= 1.0:
        emoji = "🔴"
    elif score >= 0.6:
        emoji = "🟠"
    elif score > 0.0:
        emoji = "🟡"
    else:
        emoji = "🟢"

    lines = [
        f"{emoji} **Threat Scan הושלם** ({elapsed:.1f}s)",
        f"Score: **{score:.2f}**",
        f"Dispatched: {'כן' if dispatched else 'לא'}",
    ]
    if skip:
        lines.append(f"Skip: {skip}")
    await safe_answer(message, "\n".join(lines))
