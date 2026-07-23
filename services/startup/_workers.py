"""Core workers — monitor producer + LLM analysis consumer + rule-based fallback."""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

from config import (
    CPU_THRESHOLD,
    LLM_TIMEOUT,
    MONITOR_AI_ENABLED,
    MONITOR_INTERVAL,
    RAM_THRESHOLD,
    SNAPSHOT_TO_THREAD_TIMEOUT,
)
from services.agent import analyze_data
from services.alert_history import save_alert
from services.monitor_engine import get_system_snapshot
from services.net_baseline import record_net_baselines
from services.net_parser import parse_ip_port
from services.sentinel_events import put_alert_snapshot, send_alert_event
from services.startup._monitor_ai import _get_alert_dispatcher, _get_monitor_analyzer
from services.startup._net_baseline import _collect_net_baseline_rows
from services.thinking_parser import strip_thinking_content

logger = logging.getLogger(__name__)

_DEFAULT_SOC_PROMPT = (
    "CRITICAL OUTPUT RULE: You are the analytical engine, NOT the presentation layer. "
    "Output ONLY the raw analytical insight (1-2 sentences explaining what the threat is). "
    "DO NOT include headers, emojis, timestamps, dividers (--- or ===), "
    "or repeat system metrics like CPU/RAM. "
    "Return ONLY a 1-2 sentence summary in Hebrew. "
    "Format: [Severity] - [Category] - [Description]. "
    "Be extremely concise. No bullet points, no headers. "
    "Max 2 lines total."
)

_SOC_PROMPT_PATH = os.getenv(
    "SOC_PROMPT_PATH",
    str((Path(__file__).parent.parent.parent / "config" / "soc_prompt.txt").absolute()),
)


def _load_soc_prompt() -> str:
    """Load SOC analyst prompt from external file. Falls back to embedded default."""
    try:
        path = Path(_SOC_PROMPT_PATH)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    except Exception as exc:
        logger.warning("[Workers] Failed to load SOC prompt from %s: %s", _SOC_PROMPT_PATH, exc)
    return _DEFAULT_SOC_PROMPT


async def _collect_net_baseline(bg_tasks: set[asyncio.Task]) -> None:
    """Collect network baseline rows and record them fire-and-forget."""
    try:
        _baseline_rows = await asyncio.wait_for(
            asyncio.to_thread(_collect_net_baseline_rows),
            timeout=SNAPSHOT_TO_THREAD_TIMEOUT,
        )
        if _baseline_rows:
            task = asyncio.create_task(
                record_net_baselines(_baseline_rows),
                name="record_net_baselines",
            )
            bg_tasks.add(task)
            task.add_done_callback(bg_tasks.discard)
    except Exception as exc:
        logger.warning("[Monitor] Baseline collection failed: %s", exc)


async def _run_ai_analysis(snapshot: dict[str, Any]) -> None:
    """Run AI monitor analysis + dispatch on a snapshot."""
    analyzer = _get_monitor_analyzer()
    if analyzer is None:
        if snapshot.get("alert_needed", False):
            logger.warning("🚨 Anomaly Detected! Enqueueing for LLM analysis...")
            await put_alert_snapshot(snapshot)
        return

    anomalies, threats = await analyzer.analyze(snapshot)
    if not anomalies and not threats:
        logger.info(
            "🟢 Nominal - CPU: %.1f%% | RAM: %.1f%% | Disk: %s",
            snapshot.get("cpu", 0),
            snapshot.get("mem", 0),
            "OK" if not snapshot.get("disk_alerts") else "ALERT",
        )
        return

    for ev in anomalies:
        logger.warning(
            "🚨 [%s] %s | %s",
            ev.severity.upper(),
            ev.category,
            ev.reason,
        )
    dispatcher = _get_alert_dispatcher()
    if dispatcher is not None:
        dispatch_result = await dispatcher.dispatch(anomalies, threats=threats, snapshot=snapshot)
        logger.info(
            "[MonitorAI] Dispatch: sent=%d, suppressed=%d",
            dispatch_result.sent,
            dispatch_result.suppressed_cooldown
            + dispatch_result.suppressed_rate_limit
            + dispatch_result.suppressed_severity,
        )
    if any(ev.severity == "critical" for ev in anomalies):
        snapshot["anomalies"] = anomalies
        await put_alert_snapshot(snapshot)


async def _run_monitor_cycle(bg_tasks: set[asyncio.Task]) -> None:
    """Execute one monitor cycle: snapshot → baseline → analysis → sleep."""
    logger.debug("💓 monitor heartbeat")
    snapshot = await get_system_snapshot()
    await _collect_net_baseline(bg_tasks)

    if MONITOR_AI_ENABLED:
        await _run_ai_analysis(snapshot)
    else:
        # Legacy mode: simple threshold
        if snapshot.get("alert_needed", False):
            logger.warning("🚨 Anomaly Detected! Enqueueing for LLM analysis...")
            await put_alert_snapshot(snapshot)
        else:
            logger.info(
                "🟢 Nominal - CPU: %.1f%% | RAM: %.1f%% | Disk: OK",
                snapshot.get("cpu", 0),
                snapshot.get("mem", 0),
            )

    await asyncio.sleep(MONITOR_INTERVAL)


async def monitor_loop(alert_queue: asyncio.Queue[dict[str, Any]], bg_tasks: set[asyncio.Task]) -> None:
    """Autonomous monitor loop — Producer: snapshots → alert_queue."""
    logger.info("🚀 Sentinel Autonomous Core Online (Producer mode)")
    while True:
        try:
            await _run_monitor_cycle(bg_tasks)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Critical Loop Error: %s", e, exc_info=True)
            logger.error("Monitor cooldown for 10 minutes after error.")
            await asyncio.sleep(600)


def _compute_severity(cpu: int, ram: int, disk_alerts: list, susp_net: list) -> str:
    """Severity bucket from raw resource metrics + alert counts."""
    if cpu > 90 or ram > 95:
        return "🔴 קריטית"
    if cpu > 85 or ram > 90 or len(disk_alerts) > 0:
        return "🟠 גבוהה"
    if cpu > 70 or ram > 80 or len(susp_net) > 5:
        return "🟡 בינונית"
    return "🟢 נמוכה"


_STANDARD_PORTS = {80, 443, 8080, 8443}


def _analyze_suspicious_net(susp_net: list) -> str:
    """Categorize suspicious connections: non-standard ports vs plain external."""
    non_standard_ports = 0
    for conn in susp_net:
        ip_part = conn.split(" ")[0] if " " in conn else conn
        ip, port = parse_ip_port(ip_part)
        if ip is not None and port is not None and port not in _STANDARD_PORTS:
            non_standard_ports += 1
    if non_standard_ports > 0:
        return f"רשת חשודה ({non_standard_ports} פורטים לא סטנדרטיים)"
    return f"חיבורים חיצוניים ({len(susp_net)})"


def _compute_categories(cpu: int, ram: int, disk_alerts: list, susp_net: list) -> list:
    """Build the category list from resource + network signals."""
    cats = []
    if cpu > CPU_THRESHOLD:
        cats.append("עומס CPU")
    if ram > RAM_THRESHOLD:
        cats.append("עומס זיכרון")
    if disk_alerts:
        cats.append("אחסון")
    if susp_net:
        cats.append(_analyze_suspicious_net(susp_net))
    return cats


def _rule_based_analysis(snapshot: dict) -> str:
    """Rule-based fallback analysis when LLM is unavailable."""
    cpu, ram = snapshot.get("cpu", 0), snapshot.get("mem", 0)
    disk_alerts = snapshot.get("disk_alerts", [])
    susp_net = snapshot.get("suspicious_net", [])

    severity = _compute_severity(cpu, ram, disk_alerts, susp_net)
    cats = _compute_categories(cpu, ram, disk_alerts, susp_net)
    category = " + ".join(cats) if cats else "כללית"

    return f"{severity} - {category} - ניתוח heuristic (LLM unavailable)"


async def llm_analysis_worker(alert_queue: asyncio.Queue[dict[str, Any]]) -> None:
    """Consumer: pulls snapshots from queue, runs LLM analysis, emits alerts."""
    logger.info("🧠 LLM Analysis Worker Online")
    while True:
        snapshot = await alert_queue.get()
        try:
            logger.info("🔍 Processing queued alert snapshot...")
            disk_str = ", ".join(snapshot.get("disk_alerts", [])) or "OK"

            # Defensive process collection
            top_procs_list = snapshot.get("top_procs", [])
            procs_str = ", ".join(p.get("name", "unknown") for p in top_procs_list if isinstance(p, dict)) or "None"

            sys_data = f"CPU: {snapshot.get('cpu', 0)}%, RAM: {snapshot.get('mem', 0)}%, Disk: {disk_str}, Heavy Procs: {procs_str}"

            susp_net = snapshot.get("suspicious_net", [])
            if susp_net:
                # Send FULL enriched connections to LLM (not summarized)
                # Each line: IP:port (Org / ASN) (process:pid)
                net_data = "\n".join(f"- {conn}" for conn in susp_net)
            else:
                net_data = "No suspicious connections"

            _soc_prompt = _load_soc_prompt()
            report: str | None = None
            from services.llm_bridge import is_llm_ready

            if not is_llm_ready():
                logger.info("[LLM Worker] LLM not ready — skipping LLM call, using rule-based fallback")
            else:
                try:
                    report = await asyncio.wait_for(
                        analyze_data(
                            _soc_prompt,
                            f"=== SYSTEM ===\n{sys_data}\n\n=== NETWORK ===\n{net_data}",
                            max_tokens=800,
                        ),
                        timeout=LLM_TIMEOUT,
                    )
                except TimeoutError:
                    logger.warning("[LLM Worker] Analysis timeout — using rule-based fallback")
                    report = None

            if not report or report.startswith("⚠️") or "ניתוח חלק" in report:
                logger.info("[LLM Worker] Using rule-based fallback analysis")
                report = _rule_based_analysis(snapshot)

            report = strip_thinking_content(report or "")
            await send_alert_event(snapshot, report)

            await save_alert("system_monitor", report)
            logger.info("✅ Alert processed and emitted to event bus.")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("[LLM Worker] Error processing alert: %s", e, exc_info=True)
        finally:
            alert_queue.task_done()
