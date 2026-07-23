"""Web C2 data access layer — metrics, threats, health."""

import asyncio
import json
import logging
import os
import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import aiosqlite

from services.db_pool import DB_DIR

logger = logging.getLogger(__name__)

_DB_PATH = str(DB_DIR / "alerts.db")

# Category classification
_CONTINUOUS_CATS: frozenset[str] = frozenset({"cpu", "ram", "disk"})
_DISCRETE_CATS: frozenset[str] = frozenset({"net", "proc"})

# Parsing patterns
_CAT_METRIC_RE = re.compile(r"^([a-zA-Z]+):([^\s]+)")
_VAL_RE = re.compile(r"([\d.]+)%")

# Header prefixes to filter
_HEADER_PREFIXES: tuple[str, ...] = (
    "\U0001f7e0",  # 🟠
    "\U0001f534",  # 🔴
    "\U0001f7e1",  # 🟡
    "\u26aa",  # ⚪
    "\U0001f4ca",  # 📊
    "\U0001f4be",  # 💾
    "התראת Sentinel",
    "קטגוריה:",
    "מדד:",
    "זמן:",
    "בסיס:",
    "ערך נוכחי:",
    "סטטוס:",
)


def parse_trigger(trigger: str | None) -> tuple[str | None, float | None]:
    """Extract (category, current_value) from a stored trigger string.

    Real format: "<cat>:<metric>" (e.g. "net:new_external_ip").
    For continuous categories (cpu/ram/disk), a numeric percentage may follow.
    For discrete categories (net/proc), no numeric value is meaningful.
    """
    if not trigger:
        return None, None
    m = _CAT_METRIC_RE.match(trigger.strip())
    if not m:
        return None, None
    cat = m.group(1).lower()
    if cat in _DISCRETE_CATS:
        return cat, None
    if cat in _CONTINUOUS_CATS:
        v = _VAL_RE.search(trigger)
        if v:
            try:
                return cat, float(v.group(1))
            except ValueError:
                return cat, None
        return cat, None
    return cat, None


def extract_reason(report: str | None) -> str:
    """Strip dispatcher header/decoration lines, return the actual payload.

    Dispatcher reports include severity icon, separators, category/metric/time
    headers, and a snapshot footer. The meaningful body sits between them.
    """
    if not report:
        return ""
    text = report.replace("\u2501", "").replace("\u2500", "")
    lines = [ln.strip() for ln in text.split("\n")]
    body = [ln for ln in lines if ln and len(ln) >= 3 and not ln.startswith(_HEADER_PREFIXES)]
    if body:
        return " | ".join(body)
    # Fallback: last meaningful line (skip short placeholder glyphs like ⇳)
    for ln in reversed(lines):
        if len(ln) >= 5:
            return ln
    return ""


async def get_metrics(limit: int = 50) -> list[dict]:
    """Return latest metrics with z-score computed from 7-day baseline.

    Sprint 5: system_baselines now lives in metrics.db.
    """
    from services.metrics_db import _ensure_init as _metrics_init
    from services.metrics_db import get_metrics_pool

    await _metrics_init()
    rows: list[dict] = []
    try:
        async with get_metrics_pool().acquire() as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT metric, value, timestamp,
                       (SELECT AVG(value) FROM system_baselines b2
                        WHERE b2.metric = b1.metric
                          AND timestamp >= datetime('now', '-7 days')) as mean,
                       (SELECT SQRT(AVG(value * value) - AVG(value) * AVG(value))
                        FROM system_baselines b2
                        WHERE b2.metric = b1.metric
                          AND timestamp >= datetime('now', '-7 days')) as std
                FROM system_baselines b1
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                for row in await cursor.fetchall():
                    mean = row["mean"] or 0.0
                    std = row["std"] or 0.0
                    z = 0.0
                    if std and std > 0:
                        z = (row["value"] - mean) / std
                    rows.append(
                        {
                            "metric": row["metric"],
                            "value": round(row["value"], 2),
                            "mean": round(mean, 2),
                            "std": round(std, 2),
                            "z_score": round(z, 2),
                            "timestamp": row["timestamp"],
                        }
                    )
    except Exception as exc:
        logger.warning("[WebC2] metrics query failed: %s", exc)
    return rows


async def get_threats(limit: int = 50, since_ts: float | None = None) -> list[dict]:
    """Return alerts ordered by timestamp DESC.

    Args:
        limit: Max number of alerts to return
        since_ts: If provided, returns alerts whose timestamp > since_ts
    """
    rows: list[dict] = []
    try:
        async with aiosqlite.connect(_DB_PATH) as db:
            await db.execute("PRAGMA busy_timeout=5000")
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT ts, trigger, report
                FROM alerts
                WHERE ts >= datetime('now', '-24 hours')
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                all_rows = await cursor.fetchall()

        now = datetime.now()
        for row in all_rows:
            ts_raw = row["ts"]
            try:
                parsed = datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                try:
                    parsed = datetime.strptime(ts_raw, "%d/%m %H:%M").replace(year=now.year)
                    if parsed > now + timedelta(minutes=5):
                        parsed = parsed.replace(year=now.year - 1)
                except ValueError:
                    continue
            if since_ts is not None:
                if parsed.timestamp() <= since_ts:
                    continue
            cat, cur = parse_trigger(row["trigger"])
            raw_report = row["report"] or ""
            reason = extract_reason(raw_report)
            # Extract PID server-side so the client doesn't need the full report.
            # Truncate report to 200 chars — enough for tooltip, cuts ~36KB payload.
            pid_match = re.search(r"\([^:]+:(\d+)\)|PID:?\s*(\d+)", raw_report, re.IGNORECASE)
            rows.append(
                {
                    "time": ts_raw,
                    "trigger": row["trigger"],
                    "report": raw_report[:200],
                    "reason": reason[:200],
                    "category": cat,
                    "current": cur,
                    "pid": pid_match.group(1) or pid_match.group(2) if pid_match else None,
                }
            )
            if len(rows) >= limit:
                break
    except Exception as exc:
        logger.warning("[WebC2] threats query failed: %s", exc)
    return rows


async def get_gpu_vram_stats() -> dict[str, Any]:
    """Fetch GPU VRAM stats via Windows Performance Counters (GPU Adapter Memory).

    Uses PowerShell Get-Counter to read:
      - Dedicated Usage = VRAM in use (dedicated video memory)
      - Total Committed = total VRAM budget (dedicated + shared commitment)

    On non-Windows or no GPU: returns vram_status="no_gpu".
    Never raises — VRAM is telemetry, not critical path.

    Note: key is `vram_status` (not `status`) to avoid clobbering the main
    health status from psutil when merged via dict.update().
    """
    if os.name != "nt":
        return {"used_gb": 0.0, "total_gb": 0.0, "percent": 0.0, "vram_status": "no_gpu"}

    try:
        return await asyncio.wait_for(asyncio.to_thread(_read_gpu_counters_sync), timeout=5.0)
    except (TimeoutError, OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        logger.debug("[WebC2] VRAM counter read failed: %s", exc)
        return {"used_gb": 0.0, "total_gb": 0.0, "percent": 0.0, "vram_status": "offline"}


def _read_gpu_counters_sync() -> dict[str, Any]:
    """Read GPU Adapter Memory performance counters via PowerShell.

    Synchronous — called via asyncio.to_thread. Parses the primary GPU
    (first non-zero instance) for Dedicated Usage and Total Committed.

    Uses -EncodedCommand (base64 UTF-16LE) to avoid $-escaping issues
    when passing PowerShell scripts through subprocess on Windows.
    """
    import base64

    ps_script = (
        "(Get-Counter -Counter "
        r"'\GPU Adapter Memory(*)\Dedicated Usage',"
        r"'\GPU Adapter Memory(*)\Total Committed' "
        "-ErrorAction Stop).CounterSamples | "
        "ForEach-Object { $_.InstanceName + '|' + $_.CookedValue }"
    )
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    cmd = ["powershell", "-NoProfile", "-EncodedCommand", encoded]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
    if result.returncode != 0:
        raise RuntimeError(f"PowerShell exit {result.returncode}: {result.stderr[:200]}")

    # Parse lines: "instance_name|cooked_value"
    instances: dict[str, dict[str, float]] = {}
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if "|" not in line:
            continue
        inst, val_str = line.rsplit("|", 1)
        try:
            val = float(val_str)
        except ValueError:
            continue
        if inst not in instances:
            instances[inst] = {}
        # First counter in the query is Dedicated, second is Total Committed
        if "dedicated" not in instances[inst]:
            instances[inst]["dedicated"] = val
        else:
            instances[inst]["committed"] = val

    # Pick the primary GPU: highest Total Committed value
    best_inst = None
    best_committed = 0.0
    for inst, vals in instances.items():
        committed = vals.get("committed", 0.0)
        if committed > best_committed:
            best_committed = committed
            best_inst = inst

    if not best_inst or best_committed <= 0:
        return {"used_gb": 0.0, "total_gb": 0.0, "percent": 0.0, "vram_status": "no_gpu"}

    vals = instances[best_inst]
    used_bytes = vals.get("dedicated", 0.0)
    total_bytes = vals.get("committed", 0.0)

    if total_bytes <= 0:
        return {"used_gb": 0.0, "total_gb": 0.0, "percent": 0.0, "vram_status": "no_gpu"}

    used_gb = round(used_bytes / (1024**3), 2)
    total_gb = round(total_bytes / (1024**3), 2)
    percent = round((used_bytes / total_bytes) * 100, 1)
    return {"used_gb": used_gb, "total_gb": total_gb, "percent": percent, "vram_status": "ok"}


async def get_health() -> dict[str, Any]:
    """Return current system health (CPU, RAM, Disk, VRAM)."""
    data: dict[str, Any] = {}
    try:
        import psutil

        data["cpu"] = await asyncio.to_thread(psutil.cpu_percent, interval=0.1)
        ram = await asyncio.to_thread(psutil.virtual_memory)
        data["ram_percent"] = ram.percent
        data["ram_used_gb"] = round((ram.total - ram.available) / (1024**3), 1)
        data["ram_total_gb"] = round(ram.total / (1024**3), 1)
        disk = await asyncio.to_thread(psutil.disk_usage, "C:\\" if os.name == "nt" else "/")
        data["disk_percent"] = disk.percent
        data["disk_free_gb"] = round(disk.free / (1024**3), 1)
        data["status"] = "ok"
    except Exception as exc:
        logger.warning("[WebC2] health query failed: %s", exc)
        data["status"] = "error"
        data["error"] = str(exc)
    # VRAM — non-blocking, never degrades health status if unavailable
    data.update(await get_gpu_vram_stats())
    # Inference engine telemetry — real RSS / TPOT / context saturation.
    # Lazy import avoids circular coupling; snapshot() is in-memory (no disk I/O)
    # but sync, so offload to thread like the psutil calls above.
    try:
        from services.telemetry import get_telemetry

        snap = await asyncio.to_thread(get_telemetry().snapshot)
        data["process_rss_mb"] = snap["proc"]["rss_mb"]
        data["tpot_tps"] = snap["llm"]["tpot_tps"]
        data["ctx_sat_pct"] = snap["llm"]["ctx_sat_pct"]
    except Exception as exc:
        logger.debug("[WebC2] telemetry snapshot failed: %s", exc)
    return data


__all__ = [
    "parse_trigger",
    "extract_reason",
    "get_metrics",
    "get_threats",
    "get_health",
    "get_gpu_vram_stats",
]
