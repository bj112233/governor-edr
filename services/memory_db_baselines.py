"""System baseline metrics — time-series storage for anomaly detection.

Extracted from memory_db.py (SRP). Stores per-hour metric snapshots in
``system_baselines`` table for fast AVG()/STDDEV() baseline queries.

Sprint 5: Moved to metrics.db (isolated from alert_history.db) to eliminate
write lock contention with user-facing queries.
"""

import logging
from datetime import datetime
from typing import Optional

from services.metrics_db import _ensure_init as _metrics_ensure_init
from services.metrics_db import get_metrics_pool

logger = logging.getLogger(__name__)


async def store_baseline_metrics(metrics: dict[str, float]) -> None:
    """Persist a snapshot of metric values for baseline computation.

    Args:
        metrics: Mapping of metric name (e.g. 'cpu', 'ram') to value.
    """
    await _metrics_ensure_init()
    hour = datetime.now().hour
    rows = [(k, v, hour) for k, v in metrics.items()]
    try:
        async with get_metrics_pool().acquire() as db:
            await db.executemany(
                "INSERT INTO system_baselines (metric, value, hour) VALUES (?, ?, ?)",
                rows,
            )
            await db.commit()
        logger.debug("[MemoryDB] stored %d baseline metrics", len(rows))
    except Exception as exc:
        logger.warning("[MemoryDB] store_baseline_metrics failed: %s", exc)


async def get_baseline_stats(metric: str, window_days: int = 7) -> tuple[float | None, float | None]:
    """Return (mean, stddev) for a metric over the last N days, grouped by hour.

    Uses SQLite AVG() and a custom population STDDEV (sqrt(avg(x^2) - avg(x)^2))
    since aiosqlite does not expose the native stddev extension.

    Returns (None, None) if no data exists.
    """
    await _metrics_ensure_init()
    hour = datetime.now().hour
    try:
        async with get_metrics_pool().acquire() as db:
            cursor = await db.execute(
                """
                SELECT
                    AVG(value) AS mean,
                    SQRT(AVG(value * value) - AVG(value) * AVG(value)) AS std
                FROM system_baselines
                WHERE metric = ?
                  AND hour = ?
                  AND timestamp >= datetime('now', ? || ' days')
                """,
                (metric, hour, f"-{window_days}"),
            )
            row = await cursor.fetchone()
            if row and row[0] is not None:
                mean, std = row
                if std is not None and std < 0:
                    std = 0.0
                return (mean, std)
    except Exception as exc:
        logger.warning("[MemoryDB] get_baseline_stats failed: %s", exc)
    return (None, None)


async def get_baseline_raw_values(metric: str, window_days: int = 7) -> list[float]:
    """Fetch raw values for ``metric`` (outlier-robust bootstrap).

    Returns an empty list if no rows exist. Caller must use Median + MAD
    (not AVG / STDDEV) to avoid poisoning by anomalous historical samples.
    """
    await _metrics_ensure_init()
    hour = datetime.now().hour
    values: list[float] = []
    try:
        async with get_metrics_pool().acquire() as db:
            cursor = await db.execute(
                """
                SELECT value
                FROM system_baselines
                WHERE metric = ?
                  AND hour = ?
                  AND timestamp >= datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                LIMIT 1000
                """,
                (metric, hour, f"-{window_days}"),
            )
            async for row in cursor:
                if row[0] is not None:
                    values.append(float(row[0]))
    except Exception as exc:
        logger.warning("[MemoryDB] get_baseline_raw_values failed: %s", exc)
    return values


async def cleanup_old_baselines(days: int = 30) -> int:
    """Purge baseline rows older than ``days`` days. Returns deleted count."""
    await _metrics_ensure_init()
    async with get_metrics_pool().acquire() as db:
        cur = await db.execute(
            "DELETE FROM system_baselines WHERE timestamp < datetime('now', ?)",
            (f"-{days} days",),
        )
        await db.commit()
        return cur.rowcount
