# services/alert_history.py
"""
Level 150: Alert History — SQLite Persistent Storage + Semantic Search
כל התראה אוטונומית נשמרת לדיסק עם embedding לחיפוש סמנטי.
"""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import aiosqlite

from config import EMBEDDING_MODEL, LLM_API_BASE
from services.db_pool import DB_DIR, get_pool
from services.embedding_service import deserialize_vector, serialize_vector
from services.llm_bridge import LLMBridge

_DB_PATH = str(DB_DIR / "alerts.db")
_pool = get_pool(_DB_PATH, max_connections=4)


async def _init_db() -> None:
    """Initialize schema — called once during app startup (NOT at import time)."""
    async with _pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      TEXT    NOT NULL,
                trigger TEXT    NOT NULL,
                report  TEXT    NOT NULL,
                embedding BLOB
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT    NOT NULL,
                tool        TEXT    NOT NULL,
                args        TEXT,
                result      TEXT,
                client_ip   TEXT,
                duration_ms INTEGER
            )
            """
        )
        existing_cols = {row[1] async for row in await db.execute("PRAGMA table_info(alerts)")}
        if "embedding" not in existing_cols:
            await db.execute("ALTER TABLE alerts ADD COLUMN embedding BLOB")
        if "intel" not in existing_cols:
            await db.execute("ALTER TABLE alerts ADD COLUMN intel TEXT")


async def get_latest_system_metrics() -> list[dict]:
    """Fetch latest system_baselines rows + 7d Z-Score stats.

    Sprint 5: system_baselines now lives in metrics.db (isolated pool).
    """
    from services.metrics_db import _ensure_init as _metrics_init
    from services.metrics_db import get_metrics_pool

    await _metrics_init()
    rows: list[dict] = []
    async with get_metrics_pool().acquire() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT b1.metric, b1.value, b1.timestamp
            FROM system_baselines b1
            WHERE b1.id IN (SELECT MAX(id) FROM system_baselines GROUP BY metric)
            ORDER BY b1.metric
            """
        )
        latest_rows = await cursor.fetchall()
        for r in latest_rows:
            cursor2 = await db.execute(
                """
                SELECT value FROM system_baselines
                WHERE metric = ? AND timestamp >= datetime('now', '-7 days')
                """,
                (r["metric"],),
            )
            vals = [row["value"] for row in await cursor2.fetchall()]
            if vals:
                mean = sum(vals) / len(vals)
                var = sum((v - mean) ** 2 for v in vals) / len(vals)
                std = var**0.5
            else:
                mean, std = 0.0, 0.0
            rows.append(
                {
                    "metric": r["metric"],
                    "value": r["value"],
                    "mean": mean,
                    "std": std,
                }
            )
    return rows


async def get_latest_intel_alerts(limit: int = 5) -> list[dict]:
    """Fetch top *limit* alerts from last 24h via connection pool.
    Handles both ISO and legacy "DD/MM HH:MM" timestamps."""
    now = datetime.now()
    cutoff = now - timedelta(hours=24)
    rows: list[dict] = []

    async with _pool.acquire() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT ts, trigger, report
            FROM alerts
            WHERE datetime(ts) IS NULL
               OR datetime(ts) >= datetime('now', '-24 hours')
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit * 4,),
        )
        all_rows = await cursor.fetchall()

    for row in all_rows:
        ts_raw = row["ts"]
        try:
            datetime.strptime(ts_raw, "%Y-%m-%d %H:%M:%S")
            rows.append(
                {
                    "ts": row["ts"],
                    "trigger": row["trigger"],
                    "report": row["report"],
                }
            )
        except ValueError:
            try:
                parsed = datetime.strptime(ts_raw, "%d/%m %H:%M").replace(year=now.year)
                if parsed > now + timedelta(minutes=5):
                    parsed = parsed.replace(year=now.year - 1)
                if parsed >= cutoff:
                    rows.append(
                        {
                            "ts": row["ts"],
                            "trigger": row["trigger"],
                            "report": row["report"],
                        }
                    )
            except ValueError:
                continue
        if len(rows) >= limit:
            break

    return rows


async def save_alert(trigger: str, report: str) -> None:
    """שומר התראה חדשה ל-SQLite עם embedding סמנטי"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        vectors = await LLMBridge.get_instance().embed([report])
        embedding_blob = serialize_vector(vectors[0]) if vectors else None
    except Exception:
        embedding_blob = None

    async with _pool.acquire() as db:
        await db.execute(
            "INSERT INTO alerts (ts, trigger, report, embedding) VALUES (?, ?, ?, ?)",
            (ts, trigger, report, embedding_blob),
        )
        await db.commit()


async def get_recent_alerts(limit: int = 10) -> list:
    """מחזיר את N ההתראות האחרונות"""
    async with _pool.acquire() as db:
        return list(
            await (
                await db.execute(
                    "SELECT ts, trigger, report FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            ).fetchall()
        )


async def async_save_audit_log(
    tool: str,
    args: str,
    result: str,
    client_ip: str = "",
    duration_ms: int = 0,
) -> None:
    """שומר רישום ביקורת (audit log) לכל קריאת כלי MCP."""
    async with _pool.acquire() as db:
        await db.execute(
            "INSERT INTO audit_log (ts, tool, args, result, client_ip, duration_ms) VALUES (?, ?, ?, ?, ?, ?)",
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                tool,
                args,
                result,
                client_ip,
                duration_ms,
            ),
        )
        await db.commit()


# ── Re-exports for backward compatibility ──
from services.alert_history_query import (  # noqa: E402,F401
    _cosine_similarity,
    _embed_texts,
    _embed_texts_sync,
    format_daily_summary,
    get_alerts_last_24h,
    query_alert_history_raw,
    search_alerts_semantic,
)
