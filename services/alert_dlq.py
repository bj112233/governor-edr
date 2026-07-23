# services/alert_dlq.py
"""Dead-Letter Queue for failed alert dispatches.

When send_alert_event fails (network/rate-limit/Telegram outage), the
alert payload is persisted to alert_dlq in alerts.db. A scheduled sweeper
retries with exponential backoff. After MAX_RETRIES, the row is marked
'dead' (kept for audit, no further retries).

Architecture (recursion-safe):
  - _send_alert_raw(): pure network emit, RAISES on failure.
  - Main flow (_emit_and_persist): calls raw → on exception → enqueue_dlq.
  - Sweeper (sweep_dlq): calls raw → on exception → mark_retried (NO new row).
  This separation prevents the infinite-duplication loop where the main
  flow's except handler re-enqueues a sweeper retry.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any

import aiosqlite

from services.db_pool import DB_DIR, get_pool

logger = logging.getLogger(__name__)

_DB_PATH = str(DB_DIR / "alerts.db")
_pool = get_pool(_DB_PATH, max_connections=2)

_MAX_RETRIES = 8
_BACKOFF_CAP_MIN = 64  # seconds cap = 64 min


async def init_dlq_schema() -> None:
    """Create alert_dlq table if missing. Called at startup."""
    async with _pool.acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_dlq (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_queued     TEXT    NOT NULL,
                payload       TEXT    NOT NULL,
                error_reason  TEXT    NOT NULL,
                retry_count   INTEGER NOT NULL DEFAULT 0,
                next_retry_at TEXT    NOT NULL,
                status        TEXT    NOT NULL DEFAULT 'pending'
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_dlq_retry ON alert_dlq(next_retry_at) WHERE status='pending'")
        await db.commit()


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _compute_next_retry(retry_count: int) -> str:
    """Exponential backoff: 2^count minutes, capped at _BACKOFF_CAP_MIN."""
    minutes = min(2**retry_count, _BACKOFF_CAP_MIN)
    return (datetime.now() + timedelta(minutes=minutes)).strftime("%Y-%m-%d %H:%M:%S")


async def enqueue_dlq(payload: dict[str, Any], error_reason: str) -> int:
    """Persist a failed alert to the DLQ. Returns the row id."""
    ts = _now_iso()
    payload_json = json.dumps(payload, ensure_ascii=False, default=str)
    err = (error_reason or "")[:500]
    async with _pool.acquire() as db:
        cursor = await db.execute(
            "INSERT INTO alert_dlq (ts_queued, payload, error_reason, retry_count, next_retry_at, status) "
            "VALUES (?, ?, ?, 0, ?, 'pending')",
            (ts, payload_json, err, ts),  # next_retry_at = now (due immediately)
        )
        row_id = cursor.lastrowid
        await db.commit()
    logger.warning("[DLQ] Alert enqueued (id=%s): %s", row_id, err[:120])
    return row_id or 0


async def fetch_due_dlq(limit: int = 20) -> list[dict[str, Any]]:
    """Fetch pending DLQ rows whose next_retry_at has passed."""
    now = _now_iso()
    async with _pool.acquire() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT id, payload, retry_count FROM alert_dlq "
            "WHERE status='pending' AND next_retry_at <= ? "
            "ORDER BY next_retry_at ASC LIMIT ?",
            (now, limit),
        )
        rows = await cursor.fetchall()
    return [{"id": r["id"], "payload": r["payload"], "retry_count": r["retry_count"]} for r in rows]


async def mark_retried(row_id: int, retry_count: int, error_reason: str) -> None:
    """Increment retry_count, set next_retry_at, update error. Mark dead if exhausted."""
    new_count = retry_count + 1
    err = (error_reason or "")[:500]
    if new_count >= _MAX_RETRIES:
        async with _pool.acquire() as db:
            await db.execute(
                "UPDATE alert_dlq SET retry_count=?, error_reason=?, status='dead', next_retry_at=? WHERE id=?",
                (new_count, err, _now_iso(), row_id),
            )
            await db.commit()
        logger.error("[DLQ] Row %d marked DEAD after %d retries: %s", row_id, new_count, err[:120])
        return
    async with _pool.acquire() as db:
        await db.execute(
            "UPDATE alert_dlq SET retry_count=?, error_reason=?, next_retry_at=? WHERE id=?",
            (new_count, err, _compute_next_retry(new_count), row_id),
        )
        await db.commit()
    logger.info("[DLQ] Row %d retry %d/%d scheduled: %s", row_id, new_count, _MAX_RETRIES, err[:80])


async def delete_dlq(row_id: int) -> None:
    """Remove a successfully delivered DLQ row."""
    async with _pool.acquire() as db:
        await db.execute("DELETE FROM alert_dlq WHERE id=?", (row_id,))
        await db.commit()


async def sweep_dlq() -> dict[str, int]:
    """Sweeper worker: retry due DLQ rows via _send_alert_raw (NOT _emit_and_persist).

    Returns stats: {retried, delivered, dead, failed}.
    Recursion-safe: failures call mark_retried, NOT enqueue_dlq.
    """
    from services.alert_dispatcher_helpers import _send_alert_raw

    stats = {"retried": 0, "delivered": 0, "dead": 0, "failed": 0}
    due = await fetch_due_dlq()
    if not due:
        return stats

    logger.info("[DLQ] Sweeper: %d due rows", len(due))
    for row in due:
        try:
            payload = json.loads(row["payload"])
            await _send_alert_raw(payload)
            await delete_dlq(row["id"])
            stats["delivered"] += 1
            logger.info("[DLQ] Row %d delivered successfully", row["id"])
        except Exception as exc:
            stats["failed"] += 1
            old_count = row["retry_count"]
            await mark_retried(row["id"], old_count, str(exc))
            if old_count + 1 >= _MAX_RETRIES:
                stats["dead"] += 1
            else:
                stats["retried"] += 1
    return stats


async def get_dlq_stats() -> dict[str, int]:
    """Return DLQ row counts by status (for dashboard/observability)."""
    async with _pool.acquire() as db:
        cursor = await db.execute("SELECT status, COUNT(*) as cnt FROM alert_dlq GROUP BY status", ())
        rows = await cursor.fetchall()
    return {status: cnt for status, cnt in rows} or {"pending": 0, "dead": 0}
