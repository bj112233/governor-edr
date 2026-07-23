# services/pending_actions.py
"""
SQLite-backed pending-action queue for HITL approval pipeline.

Replaces the in-memory singleton with a persistent queue that survives restarts.
Each action has a correlation_id linking it to the threat event that triggered it.

Schema:
  pending_actions(
    id INTEGER PRIMARY KEY,
    correlation_id TEXT,        -- links to alert/threat event
    action_type TEXT,            -- "block_ip", "kill_process", etc.
    target TEXT,                 -- IP/PID/domain being acted on
    threat_context TEXT,         -- JSON: score, reason, indicators
    status TEXT DEFAULT 'PENDING_APPROVAL',
    created_at TEXT,
    resolved_at TEXT
  )

Backward compat: set_pending/get_pending/clear_pending still work,
now backed by SQLite instead of in-memory singleton.
"""

import asyncio
import json
import logging
import time
from typing import Any

import aiosqlite

from services.db_pool import get_db_path

logger = logging.getLogger(__name__)

_DB_PATH = get_db_path("pending_actions")
_lock = asyncio.Lock()
_initialized = False


async def _ensure_schema() -> None:
    """Create table if not exists. Idempotent."""
    global _initialized
    if _initialized:
        return
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT,
                action_type TEXT NOT NULL,
                target TEXT,
                threat_context TEXT,
                status TEXT DEFAULT 'PENDING_APPROVAL',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_pa_status ON pending_actions(status)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_pa_corr ON pending_actions(correlation_id)")
        await db.commit()
    _initialized = True


# ── New API: structured queue ────────────────────────────────────


async def queue_action(
    action_type: str,
    target: str,
    correlation_id: str = "",
    threat_context: dict[str, Any] | None = None,
) -> int:
    """Queue a new pending action. Returns the row ID.

    Args:
        action_type: "block_ip", "kill_process", etc.
        target: IP address, PID, or domain
        correlation_id: links to alert/threat event (for audit trail)
        threat_context: {"score": 85, "reason": "...", "indicators": [...]}
    """
    await _ensure_schema()
    ctx_json = json.dumps(threat_context, ensure_ascii=False) if threat_context else "{}"
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    async with _lock, aiosqlite.connect(_DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO pending_actions
                (correlation_id, action_type, target, threat_context, status, created_at)
            VALUES (?, ?, ?, ?, 'PENDING_APPROVAL', ?)
            """,
            (correlation_id, action_type, target, ctx_json, now),
        )
        await db.commit()
        row_id = cursor.lastrowid or 0
        logger.info(
            "[PendingActions] Queued #%d: %s %s (corr=%s)",
            row_id,
            action_type,
            target,
            correlation_id[:20],
        )
        return row_id


async def get_action(action_id: int) -> dict[str, Any] | None:
    """Get a single action by ID."""
    await _ensure_schema()
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM pending_actions WHERE id = ?", (action_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def list_pending(limit: int = 10) -> list[dict[str, Any]]:
    """List all PENDING_APPROVAL actions."""
    await _ensure_schema()
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM pending_actions WHERE status = 'PENDING_APPROVAL' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def update_status(action_id: int, status: str) -> bool:
    """Update action status. Returns True if row was found."""
    await _ensure_schema()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    async with _lock, aiosqlite.connect(_DB_PATH) as db:
        cursor = await db.execute(
            "UPDATE pending_actions SET status = ?, resolved_at = ? WHERE id = ?",
            (status, now, action_id),
        )
        await db.commit()
        return cursor.rowcount > 0


# ── Backward-compat API (wraps SQLite) ───────────────────────────


async def set_pending(action: dict[str, Any]) -> None:
    """Backward-compat: queue action from legacy dict format.

    Cancels all existing PENDING_APPROVAL actions first (singleton semantics).
    Expected dict keys: action, target, reason, (optional) correlation_id, threat_context.
    """
    # Cancel all existing pending (old singleton held max 1)
    existing = await list_pending(limit=100)
    for item in existing:
        await update_status(item["id"], "SUPERSEDED")

    action_type = str(action.get("action", action.get("tool", "unknown")))
    target = action.get("target", "")
    if not isinstance(target, str):
        target = json.dumps(target, ensure_ascii=False)
    corr = action.get("correlation_id", "")
    ctx = action.get("threat_context")
    if not ctx and action.get("reason"):
        ctx = {"reason": action["reason"]}
    await queue_action(action_type, target, correlation_id=corr, threat_context=ctx)


async def get_pending() -> dict[str, Any] | None:
    """Backward-compat: return most recent PENDING_APPROVAL action as legacy dict."""
    pending = await list_pending(limit=1)
    if not pending:
        return None
    row = pending[0]
    ctx = {}
    try:
        ctx = json.loads(row.get("threat_context", "{}"))
    except Exception:
        pass
    # Reconstruct target (may be JSON for complex args)
    target: Any = row["target"]
    try:
        target = json.loads(target)
    except (json.JSONDecodeError, TypeError):
        pass
    return {
        "action": row["action_type"],
        "target": target,
        "reason": ctx.get("reason", ""),
        "correlation_id": row.get("correlation_id", ""),
        "threat_context": ctx,
        "_row_id": row["id"],
    }


async def clear_pending() -> None:
    """Backward-compat: cancel most recent PENDING_APPROVAL action."""
    pending = await list_pending(limit=1)
    if pending:
        await update_status(pending[0]["id"], "CANCELLED")


async def queue_kill_for_ttp(
    pid: int,
    score: int,
    technique_id: str,
    signals: list[str],
    proc_name: str,
    cmdline: str,
) -> int:
    """Queue a kill_process action for a TTP detection with score >= 85.

    Target is a composite key ``{pid}|{proc_name}`` to guard against PID recycling
    — the executor verifies the process name matches before killing.

    Returns the row ID (0 on failure).
    """
    import uuid

    corr_id = str(uuid.uuid4())[:8]
    target = f"{pid}|{proc_name}"
    return await queue_action(
        action_type="kill_process",
        target=target,
        correlation_id=corr_id,
        threat_context={
            "score": score,
            "reason": f"TTP {technique_id}: {'; '.join(signals[:2])}",
            "cmdline": cmdline[:200],
            "process_name": proc_name,
        },
    )
