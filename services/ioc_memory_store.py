# services/ioc_memory_store.py
"""
IOC Score History — temporal correlation via SQLite + exponential decay.

Stores per-IOC score events and recalls them with time-decay weighting.
Enables detection of Low-and-Slow attacks where individual scores stay
below threshold but accumulate over time.

Decay formula: S_decayed = S_i * exp(-dt / tau)
  tau = 14 days (half-life ~9.7 days — score halves every ~10 days)

Schema:
  ioc_score_history(
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,          -- 'ip' | 'domain' | 'hash'
    score INTEGER NOT NULL,          -- raw score at time of event (0-100)
    context_source TEXT,             -- 'VirusTotal', 'AbuseIPDB', etc.
    timestamp TEXT NOT NULL          -- ISO 8601 UTC
  )
"""

import asyncio
import logging
import time
from typing import Any

import aiosqlite

from services.db_pool import get_db_path

logger = logging.getLogger(__name__)

_DB_PATH = get_db_path("ioc_memory")
_lock = asyncio.Lock()
_initialized = False

# Decay constant: tau=14 days. After 14 days, score retains ~37% of original.
# Half-life = tau * ln(2) ≈ 9.7 days
_DECAY_TAU_DAYS = 14.0
_MAX_HISTORY_DAYS = 90  # Prune entries older than this


async def _ensure_schema() -> None:
    global _initialized
    if _initialized:
        return
    async with aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_score_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                context_source TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_score_history(ioc_value)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_ioc_type ON ioc_score_history(ioc_type)")
        await db.commit()
    _initialized = True


async def save_score(
    ioc_value: str,
    ioc_type: str,
    score: int,
    context_source: str = "",
) -> None:
    """Fire-and-forget: persist a score event for future recall."""
    await _ensure_schema()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    async with _lock, aiosqlite.connect(_DB_PATH) as db:
        await db.execute(
            "INSERT INTO ioc_score_history (ioc_value, ioc_type, score, context_source, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (ioc_value, ioc_type, score, context_source, now),
        )
        await db.commit()
    logger.debug(
        "[IOCMemory] Saved %s=%s score=%d source=%s",
        ioc_type,
        ioc_value[:30],
        score,
        context_source,
    )


async def recall_history(
    ioc_value: str,
    ioc_type: str = "",
    max_days: int = _MAX_HISTORY_DAYS,
) -> list[dict[str, Any]]:
    """Recall raw score events for an IOC within the decay window."""
    await _ensure_schema()
    cutoff = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - max_days * 86400),
    )
    async with aiosqlite.connect(_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if ioc_type:
            cursor = await db.execute(
                "SELECT * FROM ioc_score_history "
                "WHERE ioc_value = ? AND ioc_type = ? AND timestamp >= ? "
                "ORDER BY timestamp DESC",
                (ioc_value, ioc_type, cutoff),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM ioc_score_history WHERE ioc_value = ? AND timestamp >= ? ORDER BY timestamp DESC",
                (ioc_value, cutoff),
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def recall_decayed_score(
    ioc_value: str,
    ioc_type: str = "",
    tau_days: float = _DECAY_TAU_DAYS,
) -> float:
    """Recall history and compute decayed aggregate score.

    Returns the decayed sum of all historical scores (0-100 float).
    Uses exponential decay: S_i * exp(-dt_i / tau)
    """
    events = await recall_history(ioc_value, ioc_type)
    if not events:
        return 0.0

    now = time.time()
    total = 0.0
    for event in events:
        try:
            ts_str = event["timestamp"]
            # Parse ISO 8601 UTC: "2026-06-28T12:00:00Z"
            ts = time.mktime(time.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ"))
            dt_days = max(0.0, (now - ts) / 86400.0)
            decayed = float(event["score"]) * pow(2.718281828, -dt_days / tau_days)
            total += decayed
        except Exception:
            continue

    return min(total, 100.0)


async def recall_by_asn(
    asn: str,
    tau_days: float = _DECAY_TAU_DAYS,
) -> float:
    """Recall decayed scores for all IOCs sharing an ASN.

    Used for cross-IOC correlation: if multiple IPs from same ASN
    have history, the aggregate boosts the current IOC's score.
    """
    # ASN is stored as context_source="asn:AS123" in save_score
    events = await recall_history(f"asn:{asn}", "asn", max_days=int(tau_days * 4))
    if not events:
        return 0.0

    now = time.time()
    total = 0.0
    for event in events:
        try:
            ts = time.mktime(time.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
            dt_days = max(0.0, (now - ts) / 86400.0)
            total += float(event["score"]) * pow(2.718281828, -dt_days / tau_days)
        except Exception:
            continue

    return min(total, 100.0)


async def prune_old_entries(max_days: int = _MAX_HISTORY_DAYS) -> int:
    """Delete entries older than max_days. Returns count deleted."""
    await _ensure_schema()
    cutoff = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() - max_days * 86400),
    )
    async with _lock, aiosqlite.connect(_DB_PATH) as db:
        cursor = await db.execute(
            "DELETE FROM ioc_score_history WHERE timestamp < ?",
            (cutoff,),
        )
        await db.commit()
        deleted = cursor.rowcount
        if deleted:
            logger.info("[IOCMemory] Pruned %d entries older than %d days", deleted, max_days)
        return deleted
