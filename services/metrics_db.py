"""Metrics database — isolated SQLite for high-frequency telemetry.

Separates system_baselines + net_baselines from alert_history.db to eliminate
write lock contention between the 30s monitor cycle and user-facing queries.

Tables:
  - system_baselines: (id, timestamp, metric, value, hour) — 149K+ rows
  - net_baselines: (id, process_name, remote_ip, remote_port, first_seen)
  - intel_whitelist: (id, remote_ip, first_seen, expires_at) — kept here because
    it's co-queried with net_baselines during anomaly checks. expires_at enforces
    a hard TTL (default 7 days); cleanup_intel_whitelist() purges stale rows.
"""

import logging
from pathlib import Path

import aiosqlite

from services.db_pool import DB_DIR, get_pool

logger = logging.getLogger(__name__)

_METRICS_DB_PATH = str(DB_DIR / "metrics.db")
_init_done: bool = False


def get_metrics_pool():
    """Return the DBPool instance for metrics.db."""
    return get_pool(_METRICS_DB_PATH, max_connections=2)


async def _ensure_init() -> None:
    """Create metrics tables if not exists. Idempotent."""
    global _init_done
    if _init_done:
        return
    async with get_metrics_pool().acquire() as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS system_baselines (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metric    TEXT NOT NULL,
                value     REAL NOT NULL,
                hour      INTEGER NOT NULL
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_baseline_metric_hour ON system_baselines(metric, hour, timestamp)"
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_baseline_ts ON system_baselines(timestamp)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS net_baselines (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name   TEXT NOT NULL,
                remote_ip      TEXT NOT NULL,
                remote_port    INTEGER NOT NULL,
                first_seen     DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(process_name, remote_ip, remote_port)
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_net_baseline_lookup ON net_baselines(process_name, remote_ip, remote_port)"
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS intel_whitelist (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                remote_ip  TEXT NOT NULL UNIQUE,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_intel_whitelist_lookup ON intel_whitelist(remote_ip)")
        # Migration: add expires_at column to pre-existing tables (SQLite < 3.35
        # cannot ALTER TABLE ADD COLUMN with IF NOT EXISTS, so guard via PRAGMA).
        cursor = await db.execute("PRAGMA table_info(intel_whitelist)")
        cols = {row[1] for row in await cursor.fetchall()}
        if "expires_at" not in cols:
            await db.execute("ALTER TABLE intel_whitelist ADD COLUMN expires_at DATETIME")
            # Backfill: legacy rows get expires_at = first_seen + 7 days
            await db.execute(
                "UPDATE intel_whitelist SET expires_at = datetime(first_seen, '+7 days') WHERE expires_at IS NULL"
            )
            logger.info("[MetricsDB] intel_whitelist: added expires_at column + backfilled legacy rows")

        # M2 fix: Schema migration for net_baselines.last_seen column.
        # Uses PRAGMA user_version for strict version control — no blind
        # try/except. last_seen tracks the LAST time a combo was observed
        # (vs. first_seen which never updates). Enables lazy eviction.
        cursor = await db.execute("PRAGMA user_version")
        schema_version = (await cursor.fetchone())[0]
        if schema_version < 1:
            # Idempotent guard: check if column already exists (e.g. from
            # a partially-completed previous migration)
            cursor = await db.execute("PRAGMA table_info(net_baselines)")
            nb_cols = {row[1] for row in await cursor.fetchall()}
            if "last_seen" not in nb_cols:
                # SQLite forbids non-constant defaults (CURRENT_TIMESTAMP) in
                # ALTER TABLE ADD COLUMN — add without default, then backfill.
                await db.execute("ALTER TABLE net_baselines ADD COLUMN last_seen DATETIME")
                # Backfill: legacy rows get last_seen = first_seen
                await db.execute("UPDATE net_baselines SET last_seen = first_seen WHERE last_seen IS NULL")
                logger.info("[MetricsDB] net_baselines: added last_seen column + backfilled legacy rows")
            await db.execute("PRAGMA user_version = 1")
            logger.info("[MetricsDB] Schema migrated to user_version=1 (net_baselines.last_seen)")

        await db.commit()
    _init_done = True
    logger.info("[MetricsDB] system_baselines + net_baselines + intel_whitelist ready (WAL)")


async def migrate_from_alert_history(source_path: str | None = None) -> int:
    """One-time migration: copy baseline tables from alert_history.db to metrics.db.

    Uses ATTACH DATABASE for atomic cross-DB copy. Safe to run multiple times
    (INSERT OR IGNORE). Returns total rows migrated.

    Call this at startup if metrics.db is empty but alert_history.db has data.
    """
    if source_path is None:
        source_path = str(DB_DIR / "alerts.db")

    if not Path(source_path).exists():
        logger.info("[MetricsDB] No source DB found, skipping migration")
        return 0

    await _ensure_init()
    total = 0
    async with get_metrics_pool().acquire() as db:
        await db.execute(f"ATTACH DATABASE '{source_path}' AS source")

        # Check which source tables exist (post-migration, they may be dropped)
        cursor = await db.execute(
            "SELECT name FROM source.sqlite_master WHERE type='table' "
            "AND name IN ('system_baselines','net_baselines','intel_whitelist')"
        )
        existing = {row[0] for row in await cursor.fetchall()}
        if not existing:
            await db.execute("DETACH DATABASE source")
            logger.info("[MetricsDB] No baseline tables in source, already migrated")
            return 0

        # system_baselines
        if "system_baselines" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO system_baselines (timestamp, metric, value, hour) "
                "SELECT timestamp, metric, value, hour FROM source.system_baselines"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        # net_baselines
        if "net_baselines" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO net_baselines (process_name, remote_ip, remote_port, first_seen) "
                "SELECT process_name, remote_ip, remote_port, first_seen FROM source.net_baselines"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        # intel_whitelist
        if "intel_whitelist" in existing:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
                "SELECT remote_ip, first_seen, datetime(first_seen, '+7 days') "
                "FROM source.intel_whitelist"
            )
            total += cursor.rowcount if cursor.rowcount > 0 else 0

        await db.commit()
        await db.execute("DETACH DATABASE source")

    if total > 0:
        logger.info("[MetricsDB] Migrated %d rows from %s", total, source_path)

        # Drop old tables from source DB to reclaim space (offloaded to thread — VACUUM blocks).
        # Safe: data already committed to metrics.db.
        try:
            import asyncio
            import sqlite3

            def _cleanup_source():
                conn = sqlite3.connect(source_path, timeout=30.0)
                conn.execute("PRAGMA busy_timeout=10000")
                conn.execute("DROP TABLE IF EXISTS system_baselines")
                conn.execute("DROP TABLE IF EXISTS net_baselines")
                conn.execute("DROP TABLE IF EXISTS intel_whitelist")
                conn.execute("VACUUM")
                conn.close()

            await asyncio.to_thread(_cleanup_source)
            logger.info("[MetricsDB] Dropped old tables + vacuumed source DB")
        except Exception as exc:
            logger.warning("[MetricsDB] Source cleanup failed: %s", exc)

    return total
