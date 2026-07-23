#!/usr/bin/env python3
"""Sprint 5 Phase 3 — Atomic migration: static tables → reference.db + rename.

Usage:
    .venv\\Scripts\\python.exe scripts\\migrate_phase3_reference.py

Steps:
1. Create reference.db with schemas (via reference_store._ensure_init)
2. ATTACH alert_history.db, INSERT static tables, DROP from source, VACUUM
3. Rename alert_history.db → alerts.db
4. Update db_pool registry path

Idempotent: safe to run multiple times.
"""

import asyncio
import os
import sqlite3
import sys
from pathlib import Path

# Fix Windows console encoding for unicode output
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Ensure repo root on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from services.db_pool import DB_DIR, register_db_path  # noqa: E402

ALERT_HISTORY = DB_DIR / "alert_history.db"
ALERTS_DB = DB_DIR / "alerts.db"
REFERENCE_DB = DB_DIR / "reference.db"

STATIC_TABLES = ("osint_intel", "skill_state", "pairing_codes")


def _create_reference_schemas(conn: sqlite3.Connection) -> None:
    """Create all static tables in reference.db."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS osint_intel (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            topic           TEXT NOT NULL,
            raw_data        TEXT NOT NULL,
            extracted_iocs_json TEXT NOT NULL,
            embedding_blob  BLOB NOT NULL,
            timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_osint_topic ON osint_intel(topic);

        CREATE TABLE IF NOT EXISTS skill_state (
            key   TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS pairing_codes (
            code       TEXT PRIMARY KEY,
            user_id    TEXT    NOT NULL,
            user_name  TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            approved   INTEGER NOT NULL DEFAULT 0,
            expiry_min INTEGER NOT NULL DEFAULT 60
        );
        """
    )
    conn.commit()


def _migrate_static_tables(ref_conn: sqlite3.Connection, source_path: str) -> int:
    """ATTACH source, INSERT static tables, return total rows migrated."""
    ref_conn.execute(f"ATTACH DATABASE '{source_path}' AS source")
    total = 0
    for table in STATIC_TABLES:
        # Check if table exists in source
        exists = ref_conn.execute(
            "SELECT name FROM source.sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if not exists:
            continue
        count = ref_conn.execute(f"SELECT COUNT(*) FROM source.{table}").fetchone()[0]
        if count == 0:
            continue
        ref_conn.execute(f"INSERT OR IGNORE INTO {table} SELECT * FROM source.{table}")
        total += count
        print(f"   ✓ Migrated {count} rows from source.{table}")
    ref_conn.commit()
    ref_conn.execute("DETACH DATABASE source")
    ref_conn.commit()
    return total


async def run_migration() -> None:
    print("=" * 60)
    print("Sprint 5 Phase 3 — reference.db migration + rename")
    print("=" * 60)

    # Step 1: Create reference.db with schemas (synchronous, no pool)
    print("\n[1/4] Creating reference.db schemas...")
    ref_conn = sqlite3.connect(str(REFERENCE_DB))
    ref_conn.execute("PRAGMA busy_timeout=5000")
    ref_conn.execute("PRAGMA journal_mode=WAL")
    _create_reference_schemas(ref_conn)
    ref_conn.close()
    print(f"   ✓ {REFERENCE_DB.name} ready")

    # Step 2: Migrate static tables from alert_history.db
    print("\n[2/4] Migrating static tables from alert_history.db...")
    if not ALERT_HISTORY.exists():
        print(f"   ⚠ {ALERT_HISTORY.name} not found — nothing to migrate")
    else:
        ref_conn = sqlite3.connect(str(REFERENCE_DB))
        ref_conn.execute("PRAGMA busy_timeout=5000")
        migrated = _migrate_static_tables(ref_conn, str(ALERT_HISTORY))
        ref_conn.close()
        print(f"   ✓ Migrated {migrated} total rows")

        # Step 3: Drop static tables from source + VACUUM
        print("\n[3/4] Dropping static tables from alert_history.db + VACUUM...")
        src_conn = sqlite3.connect(str(ALERT_HISTORY))
        src_conn.execute("PRAGMA busy_timeout=5000")
        for table in STATIC_TABLES:
            try:
                src_conn.execute(f"DROP TABLE IF EXISTS {table}")
                print(f"   ✓ Dropped {table}")
            except sqlite3.OperationalError as e:
                print(f"   ⚠ Could not drop {table}: {e}")
        src_conn.commit()
        src_conn.execute("VACUUM")
        src_conn.close()
        print("   ✓ VACUUM complete")

    # Step 4: Rename alert_history.db → alerts.db
    print("\n[4/4] Renaming alert_history.db → alerts.db...")
    if ALERTS_DB.exists():
        print(f"   ⚠ {ALERTS_DB} already exists — skipping rename")
    elif ALERT_HISTORY.exists():
        # Close any WAL/SHM files first
        for ext in ("-wal", "-shm"):
            sidecar = ALERT_HISTORY.with_suffix(f".db{ext}")
            if sidecar.exists():
                try:
                    sidecar.unlink()
                except OSError:
                    pass
        ALERT_HISTORY.rename(ALERTS_DB)
        print(f"   ✓ {ALERT_HISTORY.name} → {ALERTS_DB.name}")
    else:
        print("   ⚠ Neither alert_history.db nor alerts.db found — skipping")

    # Update registry
    register_db_path("alerts", str(ALERTS_DB))
    print(f"   ✓ db_pool registry updated: alerts → {ALERTS_DB.name}")

    # Verify final state
    print("\n" + "=" * 60)
    print("Verification:")
    for db_file, expected_tables in [
        (REFERENCE_DB, {"osint_intel", "skill_state", "pairing_codes"}),
        (ALERTS_DB, {"alerts", "audit_log"}),
    ]:
        if db_file.exists():
            c = sqlite3.connect(str(db_file))
            tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            c.close()
            size = db_file.stat().st_size // 1024
            status = "✓" if expected_tables.issubset(tables) else "✗"
            print(f"  {status} {db_file.name}: {size}KB, tables={sorted(tables)}")
        else:
            print(f"  ✗ {db_file.name}: NOT FOUND")
    print("=" * 60)
    print("Done. Update db_pool.py _DB_PATHS['alerts'] to point to alerts.db.")


if __name__ == "__main__":
    asyncio.run(run_migration())
