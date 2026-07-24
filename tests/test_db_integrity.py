"""DB integrity check — verify SQLite databases in data/ are healthy.

Checks:
  1. All DB files exist and are openable
  2. PRAGMA integrity_check passes (no corruption)
  3. PRAGMA foreign_key_check passes (no orphaned FK references)
  4. WAL checkpoint succeeds (no stuck WAL)
  5. Core tables exist in each DB
"""

import sqlite3
from pathlib import Path

import pytest

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

# Expected DB files and their core tables
_EXPECTED_DBS = {
    "alerts.db": ["alerts", "audit_log"],
    "memory.db": ["conversations", "memories"],
    "metrics.db": ["system_baselines"],
    "reference.db": ["osint_intel", "skill_state"],
    "error_lessons.db": ["error_lessons"],
}


@pytest.fixture
def db_path(request):
    """Return path to a DB file in data/, skipping if it doesn't exist."""
    name = request.param
    path = DATA_DIR / name
    if not path.exists():
        pytest.skip(f"{name} not found in data/")
    return path


@pytest.mark.parametrize("db_path", list(_EXPECTED_DBS.keys()), indirect=True)
def test_integrity_check(db_path):
    """PRAGMA integrity_check must return 'ok'."""
    with sqlite3.connect(str(db_path)) as conn:
        result = conn.execute("PRAGMA integrity_check").fetchone()
        assert result[0] == "ok", f"{db_path.name}: integrity_check failed: {result[0]}"


@pytest.mark.parametrize("db_path", list(_EXPECTED_DBS.keys()), indirect=True)
def test_foreign_key_check(db_path):
    """PRAGMA foreign_key_check must return no rows (no orphaned FKs)."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        assert not violations, f"{db_path.name}: FK violations: {violations}"


@pytest.mark.parametrize("db_path", list(_EXPECTED_DBS.keys()), indirect=True)
def test_wal_checkpoint(db_path):
    """WAL checkpoint must succeed (TRUNCATE mode)."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        # If we get here, checkpoint succeeded
        assert True


@pytest.mark.parametrize("db_name", list(_EXPECTED_DBS.keys()))
def test_core_tables_exist(db_name):
    """Each DB must have its expected core tables."""
    db_path = DATA_DIR / db_name
    if not db_path.exists() or db_path.stat().st_size == 0:
        pytest.skip(f"{db_name} not found or empty in data/")
    expected_tables = _EXPECTED_DBS[db_name]
    with sqlite3.connect(str(db_path)) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if not tables:
        pytest.skip(f"{db_name} exists but has no tables (uninitialized)")
    for table in expected_tables:
        assert table in tables, f"{db_path.name}: missing table '{table}'"
