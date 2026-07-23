"""Connection pool for aiosqlite — central routing engine for multi-DB.

Sprint 5 Phase 2: get_pool(db_type=...) routes to the correct SQLite file.
All WAL/busy_timeout/foreign_keys pragmas live here — single source of truth.

DB types:
  - "alerts":    alerts.db (alerts + audit_log — cold SOC storage)
  - "memory":    memory.db (conversations, memories, user_profiles, events)
  - "metrics":   metrics.db (system_baselines, net_baselines — hot telemetry)
  - "reference": reference.db (osint_intel, skill_state, pairing_codes — static)
"""

import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import aiosqlite

logger = logging.getLogger(__name__)

_POOLS: dict[str, "DBPool"] = {}

_BASE_DIR = Path(__file__).parent.parent

# All SQLite databases live in <repo>/data/ — keeps the root directory clean
# and separates runtime state from source code. Import this instead of
# recomputing Path(__file__).parent.parent / "<name>.db" elsewhere.
DB_DIR = _BASE_DIR / "data"
DB_DIR.mkdir(parents=True, exist_ok=True)

# Central registry: db_type → file path
_DB_PATHS: dict[str, str] = {
    "alerts": str(DB_DIR / "alerts.db"),
    "memory": str(DB_DIR / "memory.db"),
    "metrics": str(DB_DIR / "metrics.db"),
    "reference": str(DB_DIR / "reference.db"),
    "pending_actions": str(DB_DIR / "pending_actions.db"),
    "ioc_memory": str(DB_DIR / "ioc_memory.db"),
}


class DBPool:
    """Simple aiosqlite connection pool. SQLite is single-writer; pool
    keeps N persistent connections open for concurrent readers."""

    def __init__(self, db_path: str, max_connections: int = 4, post_connect=None) -> None:
        self.db_path = db_path
        self._max = max(max_connections, 1)
        self._conns: list[aiosqlite.Connection] = []
        self._available: list[aiosqlite.Connection] = []
        self._lock: asyncio.Lock | None = None  # lazy init (needs running loop)
        self._post_connect = post_connect

    async def _init(self) -> None:
        if self._lock is None:
            self._lock = asyncio.Lock()

    async def _open(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.db_path, timeout=20.0)
        if self._post_connect:
            await self._post_connect(db)
        await db.execute("PRAGMA busy_timeout=5000")
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.execute("PRAGMA foreign_keys=ON")
        return db

    @asynccontextmanager
    async def acquire(self) -> AsyncGenerator[aiosqlite.Connection, None]:
        await self._init()
        conn: aiosqlite.Connection | None = None
        is_fallback = False

        assert self._lock is not None  # guaranteed by _init()
        async with self._lock:
            if not self._available and len(self._conns) < self._max:
                new_conn = await self._open()
                self._conns.append(new_conn)
                self._available.append(new_conn)

            if self._available:
                conn = self._available.pop()
            else:
                is_fallback = True

        if is_fallback:
            logger.warning("[DBPool] Pool exhausted for %s, using fresh connection", self.db_path)
            fallback_conn = await self._open()
            try:
                yield fallback_conn
            finally:
                await fallback_conn.close()
            return

        assert conn is not None  # guaranteed: not is_fallback means conn was popped
        try:
            yield conn
        finally:
            # Hygiene: clear any transaction left open by the caller so the
            # next acquirer gets a clean connection. Without this, a pooled
            # connection carrying an open transaction makes a subsequent
            # manual `BEGIN IMMEDIATE` fail with "cannot start a transaction
            # within a transaction". Rollback (not commit) is the safe choice:
            # uncommitted state is by definition not the caller's intent.
            if conn.in_transaction:
                try:
                    await conn.rollback()
                except Exception as exc:
                    logger.warning("[DBPool] rollback-on-release failed: %s", exc)
            assert self._lock is not None
            async with self._lock:
                self._available.append(conn)

    async def set_post_connect(self, post_connect) -> None:
        """Update post_connect hook and recycle existing connections
        so new ones pick up the hook (e.g., vectorlite extension).

        Lock-protected: a concurrent acquire() must not pop a connection
        that is about to be closed (race condition → OperationalError).
        """
        await self._init()
        assert self._lock is not None
        async with self._lock:
            self._post_connect = post_connect
            # Close existing connections synchronously under lock —
            # fire-and-forget (create_task) would race with acquire().
            for conn in list(self._conns):
                try:
                    await conn.close()
                except Exception:
                    pass
            self._conns.clear()
            self._available.clear()

    async def close_all(self) -> None:
        """Close all connections. Lock-protected to prevent race with acquire()."""
        await self._init()
        assert self._lock is not None
        async with self._lock:
            for conn in self._conns:
                try:
                    await conn.close()
                except Exception:
                    pass
            self._conns.clear()
            self._available.clear()


def get_pool(
    db_path: str = "",
    max_connections: int = 4,
    post_connect=None,
    db_type: str | None = None,
) -> DBPool:
    """Get or create a DBPool.

    Two modes:
      1. db_type="memory"|"metrics"|"alerts" — routes via central registry
      2. db_path="/explicit/path.db" — legacy direct path (backwards compat)
    """
    if db_type:
        db_path = _DB_PATHS[db_type]
    key = str(Path(db_path).resolve())
    if key not in _POOLS:
        _POOLS[key] = DBPool(key, max_connections, post_connect)
    return _POOLS[key]


def get_db_path(db_type: str) -> str:
    """Return the file path for a registered db_type."""
    return _DB_PATHS[db_type]


def register_db_path(db_type: str, path: str) -> None:
    """Override or register a new db_type → path mapping (used by tests)."""
    _DB_PATHS[db_type] = path


async def close_all_pools() -> None:
    for pool in _POOLS.values():
        await pool.close_all()
    _POOLS.clear()
