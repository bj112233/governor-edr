# services/net_baseline.py
"""Network baseline tracking — stores (process_name, remote_ip, remote_port, first_seen)
in SQLite for binary anomaly detection (exists vs. doesn't exist).

Sprint 5: Moved to metrics.db (isolated from alert_history.db) to eliminate
write lock contention with user-facing queries.
"""

import logging

from services.metrics_db import _ensure_init as _metrics_ensure_init
from services.metrics_db import get_metrics_pool

logger = logging.getLogger(__name__)

_init_done: bool = False


async def _ensure_table() -> None:
    """Create net_baselines + intel_whitelist tables if not exists."""
    global _init_done
    if _init_done:
        return
    await _metrics_ensure_init()
    _init_done = True
    logger.info("[NetBaseline] net_baselines + intel_whitelist tables ready (metrics.db)")


# H2 fix: Baseline entries expire after 90 days. Prevents permanent
# invisibility from baseline poisoning (low-and-slow C2 that learned
# its way into the baseline and then became malicious).
_BASELINE_TTL_DAYS = 90


async def is_known_combo(process_name: str, remote_ip: str, remote_port: int) -> bool:
    """Binary check: does this (process, ip, port) exist in baseline AND is it recent?

    H2 fix: Baseline entries older than 90 days are treated as unknown.
    M2 fix: Uses last_seen (updated on every observation) instead of
    first_seen. This ensures the TTL reflects the LAST time the combo
    was seen, not the first. Also performs lazy eviction — expired
    entries are deleted in the same transaction (no background job needed).

    This prevents permanent invisibility from baseline poisoning — a
    C2 beacon that was learned as benign and then weaponized will
    re-surface after the TTL window expires from last observation.
    """
    await _ensure_table()
    try:
        async with get_metrics_pool().acquire() as db:
            cursor = await db.execute(
                """
                SELECT 1 FROM net_baselines
                WHERE process_name = ? AND remote_ip = ? AND remote_port = ?
                  AND last_seen > datetime('now', ? || ' days')
                LIMIT 1
                """,
                (process_name, remote_ip, remote_port, -_BASELINE_TTL_DAYS),
            )
            row = await cursor.fetchone()
            if row is not None:
                return True
            # M2: Lazy eviction — delete expired entry if it exists
            await db.execute(
                """
                DELETE FROM net_baselines
                WHERE process_name = ? AND remote_ip = ? AND remote_port = ?
                  AND last_seen <= datetime('now', ? || ' days')
                """,
                (process_name, remote_ip, remote_port, -_BASELINE_TTL_DAYS),
            )
            await db.commit()
            return False
    except Exception as exc:
        logger.warning("[NetBaseline] is_known_combo failed: %s", exc)
        return False


async def record_net_baselines(connections: list[dict]) -> None:
    """Persist new (process_name, remote_ip, remote_port) combos.

    M2 fix: Uses ON CONFLICT DO UPDATE to refresh last_seen on every
    observation. This ensures the TTL check in is_known_combo() reflects
    the LAST time a combo was seen, not the first. Prevents baseline
    poisoning where a stale entry stays "valid" for 90 days after the
    last legitimate use.
    """
    await _ensure_table()
    if not connections:
        return
    rows = []
    seen = set()
    for c in connections:
        proc = c.get("proc_name", "unknown")
        rip = c.get("raddr_ip", "")
        rport = c.get("raddr_port", 0)
        if not rip or rport <= 0:
            continue
        if not proc or proc == "unknown":
            continue  # Don't learn blind combos — data integrity
        key = (proc, rip, rport)
        if key not in seen:
            seen.add(key)
            rows.append(key)
    if not rows:
        return
    try:
        async with get_metrics_pool().acquire() as db:
            await db.executemany(
                """
                INSERT INTO net_baselines (process_name, remote_ip, remote_port, last_seen)
                VALUES (?, ?, ?, datetime('now'))
                ON CONFLICT(process_name, remote_ip, remote_port)
                DO UPDATE SET last_seen = datetime('now')
                """,
                rows,
            )
            await db.commit()
        logger.debug("[NetBaseline] recorded/refreshed %d combos", len(rows))
    except Exception as exc:
        logger.warning("[NetBaseline] record failed: %s", exc)


async def add_to_baseline(process_name: str, remote_ip: str, remote_port: int) -> None:
    """Persist a single (process_name, remote_ip, remote_port) combo as benign.

    Called when user clicks 'Ignore' on an alert — teaches the system
    that this specific connection is legitimate.
    """
    await _ensure_table()
    if not remote_ip or remote_port <= 0:
        return
    if not process_name or process_name == "unknown":
        logger.debug(
            "[NetBaseline] Skipping baseline learning for unknown process on IP %s",
            remote_ip,
        )
        return
    try:
        async with get_metrics_pool().acquire() as db:
            await db.execute(
                """
                INSERT INTO net_baselines (process_name, remote_ip, remote_port, last_seen)
                VALUES (?, ?, ?, datetime('now'))
                ON CONFLICT(process_name, remote_ip, remote_port)
                DO UPDATE SET last_seen = datetime('now')
                """,
                (process_name, remote_ip, remote_port),
            )
            await db.commit()
        logger.info(
            "[NetBaseline] Learned benign combo: %s -> %s:%d",
            process_name,
            remote_ip,
            remote_port,
        )
    except Exception as exc:
        logger.warning("[NetBaseline] add_to_baseline failed: %s", exc)


async def is_intel_whitelisted(remote_ip: str) -> bool:
    """Check if an IP was previously scored as clean by threat intel.

    Uses explicit expires_at column (hard TTL, default 7 days from insertion).
    """
    await _ensure_table()
    try:
        async with get_metrics_pool().acquire() as db:
            cursor = await db.execute(
                "SELECT 1 FROM intel_whitelist WHERE remote_ip = ? AND expires_at > datetime('now') LIMIT 1",
                (remote_ip,),
            )
            row = await cursor.fetchone()
            return row is not None
    except Exception as exc:
        logger.warning("[NetBaseline] is_intel_whitelisted failed: %s", exc)
        return False


async def benign_baseline_ips(candidate_ips: set[str]) -> set[str]:
    """Return the subset of candidate_ips known-benign in the runtime baseline.

    An IP qualifies if it appears in a learned net_baselines combo (any
    process/port) OR in a live intel_whitelist entry. Runs ONE parameterized
    query per candidate — the candidate set is the handful of IPs found in a
    draft report, so N is tiny. This exists so the CPU-bound entity audit can
    stay pure/sync: the async DB work happens here (orchestration layer) and
    the resolved set is passed into the audit as data (dependency injection).
    """
    if not candidate_ips:
        return set()
    await _ensure_table()
    found: set[str] = set()
    try:
        async with get_metrics_pool().acquire() as db:
            for ip in candidate_ips:
                # M2: use last_seen for TTL consistency with is_known_combo
                cursor = await db.execute(
                    "SELECT 1 FROM net_baselines WHERE remote_ip = ? "
                    "AND last_seen > datetime('now', ? || ' days') LIMIT 1",
                    (ip, -_BASELINE_TTL_DAYS),
                )
                if await cursor.fetchone():
                    found.add(ip)
                    continue
                cursor = await db.execute(
                    "SELECT 1 FROM intel_whitelist WHERE remote_ip = ? AND expires_at > datetime('now') LIMIT 1",
                    (ip,),
                )
                if await cursor.fetchone():
                    found.add(ip)
    except Exception as exc:
        logger.warning("[NetBaseline] benign_baseline_ips failed: %s", exc)
    return found


async def record_intel_whitelist(remote_ip: str, ttl_days: int = 7) -> None:
    """Register an IP as clean (scored 0 by threat intel). Idempotent.

    Sets expires_at = now + ttl_days. Re-recording an IP refreshes the TTL.
    """
    await _ensure_table()
    if not remote_ip:
        return
    try:
        async with get_metrics_pool().acquire() as db:
            await db.execute(
                "INSERT OR REPLACE INTO intel_whitelist (remote_ip, first_seen, expires_at) "
                "VALUES (?, datetime('now'), datetime('now', ?))",
                (remote_ip, f"+{ttl_days} days"),
            )
            await db.commit()
        logger.debug("[NetBaseline] recorded intel whitelist for %s (TTL=%dd)", remote_ip, ttl_days)
    except Exception as exc:
        logger.warning("[NetBaseline] record_intel_whitelist failed: %s", exc)


async def cleanup_intel_whitelist() -> int:
    """Delete expired intel_whitelist entries. Returns deleted count.

    Called by the scheduler daily. Prevents unbounded table growth and
    ensures stale 'clean' IPs are purged once their TTL expires.
    """
    await _ensure_table()
    try:
        async with get_metrics_pool().acquire() as db:
            cursor = await db.execute("DELETE FROM intel_whitelist WHERE expires_at < datetime('now')")
            await db.commit()
            deleted = cursor.rowcount or 0
            if deleted:
                logger.info("[NetBaseline] cleanup_intel_whitelist: purged %d expired entries", deleted)
            return deleted
    except Exception as exc:
        logger.warning("[NetBaseline] cleanup_intel_whitelist failed: %s", exc)
        return 0
