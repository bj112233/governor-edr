"""Episodic Memory — event chains, escalation detection, temporal queries.

Read-time chaining: chain_id + ORDER BY ts ASC. No prev_event_id (race-free).
Escalation: composite-indexed COUNT(*) O(log N). Purge: 7-day retention.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

from .models import EventQuery, MemoryEvent
from .schema import _pool

logger = logging.getLogger(__name__)

_ESCALATION_WINDOW_MIN = 30
_ESCALATION_THRESHOLD = 3
_ESCALATION_MIN_SEVERITY = 2


class EpisodicStore:
    """CRUD + escalation detection for episodic events."""

    async def store(self, event: MemoryEvent) -> int:
        """Store event, return ID. Auto-detects escalation and injects escalation event."""
        async with _pool.acquire() as db:
            cursor = await db.execute(
                """
                INSERT INTO events (ts, event_type, description, severity,
                                    source, session_id, chain_id, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.ts,
                    event.event_type,
                    event.description,
                    event.severity,
                    event.source,
                    event.session_id,
                    event.chain_id,
                    event.metadata_json,
                ),
            )
            event_id = cursor.lastrowid
            await db.commit()

        await self._maybe_escalate(event)
        return event_id or 0

    async def _maybe_escalate(self, event: MemoryEvent) -> None:
        """If event matches escalation criteria, inject escalation event."""
        if event.event_type == "escalation":
            return
        if event.severity < _ESCALATION_MIN_SEVERITY:
            return
        count = await self._count_recent(event.source, event.event_type, window_minutes=_ESCALATION_WINDOW_MIN)
        if count >= _ESCALATION_THRESHOLD:
            existing = await self._has_escalation_for_chain(event.chain_id)
            if not existing:
                esc = MemoryEvent(
                    event_type="escalation",
                    description=(
                        f"Escalation: {count} {event.event_type} events "
                        f"from {event.source} in {_ESCALATION_WINDOW_MIN}m"
                    ),
                    severity=3,
                    source="episodic_store",
                    session_id=event.session_id,
                    chain_id=event.chain_id,
                    metadata_json=json.dumps(
                        {
                            "trigger_event_id": event.id,
                            "trigger_count": count,
                            "trigger_type": event.event_type,
                            "trigger_source": event.source,
                        },
                        ensure_ascii=False,
                    ),
                )
                await self.store(esc)
                logger.warning(
                    "[Episodic] Escalation injected for chain=%s source=%s",
                    event.chain_id,
                    event.source,
                )

    async def _count_recent(self, source: str, event_type: str, window_minutes: int) -> int:
        """O(log N) COUNT via composite index idx_events_escalation."""
        cutoff = (datetime.now() - timedelta(minutes=window_minutes)).isoformat()
        async with _pool.acquire() as db:
            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM events
                WHERE source = ? AND event_type = ? AND severity >= ?
                  AND ts > ?
                """,
                (source, event_type, _ESCALATION_MIN_SEVERITY, cutoff),
            )
            row = await cursor.fetchone()
            return row[0] if row else 0

    async def _has_escalation_for_chain(self, chain_id: str) -> bool:
        """True if escalation already recorded for this chain."""
        if not chain_id:
            return False
        async with _pool.acquire() as db:
            cursor = await db.execute(
                """
                SELECT 1 FROM events
                WHERE chain_id = ? AND event_type = 'escalation'
                LIMIT 1
                """,
                (chain_id,),
            )
            row = await cursor.fetchone()
            return row is not None

    async def get_chain(self, chain_id: str, limit: int = 50) -> list[MemoryEvent]:
        """Read-time chain reconstruction: ORDER BY ts ASC."""
        if not chain_id:
            return []
        async with _pool.acquire() as db:
            cursor = await db.execute(
                """
                SELECT id, ts, event_type, description, severity,
                       source, session_id, chain_id, metadata_json
                FROM events
                WHERE chain_id = ?
                ORDER BY ts ASC
                LIMIT ?
                """,
                (chain_id, limit),
            )
            rows = await cursor.fetchall()
            return [_row_to_event(row) for row in rows]

    async def query(self, eq: EventQuery) -> list[MemoryEvent]:
        """Flexible query by chain, type, source, time window."""
        clauses = []
        params: list = []
        if eq.chain_id:
            clauses.append("chain_id = ?")
            params.append(eq.chain_id)
        if eq.event_type:
            clauses.append("event_type = ?")
            params.append(eq.event_type)
        if eq.source:
            clauses.append("source = ?")
            params.append(eq.source)
        if eq.since_hours:
            cutoff = (datetime.now() - timedelta(hours=eq.since_hours)).isoformat()
            clauses.append("ts > ?")
            params.append(cutoff)

        where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
        query_sql = f"""
            SELECT id, ts, event_type, description, severity,
                   source, session_id, chain_id, metadata_json
            FROM events
            {where_sql}
            ORDER BY ts DESC
            LIMIT ?
        """
        params.append(eq.limit)

        async with _pool.acquire() as db:
            cursor = await db.execute(query_sql, tuple(params))
            rows = await cursor.fetchall()
            return [_row_to_event(row) for row in rows]

    async def purge_old(self, days: int = 7) -> int:
        """Delete events older than N days. Tactical episodic memory has short TTL."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        async with _pool.acquire() as db:
            cursor = await db.execute(
                "DELETE FROM events WHERE ts < ?",
                (cutoff,),
            )
            await db.commit()
            return cursor.rowcount


def _row_to_event(row) -> MemoryEvent:
    return MemoryEvent(
        id=row[0],
        ts=row[1],
        event_type=row[2],
        description=row[3],
        severity=row[4],
        source=row[5],
        session_id=row[6],
        chain_id=row[7],
        metadata_json=row[8],
    )
