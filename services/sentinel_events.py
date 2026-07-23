# services/sentinel_events.py
"""
Sentinel Event Bus — Local in-process event system.
Events are queued for downstream consumers (MCP polling, subscribers).
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from config import SENTINEL_ALERT_QUEUE_MAX

logger = logging.getLogger(__name__)


@dataclass
class SentinelEvent:
    """Represents a Sentinel event."""

    event_type: str  # "alert", "report", "daily_digest", "critical_override"
    priority: str  # "low", "normal", "high", "critical"
    data: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: f"evt_{int(time.time() * 1000)}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "priority": self.priority,
            "data": self.data,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(self.timestamp).isoformat(),
        }


class SentinelEventBus:
    """
    In-process event bus.

    Events are stored in a bounded deque and delivered to any async subscribers.
    Downstream systems may poll via `get_pending_events` or subscribe via
    `subscribe()` / `unsubscribe()`.
    """

    def __init__(self, max_size: int = SENTINEL_ALERT_QUEUE_MAX):
        self._queue: deque = deque(maxlen=max_size)
        self._subscribers: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def emit(self, event: SentinelEvent) -> None:
        """Emit an event to the bus."""
        async with self._lock:
            self._queue.append(event)
            subs = list(self._subscribers)

        for sub in subs:
            try:
                sub.put_nowait(event)
            except asyncio.QueueFull:
                # Bounded subscriber: evict oldest, then enqueue new event
                try:
                    sub.get_nowait()
                    sub.task_done()
                    sub.put_nowait(event)
                    logger.warning(
                        "[EventBus] Subscriber queue full — evicted oldest to deliver %s",
                        event.id,
                    )
                except Exception as exc:
                    logger.error(
                        "[EventBus] Failed to deliver %s after eviction: %s",
                        event.id,
                        exc,
                    )
            except Exception as exc:
                logger.error("[EventBus] Failed to deliver %s: %s", event.id, exc)

        logger.info(f"[EventBus] Emitted {event.event_type} ({event.priority}): {event.id}")

    async def emit_alert(
        self,
        snapshot: dict[str, Any],
        analysis: str | None = None,
        remediation: dict | None = None,
    ) -> SentinelEvent:
        """Emit a security alert event."""
        # Guarantee non-empty analysis/description — fallback to anomaly trigger
        # name to prevent downstream 'N/A' payloads.
        safe_analysis = (analysis or "").strip()
        if not safe_analysis:
            trigger = ""
            if isinstance(remediation, dict):
                cat = (remediation.get("category") or "").strip()
                metric = (remediation.get("metric") or "").strip()
                trigger = ":".join(p for p in (cat, metric) if p)
            safe_analysis = (
                trigger or (snapshot.get("trigger") if isinstance(snapshot, dict) else None) or "אירוע ללא תיאור"
            )

        event = SentinelEvent(
            event_type="alert",
            priority="high" if snapshot.get("alert_needed") else "normal",
            data={
                "snapshot": snapshot,
                "analysis": safe_analysis,
                "remediation": remediation,
                "cpu": snapshot.get("cpu", 0),
                "ram": snapshot.get("mem", 0),
                "disk_alerts": snapshot.get("disk_alerts", []),
                "suspicious_connections": snapshot.get("suspicious_net", []),
            },
        )
        await self.emit(event)
        return event

    async def emit_critical_override(self, snapshot: dict[str, Any]) -> SentinelEvent:
        """Emit a critical override event (persistent anomaly)."""
        event = SentinelEvent(
            event_type="critical_override",
            priority="critical",
            data={
                "snapshot": snapshot,
                "message": "Persistent anomaly detected after 5 minutes",
                "cpu": snapshot.get("cpu", 0),
                "ram": snapshot.get("mem", 0),
            },
        )
        await self.emit(event)
        return event

    async def emit_daily_digest(self, report: str, ai_analysis: str) -> SentinelEvent:
        """Emit daily digest report."""
        event = SentinelEvent(
            event_type="daily_digest",
            priority="normal",
            data={
                "report": report,
                "ai_analysis": ai_analysis,
            },
        )
        await self.emit(event)
        return event

    async def emit_weekly_reflection(self, report: str) -> SentinelEvent:
        """Emit weekly reflection report (Critic Node output)."""
        event = SentinelEvent(
            event_type="weekly_reflection",
            priority="normal",
            data={"report": report},
        )
        await self.emit(event)
        return event

    async def emit_threat_hunt(
        self,
        snapshot: dict[str, Any],
        analysis: str,
        threat_score: float,
        mitre_techniques: list[dict[str, Any]] | None = None,
    ) -> SentinelEvent:
        """Emit a proactive threat-hunt finding (dispatched only when score > threshold)."""
        priority = "critical" if threat_score >= 0.8 else "high"
        event = SentinelEvent(
            event_type="threat_hunt",
            priority=priority,
            data={
                "snapshot": snapshot,
                "analysis": analysis,
                "threat_score": threat_score,
                "cpu": snapshot.get("cpu", 0),
                "ram": snapshot.get("mem", 0),
                "suspicious_connections": snapshot.get("suspicious_net", []),
                "mitre_techniques": mitre_techniques or [],
            },
        )
        await self.emit(event)
        return event

    async def emit_dag_update(
        self,
        session_id: str,
        subtasks: list[dict[str, Any]],
        transition: dict[str, Any] | None = None,
    ) -> SentinelEvent:
        """Emit a DAG state transition for the C2 dashboard.

        Args:
            session_id: Unique agent session identifier (from id(ctx) or FSM).
            subtasks: Full snapshot of ctx.subtasks (list of dicts with
                id, description, depends_on, status, result?).
            transition: Optional {task_id, from_status, to_status} if this
                emit represents a state change. None for initial DAG publish.
        """
        event = SentinelEvent(
            event_type="dag_update",
            priority="normal",
            data={
                "session_id": session_id,
                "subtasks": subtasks,
                "transition": transition,
            },
        )
        await self.emit(event)
        return event

    def get_pending_events(self, limit: int = 10) -> list[dict[str, Any]]:
        """Get pending events from queue (for MCP polling)."""
        events = list(self._queue)[-limit:]
        return [e.to_dict() for e in events]

    def clear_queue(self) -> int:
        """Clear the event queue. Returns number of events cleared."""
        count = len(self._queue)
        self._queue.clear()
        return count

    async def subscribe(self, maxsize: int = 256) -> asyncio.Queue:
        """Subscribe to real-time events with a bounded queue (default 256)."""
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        async with self._lock:
            self._subscribers.append(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue) -> None:
        """Unsubscribe from events."""
        async with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)


# Global event bus instance
event_bus = SentinelEventBus()

# Dedicated asyncio queue for raw alert snapshots (decouples monitor from LLM latency)
_alert_analysis_queue: asyncio.Queue = asyncio.Queue(maxsize=SENTINEL_ALERT_QUEUE_MAX)


async def put_alert_snapshot(snapshot: dict[str, Any]) -> None:
    """Fire-and-forget: enqueue a raw alert snapshot for LLM analysis."""
    try:
        _alert_analysis_queue.put_nowait(snapshot)
    except asyncio.QueueFull:
        logger.warning("[AlertQueue] Queue full — dropping oldest snapshot")
        try:
            _alert_analysis_queue.get_nowait()
            _alert_analysis_queue.task_done()
        except asyncio.QueueEmpty:
            pass
        try:
            _alert_analysis_queue.put_nowait(snapshot)
        except asyncio.QueueFull:
            logger.error("[AlertQueue] Still full after eviction — dropping snapshot")


def get_alert_queue() -> asyncio.Queue:
    """Return the global alert analysis queue."""
    return _alert_analysis_queue


# Convenience functions
async def send_alert_event(
    snapshot: dict[str, Any],
    analysis: str | None = None,
    remediation: dict | None = None,
) -> SentinelEvent:
    """Send a security alert via the event bus."""
    return await event_bus.emit_alert(snapshot, analysis, remediation)


async def send_critical_override_event(snapshot: dict[str, Any]) -> SentinelEvent:
    """Send a critical override alert via the event bus."""
    return await event_bus.emit_critical_override(snapshot)


async def send_daily_digest_event(report: str, ai_analysis: str) -> SentinelEvent:
    """Send daily digest via the event bus."""
    return await event_bus.emit_daily_digest(report, ai_analysis)


async def send_weekly_reflection_event(report: str) -> SentinelEvent:
    """Send weekly reflection via the event bus."""
    return await event_bus.emit_weekly_reflection(report)


async def send_threat_hunt_event(
    snapshot: dict[str, Any],
    analysis: str,
    threat_score: float,
    mitre_techniques: list[dict[str, Any]] | None = None,
) -> SentinelEvent:
    """Send a proactive threat-hunt finding via the event bus."""
    return await event_bus.emit_threat_hunt(snapshot, analysis, threat_score, mitre_techniques)


async def send_dag_update_event(
    session_id: str,
    subtasks: list[dict[str, Any]],
    transition: dict[str, Any] | None = None,
) -> SentinelEvent:
    """Send a DAG state transition via the event bus (for C2 dashboard SSE)."""
    return await event_bus.emit_dag_update(session_id, subtasks, transition)
