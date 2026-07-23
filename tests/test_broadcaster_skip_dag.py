# tests/test_broadcaster_skip_dag.py
"""Regression: dag_update events must NOT be forwarded to Telegram.

Reproduces the 2026-06-25 log-leakage bug where the event broadcaster
forwarded C2-dashboard-only events to the Telegram admin chat as raw
dict repr via the formatter fallback (formatters.py:168 ``f"[{et}] {d}"``).

Verified root cause: ``_telegram_event_broadcaster`` consumed ALL events
from the bus without filtering by event_type. ``dag_update`` is explicitly
marked "for the C2 dashboard" in ``sentinel_events.emit_dag_update``.
"""

import asyncio

import pytest

from services.sentinel_events import SentinelEvent, SentinelEventBus
from services.startup._broadcast import _TELEGRAM_SKIP_TYPES


def test_dag_update_is_in_skip_set():
    """dag_update must be listed in the Telegram skip set."""
    assert "dag_update" in _TELEGRAM_SKIP_TYPES


@pytest.mark.asyncio
async def test_dag_update_not_delivered_to_subscriber():
    """A dag_update event emitted on the bus must not reach a Telegram-style
    consumer that filters via _TELEGRAM_SKIP_TYPES.

    This mirrors the broadcaster's filter logic: events whose event_type is
    in _TELEGRAM_SKIP_TYPES are skipped before send_message is called.
    """
    bus = SentinelEventBus(max_size=64)
    queue = await bus.subscribe()

    dag_event = SentinelEvent(
        event_type="dag_update",
        priority="normal",
        data={"session_id": "test", "subtasks": [], "transition": None},
    )
    await bus.emit(dag_event)

    # Drain the queue applying the same filter the broadcaster uses.
    forwarded = []
    while not queue.empty():
        event = queue.get_nowait()
        if event.event_type in _TELEGRAM_SKIP_TYPES:
            continue
        forwarded.append(event)

    assert forwarded == [], f"dag_update leaked to Telegram consumer: {forwarded}"


@pytest.mark.asyncio
async def test_alert_still_delivered_after_skip_filter():
    """Sanity: non-skipped events (alert) must still pass the filter."""
    bus = SentinelEventBus(max_size=64)
    queue = await bus.subscribe()

    alert_event = SentinelEvent(
        event_type="alert",
        priority="high",
        data={"cpu": 10, "ram": 20, "analysis": "test", "snapshot": {}},
    )
    await bus.emit(alert_event)

    forwarded = []
    while not queue.empty():
        event = queue.get_nowait()
        if event.event_type in _TELEGRAM_SKIP_TYPES:
            continue
        forwarded.append(event)

    assert len(forwarded) == 1
    assert forwarded[0].event_type == "alert"


if __name__ == "__main__":
    asyncio.run(test_dag_update_not_delivered_to_subscriber())
    asyncio.run(test_alert_still_delivered_after_skip_filter())
    print("OK")
