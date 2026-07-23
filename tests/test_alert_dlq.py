# tests/test_alert_dlq.py
"""Tests for Dead-Letter Queue: enqueue, retry, backoff, dead, no-dup-loop.

Critical test: test_sweeper_failure_does_not_create_duplicate_row
verifies the recursion paradox fix — sweeper failures call mark_retried,
NOT enqueue_dlq, so no exponential row duplication.
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from services import alert_dlq
from services.alert_dlq import (
    _MAX_RETRIES,
    delete_dlq,
    enqueue_dlq,
    fetch_due_dlq,
    get_dlq_stats,
    init_dlq_schema,
    mark_retried,
    sweep_dlq,
)


@pytest.fixture(autouse=True)
async def _isolated_dlq(tmp_path, monkeypatch):
    """Use a temp DB to avoid lock contention with alert_history's pool."""
    tmp_db = str(tmp_path / "test_alerts.db")
    # Patch the module-level pool to point at temp DB
    from services.db_pool import DBPool

    test_pool = DBPool(tmp_db, max_connections=2)
    monkeypatch.setattr(alert_dlq, "_pool", test_pool)
    await init_dlq_schema()
    yield
    await test_pool.close_all()


# ── Enqueue ──


async def test_enqueue_creates_pending_row():
    row_id = await enqueue_dlq({"analysis": "port scan"}, "Telegram timeout")
    assert row_id > 0
    stats = await get_dlq_stats()
    assert stats.get("pending") == 1


async def test_enqueue_stores_payload_json():
    payload = {"snapshot": {"cpu": 90}, "analysis": "alert text", "remediation": {"ip": "1.2.3.4"}}
    row_id = await enqueue_dlq(payload, "network error")
    due = await fetch_due_dlq()
    assert len(due) == 1
    assert due[0]["id"] == row_id
    decoded = json.loads(due[0]["payload"])
    assert decoded["analysis"] == "alert text"
    assert decoded["snapshot"]["cpu"] == 90


# ── Backoff ──


async def test_backoff_increments_retry_count():
    row_id = await enqueue_dlq({"x": 1}, "err")
    due = await fetch_due_dlq()
    assert due[0]["retry_count"] == 0

    await mark_retried(row_id, 0, "still failing")
    due = await fetch_due_dlq()
    # After mark_retried with count=0, next_retry_at = now + 2^1 = 2 min → not due now
    assert len(due) == 0


async def test_backoff_schedule_is_exponential():
    """Verify next_retry_at follows 2^count minutes pattern."""
    from services.alert_dlq import _compute_next_retry

    for count, expected_min in enumerate([1, 2, 4, 8, 16, 32, 64, 64]):
        ts = _compute_next_retry(count)
        delta = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") - datetime.now()
        # Allow 5s tolerance
        assert abs(delta.total_seconds() - expected_min * 60) < 10, f"count={count}"


# ── Dead marking ──


async def test_mark_dead_after_max_retries():
    row_id = await enqueue_dlq({"x": 1}, "err")
    # Simulate reaching max retries
    await mark_retried(row_id, _MAX_RETRIES - 1, "final failure")
    stats = await get_dlq_stats()
    assert stats.get("dead") == 1
    assert stats.get("pending", 0) == 0
    # Dead rows are NOT fetched by fetch_due_dlq
    due = await fetch_due_dlq()
    assert len(due) == 0


# ── Sweep: success path ──


async def test_sweep_delivers_and_deletes_row():
    await enqueue_dlq({"analysis": "test alert"}, "initial fail")
    due = await fetch_due_dlq()
    assert len(due) == 1

    with patch("services.alert_dispatcher_helpers._send_alert_raw", new_callable=AsyncMock):
        stats = await sweep_dlq()

    assert stats["delivered"] == 1
    assert stats["failed"] == 0
    # Row deleted after successful delivery
    due = await fetch_due_dlq()
    assert len(due) == 0


# ── Sweep: failure path (NO DUP LOOP — the critical test) ──


async def test_sweeper_failure_does_not_create_duplicate_row():
    """CRITICAL: sweeper failure must NOT enqueue a new DLQ row.

    This is the recursion-paradox fix. If the sweeper called _emit_and_persist
    (which has its own except→enqueue), each retry failure would create a
    new row, causing exponential DB bloat. The sweeper calls _send_alert_raw
    directly and calls mark_retried on failure — no new rows.
    """
    await enqueue_dlq({"analysis": "alert"}, "initial fail")
    initial_stats = await get_dlq_stats()
    assert initial_stats["pending"] == 1

    # _send_alert_raw raises → sweeper catches → mark_retried (NOT enqueue)
    with patch(
        "services.alert_dispatcher_helpers._send_alert_raw",
        new_callable=AsyncMock,
        side_effect=ConnectionError("Telegram still down"),
    ):
        stats = await sweep_dlq()

    assert stats["failed"] == 1
    assert stats["delivered"] == 0
    # Still exactly 1 row (not 2, not 3) — no duplication
    final_stats = await get_dlq_stats()
    assert final_stats["pending"] == 1, "Sweeper must NOT create duplicate DLQ rows"


async def test_sweeper_retries_then_succeeds():
    """First sweep fails (retry_count→1), second sweep succeeds (deleted)."""
    await enqueue_dlq({"analysis": "alert"}, "fail")

    with patch(
        "services.alert_dispatcher_helpers._send_alert_raw",
        new_callable=AsyncMock,
        side_effect=ConnectionError("down"),
    ):
        stats1 = await sweep_dlq()
    assert stats1["failed"] == 1

    # Manually make row due again (backoff would delay it 2 min)
    from services.alert_dlq import _pool

    past_ts = (datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    async with _pool.acquire() as db:
        await db.execute(
            "UPDATE alert_dlq SET next_retry_at=? WHERE status='pending'",
            (past_ts,),
        )
        await db.commit()

    with patch("services.alert_dispatcher_helpers._send_alert_raw", new_callable=AsyncMock):
        stats2 = await sweep_dlq()
    assert stats2["delivered"] == 1
    assert (await get_dlq_stats()).get("pending", 0) == 0


# ── Empty sweep ──


async def test_sweep_noop_when_empty():
    stats = await sweep_dlq()
    assert stats == {"retried": 0, "delivered": 0, "dead": 0, "failed": 0}


# ── _send_alert_raw isolation ──


async def test_send_alert_raw_calls_send_alert_event():
    """Verify _send_alert_raw is a thin wrapper that raises on failure."""
    from services.alert_dispatcher_helpers import _send_alert_raw

    payload = {"snapshot": {"a": 1}, "analysis": "x", "remediation": {"y": 2}}
    with patch("services.alert_dispatcher_helpers.send_alert_event", new_callable=AsyncMock) as mock:
        await _send_alert_raw(payload)
        mock.assert_called_once_with(snapshot={"a": 1}, analysis="x", remediation={"y": 2})


async def test_send_alert_raw_raises_on_failure():
    """_send_alert_raw must NOT swallow exceptions (unlike old _emit_and_persist)."""
    from services.alert_dispatcher_helpers import _send_alert_raw

    with patch(
        "services.alert_dispatcher_helpers.send_alert_event",
        new_callable=AsyncMock,
        side_effect=ConnectionError("network down"),
    ):
        with pytest.raises(ConnectionError, match="network down"):
            await _send_alert_raw({"analysis": "x"})


# ── Integration: _emit_and_persist enqueues on failure ──


async def test_emit_and_persist_enqueues_to_dlq_on_failure():
    """Main flow: _send_alert_raw fails → enqueue_dlq called → audit still saved."""
    from services.alert_dispatcher_helpers import _emit_and_persist

    alert = {"category": "net", "metric": "scan", "severity": "critical"}
    with (
        patch(
            "services.alert_dispatcher_helpers._send_alert_raw",
            new_callable=AsyncMock,
            side_effect=ConnectionError("Telegram 502"),
        ),
        patch("services.alert_dispatcher_helpers.save_alert", new_callable=AsyncMock) as mock_save,
    ):
        result = await _emit_and_persist(alert, "alert text", {"ip": "1.2.3.4"}, {"cpu": 50}, "net:scan")

    assert result is False  # first-attempt emit failed
    mock_save.assert_called_once()  # audit trail still persisted
    stats = await get_dlq_stats()
    assert stats["pending"] == 1  # enqueued to DLQ
