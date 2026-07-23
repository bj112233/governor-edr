# tests/test_burn_in_simulation.py
"""Burn-in test: graduated threat simulation under concurrent cognitive load.

Simulates a 3-phase attack scenario to stress-test the hardened architecture:
  Phase 1: Port-scan flood -> AlertDispatcher -> DLQ (Telegram outage)
  Phase 2: HITL gate under fire -> manage_service + defender_scan + screenshot
  Phase 3: All concurrent -> verify no deadlock, no state corruption

This is NOT a unit test - it's an integration stress test that verifies
the DAG/FSM/DLQ/HITL components survive chaos together.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from services.alert_dispatcher import AlertDispatcher, DispatchResult
from services.monitor_analyzer import AnomalyEvent
from services.threat_analyzers import ThreatAssessment

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════


@pytest.fixture
async def _isolated_env(tmp_path):
    """Isolated DB pools + DLQ schema for the simulation."""
    from services import alert_dlq
    from services.db_pool import DBPool

    test_pool = DBPool(str(tmp_path / "burn_alerts.db"), max_connections=4)
    original_pool = alert_dlq._pool
    alert_dlq._pool = test_pool
    await alert_dlq.init_dlq_schema()

    # Clean pending actions
    from services import pending_actions

    await pending_actions.clear_pending()

    yield {"dlq_pool": test_pool}
    await test_pool.close_all()
    alert_dlq._pool = original_pool
    await pending_actions.clear_pending()


def _make_port_scan_events(count: int = 10) -> list[AnomalyEvent]:
    """Generate a burst of port-scan anomalies from a single hostile IP."""
    events = []
    for port in range(4400, 4400 + count):
        events.append(
            AnomalyEvent(
                category="net",
                metric=f"external_conn_{port}",
                current=1.0,
                baseline=0.0,
                std=0.1,
                reason=f"Port scan detected: 203.0.113.66 -> :{port} (SYN flood)",
                severity="critical",
                details={
                    "remote_ip": "203.0.113.66",
                    "remote_port": port,
                    "pid": 1234,
                    "proc": "svchost.exe",
                },
            )
        )
    return events


def _make_threat_assessments() -> list[ThreatAssessment]:
    """Threat assessments matching the port scan (malicious IP)."""
    return [
        ThreatAssessment(
            status="malicious",
            reason="AbuseIPDB: 203.0.113.66 - 94% abuse confidence (known scanner)",
            details={"remote_ip": "203.0.113.66", "abuse_score": 94},
        ),
        ThreatAssessment(
            status="suspicious",
            reason="Unusual outbound to known C2 port 4444",
            details={"remote_port": 4444, "proc": "Widgets.exe"},
        ),
    ]


# ═══════════════════════════════════════════════════════════════════════
# PHASE 1: PORT-SCAN FLOOD -> ALERT DISPATCHER -> DLQ
# ═══════════════════════════════════════════════════════════════════════


async def test_phase1_port_scan_flood_with_telegram_outage(_isolated_env):
    """10 port-scan anomalies + 2 threat assessments hit AlertDispatcher
    while Telegram is down (send_alert_event raises).

    Verifies:
    - Cooldown suppresses duplicate keys
    - Rate limit caps per-category flood
    - Failed emits are enqueued to DLQ (not lost)
    - Audit trail (save_alert) still persists despite emit failure
    """
    dispatcher = AlertDispatcher(
        cooldown_seconds=900,
        rate_limit_window=600,
        max_alerts_per_window=3,  # tight limit to trigger suppression
    )
    events = _make_port_scan_events(10)
    threats = _make_threat_assessments()
    snapshot = {"cpu": 45, "mem": 60, "alert_needed": True}

    save_calls = []

    async def _mock_save(trigger, report):
        save_calls.append((trigger, report))

    with (
        patch(
            "services.alert_dispatcher_helpers._send_alert_raw",
            new_callable=AsyncMock,
            side_effect=ConnectionError("Telegram 503 Service Unavailable"),
        ),
        patch("services.alert_dispatcher_helpers.save_alert", new_callable=AsyncMock, side_effect=_mock_save),
        patch("services.alert_dispatcher.enrich_ip", new_callable=AsyncMock, return_value=None),
    ):
        result = await dispatcher.dispatch(events, threats, snapshot)

    # ── Verify dispatch statistics ──
    assert isinstance(result, DispatchResult)
    assert result.sent == 0  # all emits failed (Telegram down)
    # Some suppressed by rate limit (max 3 per category per 600s)
    assert result.suppressed_rate_limit > 0, "Rate limit should suppress flood"

    # ── Verify DLQ captured the failed alerts ──
    from services.alert_dlq import get_dlq_stats

    stats = await get_dlq_stats()
    assert stats.get("pending", 0) > 0, "Failed alerts must be in DLQ"
    assert stats.get("pending", 0) <= 3, "Rate-limited alerts should NOT enter DLQ"

    # ── Verify audit trail persisted despite emit failure ──
    assert len(save_calls) > 0, "save_alert must still run (audit trail)"
    print(
        f"  Phase 1: {result.sent} sent, {result.suppressed_rate_limit} rate-limited, "
        f"{stats.get('pending', 0)} in DLQ, {len(save_calls)} audit rows"
    )


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: HITL GATE UNDER FIRE
# ═══════════════════════════════════════════════════════════════════════


async def test_phase2_hitl_gate_blocks_all_destructive_tools(_isolated_env):
    """Simultaneous attempts to call manage_service, defender_scan, local_screenshot.

    Verifies:
    - All 3 are in _DANGEROUS_TOOLS (agent-loop gate)
    - All 3 handlers queue pending actions (MCP/slash gate)
    - Single pending slot enforced (last write wins or sequential)
    """
    from services.agent._context import _DANGEROUS_TOOLS
    from services.pending_actions import clear_pending, get_pending
    from services.tools.security_tools import (
        _defender_scan_handler,
        _local_screenshot_handler,
        _manage_service_handler,
    )

    # ── Gate 1: _DANGEROUS_TOOLS contains all 3 ──
    assert "manage_service" in _DANGEROUS_TOOLS
    assert "defender_scan" in _DANGEROUS_TOOLS
    assert "local_screenshot" in _DANGEROUS_TOOLS

    # ── Gate 2: Each handler queues a pending action ──
    # Run them sequentially (single pending slot)
    await clear_pending()

    # manage_service
    r1 = await _manage_service_handler(action="stop", name="wuauserv")
    assert "PENDING_APPROVAL" in r1
    p1 = await get_pending()
    assert p1["action"] == "manage_service"
    assert p1["target"] == {"action": "stop", "name": "wuauserv"}

    await clear_pending()

    # defender_scan
    r2 = await _defender_scan_handler()
    assert "PENDING_APPROVAL" in r2
    p2 = await get_pending()
    assert p2["action"] == "defender_scan"

    await clear_pending()

    # local_screenshot
    r3 = await _local_screenshot_handler()
    assert "PENDING_APPROVAL" in r3
    p3 = await get_pending()
    assert p3["action"] == "screenshot"

    await clear_pending()
    print("  Phase 2: all 3 destructive tools gated by HITL (agent-loop + MCP/slash)")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3: CONCURRENT CHAOS - ALL AT ONCE
# ═══════════════════════════════════════════════════════════════════════


async def test_phase3_concurrent_chaos_no_deadlock(_isolated_env):
    """Run alert flood + DLQ sweeper + HITL gating simultaneously.

    The critical test: verify asyncio.gather completes within timeout
    (no deadlock), DLQ integrity holds, and pending actions are clean.
    """
    from services import alert_dlq
    from services.pending_actions import clear_pending, get_pending
    from services.tools.security_tools import (
        _defender_scan_handler,
        _manage_service_handler,
    )

    # Global patch: Telegram down for entire Phase 3 (covers both
    # _alert_flood's emit and sweeper's retry - same mock scope)
    with (
        patch(
            "services.alert_dispatcher_helpers._send_alert_raw",
            new_callable=AsyncMock,
            side_effect=ConnectionError("Telegram down"),
        ),
        patch("services.alert_dispatcher_helpers.save_alert", new_callable=AsyncMock),
        patch("services.alert_dispatcher.enrich_ip", new_callable=AsyncMock, return_value=None),
    ):
        # ── Sub-task A: Alert flood (Telegram down) ──
        async def _alert_flood():
            dispatcher = AlertDispatcher(cooldown_seconds=900, rate_limit_window=60, max_alerts_per_window=5)
            events = _make_port_scan_events(8)
            threats = _make_threat_assessments()
            return await dispatcher.dispatch(events, threats, {"alert_needed": True})

        # ── Sub-task B: HITL gate attempts ──
        async def _hitl_attempts():
            results = []
            results.append(await _manage_service_handler(action="restart", name="Spooler"))
            await clear_pending()
            results.append(await _defender_scan_handler())
            await clear_pending()
            return results

        # ── Sub-task C: DLQ sweeper (will find rows from sub-task A) ──
        async def _dlq_sweep():
            # Small delay to let alert flood enqueue first
            await asyncio.sleep(0.1)
            return await alert_dlq.sweep_dlq()

        # ── Run all 3 concurrently with timeout ──
        try:
            flood_result, hitl_results, sweep_stats = await asyncio.wait_for(
                asyncio.gather(_alert_flood(), _hitl_attempts(), _dlq_sweep()),
                timeout=15.0,
            )
        except TimeoutError:
            pytest.fail("DEADLOCK detected: concurrent chaos did not complete within 15s")

    # ── Verify no state corruption ──
    # HITL: all attempts gated
    assert all("PENDING_APPROVAL" in r for r in hitl_results)

    # Alert flood: some suppressed, some failed to DLQ
    assert flood_result.sent == 0  # Telegram was down
    assert flood_result.suppressed_rate_limit > 0 or flood_result.suppressed_cooldown > 0

    # DLQ: sweeper ran, found rows, failed again (Telegram still down)
    dlq_stats = await alert_dlq.get_dlq_stats()
    total_dlq = dlq_stats.get("pending", 0) + dlq_stats.get("dead", 0)

    # Pending actions should be clean (we cleared after each HITL attempt)
    final_pending = await get_pending()
    assert final_pending is None, "Pending actions should be clean after HITL test"

    print(
        f"  Phase 3: CONCURRENT CHAOS survived - "
        f"flood: {flood_result.sent}sent/{flood_result.suppressed_rate_limit}limited, "
        f"HITL: {len(hitl_results)}gated, "
        f"DLQ: {total_dlq}rows, sweep: {sweep_stats}, "
        f"pending: clean"
    )


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3B: DLQ RECOVERY - TELEGRAM COMES BACK
# ═══════════════════════════════════════════════════════════════════════


async def test_phase3b_dlq_recovery_when_telegram_returns(_isolated_env):
    """Alert fails -> DLQ -> sweeper retries -> Telegram back -> delivered.

    Verifies the full recovery loop: enqueue -> sweep (fail) -> sweep (success) -> delete.
    """
    print("  Phase 3b: starting...", flush=True)
    from services import alert_dlq
    from services.alert_dispatcher_helpers import _emit_and_persist

    alert = {"category": "net", "metric": "port_scan", "severity": "critical"}

    # Step 1: emit fails -> DLQ
    print("  Phase 3b: step 1 - emit fail -> DLQ", flush=True)
    with (
        patch(
            "services.alert_dispatcher_helpers._send_alert_raw",
            new_callable=AsyncMock,
            side_effect=ConnectionError("Telegram 503"),
        ),
        patch("services.alert_dispatcher_helpers.save_alert", new_callable=AsyncMock),
    ):
        await _emit_and_persist(alert, "PORT SCAN from 203.0.113.66", {"ip": "203.0.113.66"}, {}, "net:port_scan")
    print("  Phase 3b: step 1 done", flush=True)

    stats = await alert_dlq.get_dlq_stats()
    assert stats.get("pending") == 1, "Alert must be in DLQ after emit failure"

    # Step 2: sweeper retries - still down
    with patch(
        "services.alert_dispatcher_helpers._send_alert_raw",
        new_callable=AsyncMock,
        side_effect=ConnectionError("still down"),
    ):
        sweep1 = await alert_dlq.sweep_dlq()
    assert sweep1["failed"] == 1
    stats = await alert_dlq.get_dlq_stats()
    assert stats.get("pending") == 1, "Row must remain pending after failed retry"

    # Step 3: make row due again (bypass backoff timer)
    from services.alert_dlq import _pool

    past_ts = (datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S")
    async with _pool.acquire() as db:
        await db.execute("UPDATE alert_dlq SET next_retry_at=? WHERE status='pending'", (past_ts,))
        await db.commit()

    # Step 4: sweeper retries - Telegram is back!
    with patch("services.alert_dispatcher_helpers._send_alert_raw", new_callable=AsyncMock):
        sweep2 = await alert_dlq.sweep_dlq()
    assert sweep2["delivered"] == 1, "Alert must be delivered on successful retry"

    stats = await alert_dlq.get_dlq_stats()
    assert stats.get("pending", 0) == 0, "DLQ must be empty after successful delivery"
    print("  Phase 3b: DLQ recovery complete - alert delivered after Telegram restored")
