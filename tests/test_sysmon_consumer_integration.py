# tests/test_sysmon_consumer_integration.py
"""E2E integration test: SysmonConsumer → alert_queue → llm_analysis_worker.

Verifies the full wiring that connects the SysmonConsumer to the existing
alert pipeline. This is the integration test required by AGENTS.md §6:
a new module feeding an existing pipeline must have an E2E test, not just
unit coverage on the module in isolation.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_sysmon_alert_reaches_send_alert_event():
    """E2E: SysmonConsumer alert dict → llm_analysis_worker → send_alert_event.

    The worker detects source="sysmon", bypasses LLM, builds a report
    from the matches, and calls send_alert_event.
    """
    from services.sentinel_events import get_alert_queue
    from services.startup._workers import llm_analysis_worker

    alert_queue = get_alert_queue()
    # Clear any pending items
    while not alert_queue.empty():
        alert_queue.get_nowait()

    # Simulate a SysmonConsumer alert (high-score T1027 match)
    sysmon_alert = {
        "pid": 1234,
        "name": "evil.exe",
        "cmdline": "evil.exe --bad",
        "image": "C:\\Users\\user\\evil.exe",
        "parent_image": "C:\\Windows\\explorer.exe",
        "sha256": "a" * 64,
        "integrity_level": "High",
        "matches": [
            {
                "technique_id": "T1027",
                "name": "Hash reputation",
                "tactic": "Defense Evasion",
                "score": 90,
                "signals": ["sha256 in known-bad set"],
            }
        ],
        "source": "sysmon",
    }
    await alert_queue.put(sysmon_alert)

    # Mock send_alert_event and save_alert to verify they're called
    with patch(
        "services.startup._workers.send_alert_event",
        AsyncMock(),
    ) as mock_send, patch(
        "services.startup._workers.save_alert",
        AsyncMock(),
    ) as mock_save:
        # Run the worker for a short time, then cancel
        worker_task = asyncio.create_task(llm_analysis_worker(alert_queue))
        await asyncio.sleep(0.3)
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass

    # send_alert_event WAS called with the sysmon alert
    assert mock_send.called, "send_alert_event was not called — Sysmon alert not processed"
    call_args = mock_send.call_args
    snapshot_arg = call_args.args[0]
    assert snapshot_arg["source"] == "sysmon"
    assert snapshot_arg["pid"] == 1234

    # save_alert WAS called
    assert mock_save.called
    # The report should contain the TTP info
    report_arg = mock_save.call_args.args[1]
    assert "T1027" in report_arg
    assert "90" in report_arg


@pytest.mark.asyncio
async def test_sysmon_alert_report_format():
    """_sysmon_alert_report formats TTP matches into a readable report."""
    from services.startup._workers import _sysmon_alert_report

    snapshot = {
        "pid": 999,
        "name": "powershell.exe",
        "image": "C:\\Windows\\System32\\powershell.exe",
        "matches": [
            {
                "technique_id": "T1059.001",
                "name": "PowerShell",
                "score": 90,
                "signals": ["encoded command", "base64 payload"],
            }
        ],
    }
    report = _sysmon_alert_report(snapshot)
    assert "PID 999" in report
    assert "powershell.exe" in report
    assert "T1059.001" in report
    assert "90" in report
    assert "encoded command" in report
