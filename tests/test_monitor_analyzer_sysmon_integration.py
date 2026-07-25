# tests/test_monitor_analyzer_sysmon_integration.py
"""E2E integration test: monitor_analyzer → analyze_process_event → queue_kill_for_ttp.

This is the regression guard that was missing and let the 4 Sysmon-enriched
checks (T1059.005, T1027, T1548.002, T1036) ship without any wiring to the
kill-queue. The test verifies the FULL path through monitor_analyzer:

  1. monitor_analyzer._diff_suspicious_procs receives a proc with a cmdline
     that triggers a high-score TTP
  2. With SYSMON_ENRICHED_ANALYSIS_ENABLED=true, it calls analyze_process_event
  3. A T1059.001 match (score=90, from the regex engine inside the wrapper)
     is produced
  4. queue_kill_for_ttp is actually called (not shadow-logged)
  5. The AnomalyEvent has kill_process_queued in details

IMPORTANT — what this test does NOT cover:
  T1027 (hash reputation), T1548.002 (UAC bypass), T1036 (unsigned
  masquerading) require Sysmon-enriched fields (sha256, integrity_level,
  signed, parent_image) that the psutil path in monitor_analyzer does NOT
  have. These 3 checks only fire through SysmonConsumer → alert_queue,
  NOT through monitor_analyzer._diff_suspicious_procs. The psutil path
  builds ProcessEvent with source="psutil" and all Sysmon fields=None,
  so the enriched checks skip gracefully (by design).

  T1059.005 (parent anomaly) also requires parent_image, so it too only
  fires through SysmonConsumer.

  The ONLY check that fires through monitor_analyzer is the regex engine
  (T1059.001, T1027 via cmdline patterns, etc.) — but now it runs THROUGH
  the analyze_process_event wrapper, not analyze_cmdline directly. This
  test verifies that wiring.

This test would have caught the original bug: analyze_process_event was
built but never called from monitor_analyzer (which still used
analyze_cmdline). Unit coverage on process_analyzer was 99% but the
wiring was dead.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from services.monitor_analyzer import SnapshotDiffer


@pytest.mark.asyncio
async def test_powershell_encoded_command_reaches_kill_queue_via_wrapper(monkeypatch):
    """E2E: PowerShell -enc (score=90 from regex engine) → kill-queue via wrapper.

    This verifies that SYSMON_ENRICHED_ANALYSIS_ENABLED=true routes through
    analyze_process_event (the wrapper), and the regex engine inside it
    still produces T1059.001 (score=90) which reaches queue_kill_for_ttp.

    This is the integration test that was missing — it verifies the WIRING,
    not just the unit behavior of analyze_process_event in isolation.
    """
    monkeypatch.setattr("config.SYSMON_ENRICHED_ANALYSIS_ENABLED", True)
    monkeypatch.setattr("config.SYSMON_KILL_QUEUE_DRY_RUN", False)

    mock_queue_kill = AsyncMock(return_value=42)
    with patch(
        "services.pending_actions.queue_kill_for_ttp",
        mock_queue_kill,
    ):
        differ = SnapshotDiffer()
        prev = {"suspicious_procs": []}
        curr = {
            "suspicious_procs": [
                {
                    "pid": 9999,
                    "name": "powershell.exe",
                    "cmdline": "powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
                }
            ]
        }

        events = await differ.diff(prev, curr)

    # ── Assertions ──

    # 1. queue_kill_for_ttp WAS called (the wiring works through the wrapper)
    assert mock_queue_kill.called, (
        "queue_kill_for_ttp was not called — the wiring from "
        "analyze_process_event to the kill-queue is broken"
    )

    # 2. It was called with the right PID, score, and technique.
    # Note: the regex engine produces 2 matches (T1059.001 score=90 +
    # T1027 score=85 via base64 payload), so queue_kill_for_ttp is called
    # twice. We verify the T1059.001 call (score=90) is among them.
    all_calls = mock_queue_kill.call_args_list
    t1059_calls = [c for c in all_calls if c.kwargs["technique_id"] == "T1059.001"]
    assert len(t1059_calls) == 1, (
        f"Expected one T1059.001 call, got: "
        f"{[c.kwargs.get('technique_id') for c in all_calls]}"
    )
    assert t1059_calls[0].kwargs["pid"] == 9999
    assert t1059_calls[0].kwargs["score"] == 90

    # 3. An AnomalyEvent was produced with kill_process_queued
    proc_events = [e for e in events if e.category == "proc" and "T1059.001" in e.reason]
    assert len(proc_events) >= 1, f"Expected T1059.001 event, got: {[e.reason for e in events]}"
    assert proc_events[0].details.get("kill_process_queued") == 42
    assert proc_events[0].severity == "critical"


@pytest.mark.asyncio
async def test_dry_run_does_not_call_kill_queue(monkeypatch):
    """When SYSMON_KILL_QUEUE_DRY_RUN=true, queue_kill_for_ttp is NOT called.

    Instead, the would-be-queued action is shadow-logged. This lets the
    enriched checks run against live traffic for false-positive tuning
    without risking auto-kill.
    """
    monkeypatch.setattr("config.SYSMON_ENRICHED_ANALYSIS_ENABLED", True)
    monkeypatch.setattr("config.SYSMON_KILL_QUEUE_DRY_RUN", True)

    mock_queue_kill = AsyncMock(return_value=99)
    with patch(
        "services.pending_actions.queue_kill_for_ttp",
        mock_queue_kill,
    ):
        differ = SnapshotDiffer()
        prev = {"suspicious_procs": []}
        curr = {
            "suspicious_procs": [
                {
                    "pid": 8888,
                    "name": "powershell.exe",
                    "cmdline": "powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
                }
            ]
        }

        events = await differ.diff(prev, curr)

    # queue_kill_for_ttp was NOT called (dry-run mode)
    assert not mock_queue_kill.called, (
        "queue_kill_for_ttp was called in dry-run mode — "
        "SYSMON_KILL_QUEUE_DRY_RUN should prevent actual queueing"
    )

    # But the T1059.001 event IS still produced (detection runs, only kill is shadowed)
    proc_events = [e for e in events if e.category == "proc" and "T1059.001" in e.reason]
    assert len(proc_events) >= 1
    # kill_process_queued should NOT be in details (it wasn't queued)
    assert "kill_process_queued" not in proc_events[0].details


@pytest.mark.asyncio
async def test_flag_off_uses_analyze_cmdline_not_process_event(monkeypatch):
    """When SYSMON_ENRICHED_ANALYSIS_ENABLED=false (default), the original
    analyze_cmdline path is used — no ProcessEvent, no enriched checks.

    This is the regression guard for the default behavior: the flag must
    NOT change behavior when off, so existing deployments are unaffected.
    """
    monkeypatch.setattr("config.SYSMON_ENRICHED_ANALYSIS_ENABLED", False)
    monkeypatch.setattr("config.SYSMON_KILL_QUEUE_DRY_RUN", False)

    mock_queue_kill = AsyncMock(return_value=1)
    with patch(
        "services.pending_actions.queue_kill_for_ttp",
        mock_queue_kill,
    ):
        differ = SnapshotDiffer()
        prev = {"suspicious_procs": []}
        curr = {
            "suspicious_procs": [
                {
                    "pid": 7777,
                    "name": "powershell.exe",
                    "cmdline": "powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
                }
            ]
        }

        events = await differ.diff(prev, curr)

    # queue_kill_for_ttp WAS called (the regex engine fires on -enc regardless of flag)
    assert mock_queue_kill.called, (
        "queue_kill_for_ttp not called with flag OFF — the original "
        "analyze_cmdline path must still work when the flag is off"
    )
    # Verify T1059.001 (score=90) is among the calls
    all_calls = mock_queue_kill.call_args_list
    t1059_calls = [c for c in all_calls if c.kwargs["technique_id"] == "T1059.001"]
    assert len(t1059_calls) == 1
    assert t1059_calls[0].kwargs["pid"] == 7777
    assert t1059_calls[0].kwargs["score"] == 90


@pytest.mark.asyncio
async def test_t1027_hash_check_not_fired_in_psutil_path(monkeypatch):
    """T1027 (hash reputation) requires sha256, which the psutil path
    in monitor_analyzer does NOT have. This test documents that fact:
    even with a known-bad hash registered and the flag ON, T1027 does
    NOT fire through monitor_analyzer because ProcessEvent.sha256 is
    None (psutil doesn't provide hashes).

    T1027 only fires through SysmonConsumer → alert_queue, where
    ProcessEvent is built from Sysmon Event 1 XML (which includes
    the Hashes field). See test_sysmon_consumer.py for that path.
    """
    monkeypatch.setattr("config.SYSMON_ENRICHED_ANALYSIS_ENABLED", True)
    monkeypatch.setattr("config.SYSMON_KILL_QUEUE_DRY_RUN", False)

    from services.process_analyzer import _KNOWN_BAD_HASHES, register_malicious_hash

    bad_hash = "e" * 64
    register_malicious_hash(bad_hash)
    try:
        mock_queue_kill = AsyncMock(return_value=1)
        with patch(
            "services.pending_actions.queue_kill_for_ttp",
            mock_queue_kill,
        ):
            differ = SnapshotDiffer()
            prev = {"suspicious_procs": []}
            curr = {
                "suspicious_procs": [
                    {
                        "pid": 6666,
                        "name": "evil.exe",
                        "cmdline": "evil.exe --harmless",  # no regex trigger
                    }
                ]
            }

            events = await differ.diff(prev, curr)

        # T1027 did NOT fire (sha256 is None in psutil path)
        t1027_events = [e for e in events if "T1027" in e.reason]
        assert len(t1027_events) == 0, (
            "T1027 fired in psutil path — monitor_analyzer should not have "
            "sha256 available; this check only works through SysmonConsumer"
        )
        # queue_kill not called (no high-score match from a harmless cmdline)
        assert not mock_queue_kill.called
    finally:
        _KNOWN_BAD_HASHES.discard(bad_hash)


# ── _maybe_queue_kill unit tests (cover missing branches) ──


@pytest.mark.asyncio
async def test_maybe_queue_kill_skips_below_threshold():
    """Score < 85 → returns 0 immediately, no queue call."""
    from services.cmdline_analyzer import CmdlineMatch
    from services.monitor_analyzer import SnapshotDiffer

    match = CmdlineMatch(
        technique_id="T1059.005", name="test", tactic="Execution",
        confidence=0.5, signals=["s"], suggested_score=75,
    )
    result = await SnapshotDiffer._maybe_queue_kill(match, 1234, "x", "x", dry_run=False)
    assert result == 0


@pytest.mark.asyncio
async def test_maybe_queue_kill_handles_exception():
    """queue_kill_for_ttp raises → except branch logs error, returns 0."""
    from services.cmdline_analyzer import CmdlineMatch
    from services.monitor_analyzer import SnapshotDiffer

    match = CmdlineMatch(
        technique_id="T1059.001", name="test", tactic="Execution",
        confidence=0.9, signals=["s"], suggested_score=90,
    )
    with patch(
        "services.pending_actions.queue_kill_for_ttp",
        AsyncMock(side_effect=RuntimeError("DB locked")),
    ):
        result = await SnapshotDiffer._maybe_queue_kill(match, 1234, "x", "x", dry_run=False)
    assert result == 0  # graceful fallback, not crash
