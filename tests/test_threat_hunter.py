# tests/test_threat_hunter.py
"""Unit tests for proactive threat hunting orchestrator.

Covers: pre-flight skip logic, prompt truncation, dispatch rule, dedup.
"""

from unittest.mock import AsyncMock, patch

from services.hunt_prompt import build_hunt_prompt as _build_hunt_prompt
from services.hunt_prompt import extract_threat_score as _extract_threat_score
from services.pre_hunt_enricher import PreHuntReport
from services.threat_hunter import (
    threat_hunt_job,
)

_EMPTY_PRE_HUNT = PreHuntReport()


def _stub_snapshot() -> dict:
    return {
        "cpu": 45.0,
        "mem": 60.0,
        "disk_alerts": [],
        "suspicious_net": ["1.2.3.4", "5.6.7.8"],
    }


# ── Pre-flight: skip on resource guard ──


async def test_run_hunt_skips_on_resource_guard():
    with (
        patch(
            "services.threat_hunter._RESOURCE_GUARD.check",
            return_value=(False, "CPU 85%"),
        ),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock) as mock_agent,
    ):
        from services.threat_hunter import _run_hunt

        result = await _run_hunt()
    assert result.skipped is not None
    assert "resource guard" in result.skipped
    assert result.dispatched is False
    mock_agent.assert_not_called()


# ── Pre-flight: skip on cooldown ──


async def test_run_hunt_skips_on_cooldown():
    import services.threat_hunter as mod

    with (
        patch(
            "services.threat_hunter._RESOURCE_GUARD.check",
            return_value=(True, ""),
        ),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", __import__("time").time()),
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock) as mock_agent,
    ):
        result = await mod._run_hunt()
    assert result.skipped == "cooldown"
    mock_agent.assert_not_called()


# ── Prompt builder: truncation ──


async def test_prompt_truncation_under_budget():
    alerts = [(f"2026-06-21 0{i}:00:00", "X" * 500, "report") for i in range(20)]
    memory = "M" * 5000  # way over cap — builder must truncate
    prompt = _build_hunt_prompt(_stub_snapshot(), alerts, memory)
    # 2000 tokens ≈ ≤8000 chars even for Hebrew; assert well under
    assert len(prompt) < 8000
    # Only THREAT_HUNT_MAX_ALERTS (5) alert lines should appear
    assert prompt.count("התראה ") <= 5
    # Memory truncated to THREAT_HUNT_MAX_MEMORY_CHARS (500)
    assert "M" * 501 not in prompt
    assert "Encoded Commands" in prompt
    assert "Execution Policy Bypass" in prompt


# ── Dispatch rule: low score → no Telegram ──


async def test_dispatch_low_score_no_telegram():
    import services.threat_hunter as mod

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=_stub_snapshot(),
        ),
        patch(
            "services.threat_hunter.get_recent_alerts",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "services.threat_hunter.recall_context",
            new_callable=AsyncMock,
            return_value="",
        ),
        patch(
            "services.threat_hunter.get_last_hunt",
            new_callable=AsyncMock,
            return_value=None,
        ),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_EMPTY_PRE_HUNT,
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="הכל תקין.\n<SCORE>0.3</SCORE>",
        ),
        patch(
            "services.threat_hunter.send_threat_hunt_event",
            new_callable=AsyncMock,
        ) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()
    assert result.threat_score == 0.3
    assert result.dispatched is False
    mock_send.assert_not_called()


# ── Dispatch rule: high score → Telegram ──


async def test_dispatch_high_score_telegram():
    import services.threat_hunter as mod

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=_stub_snapshot(),
        ),
        patch(
            "services.threat_hunter.get_recent_alerts",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "services.threat_hunter.recall_context",
            new_callable=AsyncMock,
            return_value="",
        ),
        patch(
            "services.threat_hunter.get_last_hunt",
            new_callable=AsyncMock,
            return_value=None,
        ),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_EMPTY_PRE_HUNT,
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="איום קריטי זוהה.\n<SCORE>0.8</SCORE>",
        ),
        patch(
            "services.threat_hunter.send_threat_hunt_event",
            new_callable=AsyncMock,
        ) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()
    # Scoring v3.0: LLM 0.8 → cap to 0.5 (no external evidence) → cap to 0.4 (no external IOCs)
    assert result.threat_score == 0.4
    assert result.dispatched is False  # 0.4 < 0.6 threshold
    mock_send.assert_not_called()


# ── Dedup: same prompt_hash → skip ──


async def test_dedup_same_prompt_hash_skips():
    import hashlib

    import services.threat_hunter as mod

    # Build the same prompt the builder would produce, compute its hash
    snapshot = _stub_snapshot()
    expected_prompt = mod._build_hunt_prompt(snapshot, [], "", "")
    expected_hash = hashlib.sha256(expected_prompt.encode()).hexdigest()[:16]

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=snapshot,
        ),
        patch(
            "services.threat_hunter.get_recent_alerts",
            new_callable=AsyncMock,
            return_value=[],
        ),
        patch(
            "services.threat_hunter.recall_context",
            new_callable=AsyncMock,
            return_value="",
        ),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_EMPTY_PRE_HUNT,
        ),
        patch(
            "services.threat_hunter.get_last_hunt",
            new_callable=AsyncMock,
            return_value={"prompt_hash": expected_hash, "threat_score": 0.5},
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
        ) as mock_agent,
    ):
        result = await mod._run_hunt()
    assert result.skipped == "duplicate prompt"
    mock_agent.assert_not_called()


# ── State Machine: get_hunt_status() observability ──


def test_hunt_status_initial_state_is_idle():
    """Fresh _HuntStatus defaults to IDLE with zeroed fields."""
    from services.threat_hunter import _HuntStatus, get_hunt_status

    # The module-level _HUNT_STATUS may have been mutated by prior tests;
    # verify the dataclass default and the get_hunt_status contract.
    fresh = _HuntStatus()
    assert fresh.state == "IDLE"
    assert fresh.last_run_ts == 0.0
    assert fresh.last_score == 0.0
    assert fresh.hunt_count == 0

    status = get_hunt_status()
    assert "state" in status
    assert "last_run_iso" in status
    assert "next_run_iso" in status
    assert "seconds_until_next" in status
    assert "cooldown_hours" in status
    assert "interval_hours" in status


async def test_hunt_status_non_blocking_does_not_acquire_mutex():
    """get_hunt_status() must never block on _HUNT_MUTEX.

    If it tried to acquire the mutex while a hunt is running, the dashboard
    poll would hang. Verify it completes instantly even under contention.
    """
    from services.threat_hunter import _HUNT_MUTEX, get_hunt_status

    # Acquire the mutex to simulate a running hunt
    async with _HUNT_MUTEX:
        # get_hunt_status must NOT try to acquire — should return immediately
        status = get_hunt_status()
    assert isinstance(status, dict)
    assert "state" in status


async def test_hunt_status_records_skip_reason_on_cooldown():
    """When preflight skips on cooldown, last_skip_reason is recorded."""
    import services.threat_hunter as mod

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", __import__("time").time()),
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock),
    ):
        await mod._run_hunt()
    status = mod.get_hunt_status()
    assert status["last_skip_reason"] == "cooldown"
    assert status["state"] == "IDLE"


async def test_hunt_status_updates_score_and_count_after_hunt():
    """After a successful hunt, last_score and hunt_count are updated."""
    import services.threat_hunter as mod

    initial_count = mod._HUNT_STATUS.hunt_count
    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=_stub_snapshot(),
        ),
        patch("services.threat_hunter.get_recent_alerts", new_callable=AsyncMock, return_value=[]),
        patch("services.threat_hunter.recall_context", new_callable=AsyncMock, return_value=""),
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_EMPTY_PRE_HUNT,
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="THREAT_SCORE: 0.35",
        ),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock),
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        await mod._run_hunt()
    status = mod.get_hunt_status()
    # 0.35 ≤ 0.4 no-external-IOC clamp → stays 0.35
    assert status["last_score"] == 0.35
    assert status["last_dispatched"] is False
    assert status["hunt_count"] == initial_count + 1
    assert status["last_run_ts"] > 0
    assert status["state"] == "IDLE"


# ── Threat score extraction ──


def test_extract_threat_score_valid():
    # XML tag (primary format — what the prompt requests)
    assert _extract_threat_score("report text\n<SCORE>0.75</SCORE>") == 0.75
    # Line-anchored fallback (secondary format)
    assert _extract_threat_score("report text\nTHREAT_SCORE: 0.75") == 0.75


def test_extract_threat_score_missing():
    """Missing score returns 0.1 (fail-closed), not 0.0 (clean)."""
    assert _extract_threat_score("no score here") == 0.1


def test_extract_threat_score_clamped():
    assert _extract_threat_score("THREAT_SCORE: 1.5") == 1.0
    # Negative score is unparseable (regex expects [0-9]) → 0.1 fail-closed
    assert _extract_threat_score("THREAT_SCORE: -0.3") == 0.1


# ── Global TTP Override (v3.3): local TTP is ground truth, overrides all IOC paths ──


def _ttp_snapshot() -> dict:
    """Snapshot with a suspicious process carrying an encoded PowerShell TTP."""
    return {
        "cpu": 45.0,
        "mem": 60.0,
        "disk_alerts": [],
        "suspicious_net": [],
        "suspicious_procs": [{"pid": 999, "name": "powershell.exe", "cmdline": "-enc SGVsbG8="}],
    }


async def test_ttp_override_no_ioc_path_dispatches_at_1_0():
    """TTP detected + no external IOCs → score=1.0 + dispatch (not clamped to 0.4).

    Physical law: local TTP is ground truth. A clean/absent network signature
    must NOT cancel a malicious behavioral signature. Before v3.3, the no-IOC
    path clamped to 0.4 regardless of TTP — a LOLBin attacker with a fresh IP
    (no IOC) would be silenced.
    """
    import services.threat_hunter as mod

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=_ttp_snapshot(),
        ),
        patch("services.threat_hunter.get_recent_alerts", new_callable=AsyncMock, return_value=[]),
        patch("services.threat_hunter.recall_context", new_callable=AsyncMock, return_value=""),
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_EMPTY_PRE_HUNT,  # has_any_ioc == False → no-IOC path
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="איום זוהה.\n<SCORE>0.3</SCORE>",  # LLM says low
        ),
        patch(
            "services.behavioral_escape_hatch.has_local_ttp",
            return_value=True,
        ),
        patch(
            "services.threat_hunter.send_threat_hunt_event",
            new_callable=AsyncMock,
        ) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()
    assert result.threat_score == 1.0
    assert result.dispatched is True
    mock_send.assert_called_once()


async def test_ttp_override_mixed_ioc_path_dispatches_at_1_0():
    """TTP detected + mixed/unknown IOC status → score=1.0 + dispatch.

    Before v3.3, the mixed-IOC path (neither all_clean nor malicious) applied
    no clamp and no escape hatch — TTP was never checked. A LOLBin attacker
    with an IP of unknown reputation would pass through unscored.
    """
    import services.threat_hunter as mod

    mixed_pre_hunt = PreHuntReport()
    mixed_pre_hunt.enriched = {"1.2.3.4": {"score": 10, "available": False}}  # not clean, not malicious

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch(
            "services.threat_hunter.get_system_snapshot",
            new_callable=AsyncMock,
            return_value=_ttp_snapshot(),
        ),
        patch("services.threat_hunter.get_recent_alerts", new_callable=AsyncMock, return_value=[]),
        patch("services.threat_hunter.recall_context", new_callable=AsyncMock, return_value=""),
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=mixed_pre_hunt,  # has_any_ioc=True, all_clean=False, not malicious
        ),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="איום זוהה.\n<SCORE>0.3</SCORE>",
        ),
        patch(
            "services.behavioral_escape_hatch.has_local_ttp",
            return_value=True,
        ),
        patch(
            "services.threat_hunter.send_threat_hunt_event",
            new_callable=AsyncMock,
        ) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()
    assert result.threat_score == 1.0
    assert result.dispatched is True
    mock_send.assert_called_once()


# ── v3.3.1: TTP Override must NOT bypass hallucination firewall ──────────────


async def test_ttp_override_skipped_when_hallucination_firewall_zeroed_score():
    """TTP override guard: if hallucination firewall set llm_score=0.0 (fabricated
    IOCs), TTP override must NOT elevate back to 1.0.

    Regression test for Critic Node 2026-07-10 finding: hunt id=107 had
    [HALLUCINATION_FLAG] in summary but score=1.0 + dispatched=True.
    """
    import services.threat_hunter as mod

    no_ioc_pre_hunt = PreHuntReport()
    no_ioc_pre_hunt.enriched = {}
    no_ioc_pre_hunt.failed = []  # has_any_ioc = bool(enriched or failed) = False

    hallucinated_report = "Threat found at IP 23.94.10.202\n<SCORE>0.9</SCORE>"

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch("services.threat_hunter.get_system_snapshot", new_callable=AsyncMock, return_value=_ttp_snapshot()),
        patch("services.threat_hunter.get_recent_alerts", new_callable=AsyncMock, return_value=[]),
        patch("services.threat_hunter.recall_context", new_callable=AsyncMock, return_value=""),
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch("services.threat_hunter.enrich_iocs_from_context", new_callable=AsyncMock, return_value=no_ioc_pre_hunt),
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock, return_value=hallucinated_report),
        patch("services.behavioral_escape_hatch.has_local_ttp", return_value=True),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()

    assert result.threat_score == 0.0, f"TTP override bypassed hallucination firewall! score={result.threat_score}"
    assert result.dispatched is False
    mock_send.assert_not_called()


async def test_agent_error_not_scored_as_threat():
    """Agent error messages must NOT enter the scoring pipeline.

    Regression test for Critic Node 2026-07-10 finding: hunt id=108 had
    '🚨 Agent error: Connection Error' as summary but score=1.0 + dispatched=True.
    """
    import services.threat_hunter as mod

    with (
        patch("services.threat_hunter._RESOURCE_GUARD.check", return_value=(True, "")),
        patch("services.threat_hunter.is_llm_ready", return_value=True),
        patch.object(mod, "_LAST_HUNT_TS", 0.0),
        patch("services.threat_hunter.get_system_snapshot", new_callable=AsyncMock, return_value=_ttp_snapshot()),
        patch("services.threat_hunter.get_recent_alerts", new_callable=AsyncMock, return_value=[]),
        patch("services.threat_hunter.recall_context", new_callable=AsyncMock, return_value=""),
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch("services.threat_hunter.enrich_iocs_from_context", new_callable=AsyncMock, return_value=_EMPTY_PRE_HUNT),
        patch(
            "services.threat_hunter.run_agent",
            new_callable=AsyncMock,
            return_value="🚨 Agent error: Connection Error: Ensure KoboldCpp is running with a model loaded.",
        ),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock) as mock_send,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        result = await mod._run_hunt()

    assert result.threat_score == 0.0
    assert result.dispatched is False
    assert result.skipped == "agent error"
    mock_send.assert_not_called()
