# tests/test_threat_hunter_eicar.py
"""EICAR-style test: inject malicious IP into snapshot, verify hunter
investigates (no bypass), extracts score, and dispatches.

Tests three critical fixes:
1. allow_bypasses=False prevents sysreport fast-path
2. _extract_threat_score fail-closed (0.1) on parse failure
3. Score > threshold triggers dispatch
"""

from unittest.mock import AsyncMock, patch

import pytest

from services.pre_hunt_enricher import PreHuntReport
from services.threat_hunter import (
    HuntResult,
    _build_hunt_prompt,
    _extract_threat_score,
    _run_hunt,
)


def _malicious_pre_hunt() -> PreHuntReport:
    """Pre-hunt report with a confirmed malicious IP (AbuseIPDB=85)."""
    rpt = PreHuntReport()
    rpt.enriched["185.220.101.45"] = {
        "score": 85,
        "abuse": {"country": "RU", "isp": "Evict"},
        "virustotal": {"malicious": 3, "available": True, "found": True},
    }
    return rpt


def test_extract_threat_score_valid():
    """Valid THREAT_SCORE line parses correctly."""
    assert _extract_threat_score("analysis...\nTHREAT_SCORE: 0.8") == 0.8


def test_extract_threat_score_zero():
    """Score of 0.0 is valid (clean system)."""
    assert _extract_threat_score("all clear\nTHREAT_SCORE: 0.0") == 0.0


def test_extract_threat_score_missing_fail_closed():
    """Missing THREAT_SCORE returns 0.1 (analysis failure), NOT 0.0 (clean).

    This is the fail-closed fix — prevents false negatives when the LLM
    forgets the score line.
    """
    score = _extract_threat_score("some analysis without a score line")
    assert score == 0.1, f"Expected 0.1 (fail-closed), got {score}"


def test_extract_threat_score_garbled_fail_closed():
    """Unparseable THREAT_SCORE returns 0.1, not 0.0."""
    score = _extract_threat_score("THREAT_SCORE: abc")
    assert score == 0.1


def test_extract_threat_score_clamped():
    """Score > 1.0 clamped to 1.0."""
    assert _extract_threat_score("THREAT_SCORE: 5.0") == 1.0


def test_extract_threat_score_negative_fail_closed():
    """Negative score is unparseable (regex expects [0-9]) → 0.1 fail-closed."""
    assert _extract_threat_score("THREAT_SCORE: -0.5") == 0.1


def test_build_prompt_includes_investigation_directive():
    """Prompt must instruct agent to use tools, not just summarize."""
    snapshot = {"cpu": 5.0, "mem": 30.0, "disk_alerts": [], "suspicious_net": []}
    prompt = _build_hunt_prompt(snapshot, [], "")
    assert "חובה להפעיל כלים" in prompt or "אסור לדלג" in prompt
    assert "THREAT_SCORE" in prompt


def test_build_prompt_includes_suspicious_net():
    """Prompt must include suspicious network connections."""
    snapshot = {
        "cpu": 80.0,
        "mem": 90.0,
        "disk_alerts": [],
        "suspicious_net": ["185.220.101.45:443", "45.129.11.20:8080"],
    }
    prompt = _build_hunt_prompt(snapshot, [], "")
    assert "185.220.101.45" in prompt
    assert "45.129.11.20" in prompt


@pytest.mark.asyncio
async def test_eicar_malicious_ip_triggers_dispatch():
    """EICAR test: inject known-malicious IP, verify dispatch fires.

    Mocks the agent to return a high threat score (simulating the agent
    finding the malicious IP via intel-skill). Verifies:
    - send_threat_hunt_event is called (dispatch)
    - store_threat_hunt is called with dispatched=True
    - score > threshold (0.6)
    """
    malicious_snapshot = {
        "cpu": 85.0,
        "mem": 92.0,
        "disk_alerts": [],
        "suspicious_net": ["185.220.101.45:443"],
    }
    fake_alerts = [("2026-06-22 10:00", "suspicious outbound to 185.220.101.45", "report")]
    fake_memory = ""

    with (
        patch("services.threat_hunter._preflight", return_value=None),
        patch("services.threat_hunter._HUNT_MUTEX.locked", return_value=False),
        patch("services.threat_hunter._gather_context", new_callable=AsyncMock) as mock_ctx,
        patch(
            "services.threat_hunter.enrich_iocs_from_context",
            new_callable=AsyncMock,
            return_value=_malicious_pre_hunt(),
        ),
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock) as mock_agent,
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock) as mock_dispatch,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock) as mock_store,
    ):
        mock_ctx.return_value = (malicious_snapshot, fake_alerts, fake_memory)
        mock_agent.return_value = (
            "Threat analysis: 185.220.101.45 is a known Tor exit node "
            "associated with botnet C2. High risk.\nTHREAT_SCORE: 0.85"
        )

        result = await _run_hunt()

    assert result.skipped is None, f"Hunt was skipped: {result.skipped}"
    # Scoring v2.0: LLM 0.85 → cap to 0.5 (no external evidence) → +0.3 (malicious IOC) = 0.8
    assert result.threat_score == 0.8
    assert result.dispatched is True, f"Score {result.threat_score} should have dispatched"
    mock_dispatch.assert_called_once()
    mock_store.assert_called_once()
    # Verify stored with dispatched=True. Signature: store_threat_hunt(prompt_hash, score, summary, dispatched)
    store_args = mock_store.call_args
    assert store_args[0][3] is True or store_args.kwargs.get("dispatched") is True


@pytest.mark.asyncio
async def test_bypass_disabled_for_hunt():
    """Verify run_agent is called with allow_bypasses=False."""
    with (
        patch("services.threat_hunter._preflight", return_value=None),
        patch("services.threat_hunter._HUNT_MUTEX.locked", return_value=False),
        patch("services.threat_hunter._gather_context", new_callable=AsyncMock) as mock_ctx,
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock) as mock_agent,
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock),
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock),
    ):
        mock_ctx.return_value = ({"cpu": 5.0, "mem": 30.0, "disk_alerts": [], "suspicious_net": []}, [], "")
        mock_agent.return_value = "System clean.\nTHREAT_SCORE: 0.0"

        await _run_hunt()

    mock_agent.assert_called_once()
    call_kwargs = mock_agent.call_args.kwargs
    assert call_kwargs.get("allow_bypasses") is False, "Threat hunt MUST call run_agent with allow_bypasses=False"


@pytest.mark.asyncio
async def test_parse_failure_does_not_dispatch_but_flags():
    """When agent output has no THREAT_SCORE, score=0.1 (not 0.0).

    0.1 < 0.6 threshold → no dispatch, but DB records 0.1 (analysis failure)
    instead of 0.0 (clean), making the failure visible.
    """
    with (
        patch("services.threat_hunter._preflight", return_value=None),
        patch("services.threat_hunter._HUNT_MUTEX.locked", return_value=False),
        patch("services.threat_hunter._gather_context", new_callable=AsyncMock) as mock_ctx,
        patch("services.threat_hunter.run_agent", new_callable=AsyncMock) as mock_agent,
        patch("services.threat_hunter.get_last_hunt", new_callable=AsyncMock, return_value=None),
        patch("services.threat_hunter.send_threat_hunt_event", new_callable=AsyncMock) as mock_dispatch,
        patch("services.threat_hunter.store_threat_hunt", new_callable=AsyncMock) as mock_store,
    ):
        mock_ctx.return_value = ({"cpu": 5.0, "mem": 30.0, "disk_alerts": [], "suspicious_net": []}, [], "")
        mock_agent.return_value = "I forgot to include the score line."

        result = await _run_hunt()

    assert result.threat_score == 0.1
    assert result.dispatched is False
    mock_dispatch.assert_not_called()
    # Verify 0.1 was stored (not 0.0). Signature: store_threat_hunt(prompt_hash, score, summary, dispatched)
    store_args = mock_store.call_args
    stored_score = store_args[0][1] if len(store_args[0]) > 1 else store_args.kwargs.get("score")
    assert stored_score == 0.1, f"DB should store 0.1 (analysis failure), got {stored_score}"
