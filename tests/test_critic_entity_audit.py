# tests/test_critic_entity_audit.py
"""Tests for Entity Verification — deterministic IOC hallucination detection.

Verifies:
- _audit_entity_claims catches hallucinated PIDs not in tool data
- Catches hallucinated file paths
- Catches hallucinated IP addresses
- Passes when all entities are grounded in tool data
- Ignores whitelisted IPs (127.0.0.1, 0.0.0.0)
- CoVe prompt contains ENTITY VERIFICATION block
- _run_critic_evaluation returns FAIL on hallucinated entities
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from services.agent._agent_critic import _COVE_SYSTEM, _run_critic_evaluation
from services.agent._agent_tool_audit import (
    _audit_entity_claims,
    extract_auditable_ips,
)


class TestKnownBenignIPs:
    """Entity audit provenance law (v2): baseline membership is NOT a bypass.

    An IP cited in the draft MUST appear in the current tool_data, regardless
    of whether it's in the runtime net baseline. Stale baseline memory ≠
    current evidence. The known_benign_ips parameter is deprecated (kept for
    API compat) and no longer exempts IPs from the provenance check.
    """

    def test_benign_baseline_ip_still_flagged_when_absent_from_tool_data(self):
        """IP absent from tool_data is flagged EVEN IF known-benign in baseline."""
        draft = "חיבור לכתובת 18.97.36.5 זוהה במערכת."
        tool_data = "scan complete: only 160.79.104.10 enriched (score 0)"
        # Without the baseline set it IS flagged...
        assert any("18.97.36.5" in r for r in _audit_entity_claims(draft, tool_data))
        # ...and WITH the baseline set it is STILL flagged (provenance law v2).
        result = _audit_entity_claims(draft, tool_data, known_benign_ips={"18.97.36.5"})
        assert any("18.97.36.5" in r for r in result)

    def test_benign_ip_grounded_in_tool_data_passes(self):
        """IP present in tool_data is NOT flagged, regardless of baseline status."""
        draft = "חיבור לכתובת 18.97.36.5 זוהה במערכת."
        tool_data = "scan complete: 18.97.36.5 enriched (score 0, clean)"
        result = _audit_entity_claims(draft, tool_data, known_benign_ips=set())
        assert result == []

    def test_unknown_ip_still_flagged_with_benign_set(self):
        """A DIFFERENT ungrounded IP is still flagged even when a benign set exists."""
        draft = "כתובות: 18.97.36.5 וגם 203.0.113.9 (זדונית)."
        tool_data = "nothing enriched here"
        result = _audit_entity_claims(draft, tool_data, known_benign_ips={"18.97.36.5"})
        assert any("203.0.113.9" in r for r in result)
        assert any("18.97.36.5" in r for r in result)  # v2: also flagged (absent from tool_data)

    def test_extract_auditable_ips_excludes_boilerplate(self):
        """extract_auditable_ips returns public IPs, skipping loopback/providers."""
        draft = "127.0.0.1 local; 8.8.8.8 dns; 18.97.36.5 remote."
        ips = extract_auditable_ips(draft)
        assert "18.97.36.5" in ips
        assert "127.0.0.1" not in ips  # whitelist
        assert "8.8.8.8" not in ips  # benign provider prefix


class TestAuditEntityClaims:
    """Unit tests for deterministic entity audit."""

    def test_hallucinated_pid_detected(self):
        """PID in draft but NOT in tool data → flagged."""
        draft = "נמצא תהליך חשוד powershell.exe (PID: 12847) עם קוד מוצפן."
        tool_data = "powershell.exe PID: 2868 | CLEAN\npowershell.exe PID: 9608 | CLEAN"
        result = _audit_entity_claims(draft, tool_data)
        assert any("12847" in r for r in result)

    def test_grounded_pid_passes(self):
        """PID in draft AND in tool data → not flagged."""
        draft = "תהליך powershell.exe (PID: 2868) נותח ונמצא תקין."
        tool_data = "powershell.exe PID: 2868 | CLEAN"
        result = _audit_entity_claims(draft, tool_data)
        assert result == []

    def test_hallucinated_filepath_detected(self):
        """File path in draft but NOT in tool data → flagged."""
        draft = "הקובץ C:\\Users\\user\\AppData\\Local\\Temp\\temp_script.ps1 זוהה כזדוני."
        tool_data = "No files found in Temp directory."
        result = _audit_entity_claims(draft, tool_data)
        assert any("temp_script.ps1" in r or "path" in r for r in result)

    def test_grounded_filepath_passes(self):
        """File path in draft AND in tool data → not flagged."""
        draft = "הקובץ C:\\Windows\\System32\\svchost.exe נותח."
        tool_data = "Found: C:\\Windows\\System32\\svchost.exe"
        result = _audit_entity_claims(draft, tool_data)
        assert result == []

    def test_hallucinated_ip_detected(self):
        """IP in draft but NOT in tool data → flagged."""
        draft = "חיבור חשוד ל-IP 185.220.101.34 (Tor exit node)."
        tool_data = "Active connections: 4.207.44.69 (Microsoft)"
        result = _audit_entity_claims(draft, tool_data)
        assert any("185.220.101.34" in r for r in result)

    def test_grounded_ip_passes(self):
        """IP in draft AND in tool data → not flagged."""
        draft = "חיבור ל-IP 4.207.44.69 (Microsoft Corporation) נותח."
        tool_data = "Active connections: 4.207.44.69 (Microsoft)"
        result = _audit_entity_claims(draft, tool_data)
        assert result == []

    def test_whitelisted_ip_ignored(self):
        """127.0.0.1 and 0.0.0.0 are not flagged even if not in tool data."""
        draft = "המערכת מאזינה על 127.0.0.1 ו-0.0.0.0."
        tool_data = "No connection data available."
        result = _audit_entity_claims(draft, tool_data)
        assert result == []

    def test_empty_draft_returns_empty(self):
        """Empty draft → no entities to check."""
        result = _audit_entity_claims("", "tool data here")
        assert result == []

    def test_empty_tool_data_returns_empty(self):
        """Empty tool data → no entities to check (avoid false positives)."""
        draft = "PID 12345 was found."
        result = _audit_entity_claims(draft, "")
        assert result == []

    def test_multiple_hallucinated_entities(self):
        """Multiple hallucinated entities all flagged."""
        draft = "תהליך PID: 99999 עם קובץ C:\\temp\\malware.exe מתחבר ל-IP 10.10.10.10."
        tool_data = "No matching processes found."
        result = _audit_entity_claims(draft, tool_data)
        assert len(result) >= 3  # PID + path + IP
        assert any("99999" in r for r in result)
        assert any("malware.exe" in r or "path" in r for r in result)
        assert any("10.10.10.10" in r for r in result)


class TestCovePromptEntityVerification:
    """Verify the CoVe system prompt contains entity verification rules."""

    def test_entity_verification_block_present(self):
        """Prompt must contain ENTITY VERIFICATION section."""
        assert "ENTITY VERIFICATION" in _COVE_SYSTEM

    def test_zero_tolerance_mentioned(self):
        """Prompt must mention ZERO TOLERANCE."""
        assert "ZERO TOLERANCE" in _COVE_SYSTEM

    def test_pid_example_in_prompt(self):
        """Prompt must include PID example (12847)."""
        assert "12847" in _COVE_SYSTEM

    def test_filepath_example_in_prompt(self):
        """Prompt must include file path example (temp_script.ps1)."""
        assert "temp_script.ps1" in _COVE_SYSTEM

    def test_fail_rule_for_entities(self):
        """Prompt must have FAIL rule for entity violations."""
        assert "FAIL if ANY entity in step 4" in _COVE_SYSTEM


class TestCriticEntityAuditIntegration:
    """Integration: _run_critic_evaluation returns FAIL on hallucinated entities."""

    @pytest.mark.asyncio
    async def test_hallucinated_pid_forces_fail(self):
        """Draft with hallucinated PID → deterministic FAIL before LLM."""
        draft = "תהליך חשוד powershell.exe (PID: 12847) עם קוד מוצפן."
        tool_data = "powershell.exe PID: 2868 | CLEAN"

        # Mock engine — should NOT be called (deterministic audit fires first)
        mock_engine = MagicMock()
        mock_engine.complete = AsyncMock()

        is_valid, feedback = await _run_critic_evaluation(
            original_query="scan system",
            tool_data=tool_data,
            draft_answer=draft,
            engine=mock_engine,
            tools_used=[{"name": "scan_suspicious_procs"}],
        )

        assert is_valid is False
        assert "12847" in feedback.get("logical_flaw", "") or "12847" in feedback.get("reason", "")
        # LLM critic should NOT have been called (deterministic audit caught it)
        mock_engine.complete.assert_not_called()

    @pytest.mark.asyncio
    async def test_grounded_draft_proceeds_to_llm(self):
        """Draft with grounded entities → proceeds to LLM critic."""
        draft = "תהליך powershell.exe (PID: 2868) נותח ונמצא תקין."
        tool_data = "powershell.exe PID: 2868 | CLEAN"

        mock_engine = MagicMock()
        mock_engine.complete = AsyncMock(
            return_value="VERDICT: PASS\nCLAIMS:\n- test\nEVIDENCE:\n- test: ok\nLOGICAL_FLAW: NONE\nREASON: ok"
        )

        is_valid, _ = await _run_critic_evaluation(
            original_query="scan system",
            tool_data=tool_data,
            draft_answer=draft,
            engine=mock_engine,
            tools_used=[{"name": "scan_suspicious_procs"}],
        )

        # LLM critic WAS called (no deterministic block)
        mock_engine.complete.assert_awaited_once()


class TestEntityAuditEdgeCases:
    """Edge cases for _audit_entity_claims — malformed patterns, boundary conditions."""

    def test_short_pid_ignored(self):
        """PID with < 3 digits should NOT be extracted (below regex minimum)."""
        # 2-digit "PID" — regex requires 3-8 digits
        draft = "Process PID: 42 running"
        tool_data = "no pids here"
        flags = _audit_entity_claims(draft, tool_data)
        # 42 is only 2 digits, below the 3-digit minimum — should not be flagged
        assert all("PID" not in f for f in flags)

    def test_pid_with_braces(self):
        """PID with optional closing brace before digits should be extracted."""
        # Regex: \bPID[:\s]*}?(\d{3,8})\b — } is optional, must be adjacent to digits
        draft = "Process PID:}12345 running"
        tool_data = "no match"
        flags = _audit_entity_claims(draft, tool_data)
        assert any("12345" in f for f in flags)

    def test_all_whitelisted_ips_ignored(self):
        """All IPs in _IP_WHITELIST should be ignored even if not in tool_data."""
        draft = "Connections from 127.0.0.1, 0.0.0.0, 255.255.255.255, 1.0.0.0"
        tool_data = "no ips here"
        flags = _audit_entity_claims(draft, tool_data)
        assert flags == []

    def test_unix_filepath_detected(self):
        """Unix-style file paths with security extensions should be detected."""
        draft = "Malicious script at /tmp/evil.sh detected"
        tool_data = "no files here"
        flags = _audit_entity_claims(draft, tool_data)
        assert any("evil.sh" in f for f in flags)

    def test_mixed_grounded_and_hallucinated(self):
        """Mix of grounded and hallucinated entities — only hallucinated flagged."""
        draft = "PID: 1111 is clean, but PID: 9999 is suspicious. IP 10.0.0.1 connected."
        tool_data = "PID: 1111 | clean\nIP 10.0.0.1 | connected"
        flags = _audit_entity_claims(draft, tool_data)
        # 1111 and 10.0.0.1 are grounded — should NOT be flagged
        # 9999 is hallucinated — SHOULD be flagged
        assert any("9999" in f for f in flags)
        assert not any("1111" in f for f in flags)
        assert not any("10.0.0.1" in f for f in flags)

    def test_filepath_filename_match_passes(self):
        """File path where only the filename (not full path) is in tool_data should pass."""
        draft = "Found C:\\Users\\test\\malware.exe"
        tool_data = "Scanned malware.exe — clean"
        flags = _audit_entity_claims(draft, tool_data)
        # filename "malware.exe" IS in tool_data → should NOT be flagged
        assert not any("malware.exe" in f for f in flags)
