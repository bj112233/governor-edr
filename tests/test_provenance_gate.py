# tests/test_provenance_gate.py
"""Data Provenance & Taint Tracking — entity-source verification gate tests.

Verifies the attack scenario: an attacker embeds "PID 12345" or "IP 1.2.3.4"
in an RSS feed or OSINT result. Without provenance tracking, the entity
passes the Entity Verification audit (it exists in tool_data) and can drive
execution actions (kill_process, block_ip).

With the Provenance Gate:
  - Entities from trusted system tools → allowed
  - Entities from tainted external tools only → BLOCKED
  - Cross-verification (entity appears in both tainted + trusted) → allowed
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.agent._provenance import (
    EXECUTION_ACTIONS,
    TAINTED_EXTERNAL_TOOLS,
    TRUSTED_SYSTEM_TOOLS,
    ProvenanceRegistry,
    _is_tainted_tool,
    _normalize_tool_name,
    get_registry,
    verify_execution_gate,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Reset the global registry before each test — prevent state leakage."""
    get_registry().clear()
    yield
    get_registry().clear()


# ── Trust classification ──────────────────────────────────────────


class TestTrustClassification:
    def test_trusted_tools_include_system_sensors(self):
        assert "get_process_list" in TRUSTED_SYSTEM_TOOLS
        assert "get_external_connections" in TRUSTED_SYSTEM_TOOLS
        assert "get_system_snapshot" in TRUSTED_SYSTEM_TOOLS

    def test_tainted_tools_include_external_sources(self):
        assert "skill_news_monitor" in TAINTED_EXTERNAL_TOOLS
        assert "web_search" in TAINTED_EXTERNAL_TOOLS
        assert "osint_hunt" in TAINTED_EXTERNAL_TOOLS
        assert "skill_intel" in TAINTED_EXTERNAL_TOOLS

    def test_no_overlap_between_trusted_and_tainted(self):
        assert TRUSTED_SYSTEM_TOOLS.isdisjoint(TAINTED_EXTERNAL_TOOLS)

    def test_execution_actions_cover_state_mutating_tools(self):
        assert "terminate_process" in EXECUTION_ACTIONS
        assert "block_ip" in EXECUTION_ACTIONS
        assert "unblock_ip" in EXECUTION_ACTIONS
        assert "manage_service" in EXECUTION_ACTIONS


# ── Skill name normalization (C3 fix) ─────────────────────────────


class TestSkillNameNormalization:
    """Skill tools generate names like 'skill_intel-skill' but the
    tainted list uses 'skill_intel'. Normalization must bridge this gap."""

    def test_normalize_strips_skill_prefix_and_suffix(self):
        assert _normalize_tool_name("skill_intel-skill") == "intel"
        assert _normalize_tool_name("skill_file-analyst") == "file_analyst"
        assert _normalize_tool_name("skill_pcap-analyst") == "pcap_analyst"
        assert _normalize_tool_name("skill_email-forensics") == "email_forensics"
        assert _normalize_tool_name("skill_news-monitor") == "news_monitor"

    def test_normalize_preserves_non_skill_tools(self):
        assert _normalize_tool_name("web_search") == "web_search"
        assert _normalize_tool_name("osint_hunt") == "osint_hunt"
        assert _normalize_tool_name("get_process_list") == "get_process_list"

    def test_tainted_skill_with_hyphen_suffix_detected(self):
        """skill_intel-skill must be classified as tainted."""
        assert _is_tainted_tool("skill_intel-skill") is True

    def test_tainted_skill_with_hyphen_name_detected(self):
        """skill_file-analyst must be classified as tainted."""
        assert _is_tainted_tool("skill_file-analyst") is True

    def test_tainted_skill_exact_match_still_works(self):
        """skill_intel (exact match from list) must still work."""
        assert _is_tainted_tool("skill_intel") is True

    def test_non_tainted_skill_not_matched(self):
        """A skill NOT in the tainted list must not be classified as tainted."""
        assert _is_tainted_tool("skill_crypto-skill") is False
        assert _is_tainted_tool("skill_firewall-skill") is False

    def test_registry_registers_skill_with_hyphen_suffix(self):
        """Entities from skill_intel-skill must be registered as tainted."""
        reg = ProvenanceRegistry()
        reg.register("skill_intel-skill", "C2 at 5.5.5.5")
        assert reg.is_tainted_only("IP:5.5.5.5")

    def test_registry_blocks_tainted_skill_entity_at_gate(self):
        """skill_file-analyst entity must be blocked at execution gate."""
        reg = get_registry()
        reg.register("skill_file-analyst", "Malware at 6.6.6.6")
        allowed, reason = verify_execution_gate("IP:6.6.6.6", "block_ip")
        assert not allowed
        assert "Provenance Gate" in reason


# ── Registry: registration + provenance tracking ──────────────────


class TestProvenanceRegistry:
    def test_register_trusted_tool_entities(self):
        reg = ProvenanceRegistry()
        reg.register("get_process_list", "PID: 1234 svchost.exe\nPID: 5678 explorer.exe")
        assert reg.is_trusted("PID:1234")
        assert reg.is_trusted("PID:5678")
        assert not reg.is_tainted_only("PID:1234")

    def test_register_tainted_tool_entities(self):
        reg = ProvenanceRegistry()
        reg.register("skill_news_monitor", "Breaking: C2 server at 1.2.3.4 detected")
        assert reg.is_tainted_only("IP:1.2.3.4")
        assert not reg.is_trusted("IP:1.2.3.4")

    def test_cross_verification_unlocks_tainted(self):
        """Entity from tainted source + 2 trusted sources → NOT tainted-only.

        M3 fix: A single trusted source is insufficient to launder a
        tainted entity. Requires 2 independent trusted sources (Byzantine
        tolerance). This prevents a compromised trusted tool from
        verifying malicious entities.
        """
        reg = ProvenanceRegistry()
        reg.register("skill_news_monitor", "C2 at 1.2.3.4")
        assert reg.is_tainted_only("IP:1.2.3.4")
        # 1 trusted source — NOT enough (M3 fix)
        reg.register("get_external_connections", "1.2.3.4  ESTABLISHED  PID 9999")
        assert reg.is_tainted_only("IP:1.2.3.4")  # still tainted
        # 2nd trusted source — now cross-verified
        reg.register("get_process_list", "1.2.3.4 found in PID 9999")
        assert not reg.is_tainted_only("IP:1.2.3.4")
        assert reg.is_trusted("IP:1.2.3.4")

    def test_single_trusted_not_enough_with_tainted(self):
        """M3: 1 trusted + 1 tainted → still tainted (Byzantine tolerance)."""
        reg = ProvenanceRegistry()
        reg.register("skill_intel", "Malware at 8.8.8.8")
        reg.register("get_external_connections", "8.8.8.8 ESTABLISHED")
        assert reg.is_tainted_only("IP:8.8.8.8")

    def test_two_trusted_unlocks_tainted(self):
        """M3: 2 trusted + 1 tainted → cross-verified."""
        reg = ProvenanceRegistry()
        reg.register("skill_intel", "Malware at 9.9.9.9")
        reg.register("get_external_connections", "9.9.9.9 ESTABLISHED")
        reg.register("get_process_list", "9.9.9.9 in PID 1234")
        assert not reg.is_tainted_only("IP:9.9.9.9")

    def test_only_trusted_no_taint(self):
        """M3: Only trusted sources (no taint) → not tainted-only."""
        reg = ProvenanceRegistry()
        reg.register("get_external_connections", "1.2.3.4 ESTABLISHED")
        assert not reg.is_tainted_only("IP:1.2.3.4")

    def test_unknown_entity_not_tainted(self):
        reg = ProvenanceRegistry()
        assert not reg.is_tainted_only("IP:9.9.9.9")
        assert not reg.is_trusted("IP:9.9.9.9")

    def test_whitelist_ips_not_registered(self):
        reg = ProvenanceRegistry()
        reg.register("get_external_connections", "127.0.0.1 LISTENING")
        assert "IP:127.0.0.1" not in reg._entity_sources

    def test_unclassified_tool_registered_as_tainted(self):
        """H6 fix: Unclassified tools DO register — entities treated as tainted (fail-closed)."""
        reg = ProvenanceRegistry()
        reg.register("read_file", "PID 12345 was found")
        assert "PID:12345" in reg._entity_sources
        # Unclassified source → tainted_only returns True (fail-closed)
        assert reg.is_tainted_only("PID:12345")
        assert not reg.is_trusted("PID:12345")

    def test_unclassified_tool_cross_verified_by_trusted(self):
        """H6+M3: Unclassified entity + 2 trusted sources → not tainted-only."""
        reg = ProvenanceRegistry()
        reg.register("read_file", "PID 12345 was found")
        assert reg.is_tainted_only("PID:12345")
        # M3: 1 trusted not enough with untrusted source present
        reg.register("get_process_list", "PID: 12345 svchost.exe")
        assert reg.is_tainted_only("PID:12345")  # still tainted (M3)
        # 2nd trusted source — now cross-verified
        reg.register("get_external_connections", "PID 12345 connected to 1.2.3.4")
        assert not reg.is_tainted_only("PID:12345")
        assert reg.is_trusted("PID:12345")

    def test_clear_resets_registry(self):
        reg = ProvenanceRegistry()
        reg.register("get_process_list", "PID: 1234")
        reg.clear()
        assert not reg.is_trusted("PID:1234")
        assert reg._entity_sources == {}

    def test_get_sources_returns_all(self):
        reg = ProvenanceRegistry()
        reg.register("skill_news_monitor", "1.2.3.4")
        reg.register("get_external_connections", "1.2.3.4")
        sources = reg.get_sources("IP:1.2.3.4")
        assert "skill_news_monitor" in sources
        assert "get_external_connections" in sources


# ── Execution Gate ────────────────────────────────────────────────


class TestVerifyExecutionGate:
    def test_trusted_entity_allowed(self):
        reg = get_registry()
        reg.register("get_external_connections", "1.2.3.4 ESTABLISHED")
        allowed, reason = verify_execution_gate("IP:1.2.3.4", "block_ip")
        assert allowed
        assert reason == ""

    def test_tainted_only_entity_blocked(self):
        reg = get_registry()
        reg.register("skill_news_monitor", "C2 at 1.2.3.4")
        allowed, reason = verify_execution_gate("IP:1.2.3.4", "block_ip")
        assert not allowed
        assert "Provenance Gate" in reason
        assert "skill_news_monitor" in reason
        assert "cross-verify" in reason.lower()

    def test_cross_verified_entity_allowed(self):
        """M3: 2 trusted sources needed to cross-verify a tainted entity."""
        reg = get_registry()
        reg.register("skill_news_monitor", "1.2.3.4")
        reg.register("get_external_connections", "1.2.3.4")
        reg.register("get_process_list", "1.2.3.4 in PID 9999")
        allowed, reason = verify_execution_gate("IP:1.2.3.4", "block_ip")
        assert allowed

    def test_single_trusted_with_taint_blocked(self):
        """M3: 1 trusted + 1 tainted → blocked at execution gate."""
        reg = get_registry()
        reg.register("skill_news_monitor", "7.7.7.7")
        reg.register("get_external_connections", "7.7.7.7")
        allowed, reason = verify_execution_gate("IP:7.7.7.7", "block_ip")
        assert not allowed
        assert "Provenance Gate" in reason

    def test_unknown_entity_allowed(self):
        """No provenance record → allowed (HITL still gates; no evidence of taint)."""
        allowed, reason = verify_execution_gate("IP:5.5.5.5", "block_ip")
        assert allowed

    def test_empty_entity_allowed(self):
        allowed, reason = verify_execution_gate("", "block_ip")
        assert allowed

    def test_non_execution_action_always_allowed(self):
        reg = get_registry()
        reg.register("skill_news_monitor", "1.2.3.4")
        allowed, reason = verify_execution_gate("IP:1.2.3.4", "get_system_snapshot")
        assert allowed

    def test_tainted_pid_blocked_for_terminate(self):
        reg = get_registry()
        reg.register("skill_intel", "Malware PID 12345 reported by OSINT feed")
        allowed, reason = verify_execution_gate("PID:12345", "terminate_process")
        assert not allowed
        assert "PID:12345" in reason
        assert "skill_intel" in reason


# ── Handler integration: gate blocks tainted-only entities ────────


class TestHandlerIntegration:
    def test_block_ip_handler_blocks_tainted_ip(self):
        from services.tools.security_tools import _block_ip_handler

        get_registry().register("skill_news_monitor", "C2 at 10.20.30.40")
        result = asyncio.run(_block_ip_handler(ip="10.20.30.40"))
        assert "BLOCKED" in result
        assert "Provenance Gate" in result
        assert "10.20.30.40" in result

    def test_block_ip_handler_allows_trusted_ip(self):
        from services.tools.security_tools import _block_ip_handler

        get_registry().register("get_external_connections", "10.20.30.40 ESTABLISHED")
        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock):
            result = asyncio.run(_block_ip_handler(ip="10.20.30.40"))
        assert "PENDING_APPROVAL" in result

    def test_block_ip_handler_allows_unknown_ip(self):
        from services.tools.security_tools import _block_ip_handler

        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock):
            result = asyncio.run(_block_ip_handler(ip="8.8.8.8"))
        assert "PENDING_APPROVAL" in result

    def test_terminate_process_handler_blocks_tainted_pid(self):
        from services.tools.system_tools import _terminate_process_handler

        get_registry().register("osint_hunt", "Threat actor uses PID 99999")
        result = asyncio.run(_terminate_process_handler(pid=99999))
        assert "BLOCKED" in result
        assert "PID:99999" in result

    def test_terminate_process_handler_allows_trusted_pid(self):
        from services.tools.system_tools import _terminate_process_handler

        get_registry().register("get_process_list", "PID: 4444 malware.exe")
        with patch("services.tools.system_tools.set_pending", new_callable=AsyncMock):
            result = asyncio.run(_terminate_process_handler(pid=4444))
        assert "PENDING_APPROVAL" in result

    def test_cross_verify_then_block_succeeds(self):
        """Full attack scenario: tainted IP → blocked → cross-verify (2 trusted) → allowed.

        M3 fix: requires 2 independent trusted sources to launder a tainted entity.
        """
        from services.tools.security_tools import _block_ip_handler

        reg = get_registry()
        # Step 1: RSS feed reports malicious IP
        reg.register("skill_news_monitor", "C2 server 203.0.113.5 active")
        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock) as mock_pending:
            result1 = asyncio.run(_block_ip_handler(ip="203.0.113.5"))
        assert "BLOCKED" in result1
        mock_pending.assert_not_called()

        # Step 2: Agent cross-verifies with 1st trusted tool — NOT enough (M3)
        reg.register("get_external_connections", "203.0.113.5 ESTABLISHED PID 7777")
        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock) as mock_pending:
            result1b = asyncio.run(_block_ip_handler(ip="203.0.113.5"))
        assert "BLOCKED" in result1b  # still blocked — need 2nd trusted

        # Step 3: 2nd trusted source — now cross-verified
        reg.register("get_process_list", "203.0.113.5 found in PID 7777")

        # Step 4: Retry block — now allowed
        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock) as mock_pending:
            result2 = asyncio.run(_block_ip_handler(ip="203.0.113.5"))
        assert "PENDING_APPROVAL" in result2
        mock_pending.assert_called_once()

    def test_unblock_ip_handler_blocks_tainted_ip(self):
        from services.tools.security_tools import _unblock_ip_handler

        get_registry().register("skill_news_monitor", "C2 at 10.20.30.40")
        result = asyncio.run(_unblock_ip_handler(ip="10.20.30.40"))
        assert "BLOCKED" in result
        assert "Provenance Gate" in result

    def test_unblock_ip_handler_allows_trusted_ip(self):
        from services.tools.security_tools import _unblock_ip_handler

        get_registry().register("get_external_connections", "10.20.30.40 ESTABLISHED")
        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock):
            result = asyncio.run(_unblock_ip_handler(ip="10.20.30.40"))
        assert "PENDING_APPROVAL" in result

    def test_unblock_ip_handler_allows_unknown_ip(self):
        from services.tools.security_tools import _unblock_ip_handler

        with patch("services.tools.security_tools.set_pending", new_callable=AsyncMock):
            result = asyncio.run(_unblock_ip_handler(ip="8.8.8.8"))
        assert "PENDING_APPROVAL" in result
