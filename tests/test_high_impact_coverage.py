"""High-impact coverage tests for non-security modules.

Targets modules with the most missing lines:
  - services/tools/mcp_handlers.py
  - services/intel_enricher.py
  - services/credential_monitor.py
  - services/monitor_engine_helpers.py
  - services/reference_store.py
  - services/night_watchman.py
"""

import asyncio
import json
import re
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_IPV4_RE_PATCH = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# ──────────────────────────────────────────────────────────────────
# mcp_handlers.py
# ──────────────────────────────────────────────────────────────────


class TestApprovePendingActionTool:
    """approve_pending_action_tool — execute pending action after approval."""

    async def test_no_pending_action(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=None):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "אין פעולה" in result

    async def test_block_ip_action(self):
        from services.tools import mcp_handlers

        action = {"action": "block_ip", "target": "1.2.3.4", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools.block_ip", new_callable=AsyncMock, return_value="blocked"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result
        assert "block_ip" in result

    async def test_unblock_ip_action(self):
        from services.tools import mcp_handlers

        action = {"action": "unblock_ip", "target": "1.2.3.4", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools.unblock_ip", new_callable=AsyncMock, return_value="unblocked"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_manage_service_action(self):
        from services.tools import mcp_handlers

        action = {
            "action": "manage_service",
            "target": {"action": "stop", "name": "Spooler"},
            "reason": "test",
        }
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools.manage_service", new_callable=AsyncMock, return_value="stopped"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_defender_scan_action(self):
        from services.tools import mcp_handlers

        action = {"action": "defender_scan", "target": "", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools.defender_scan", new_callable=AsyncMock, return_value="scanned"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_terminate_process_action(self):
        from services.tools import mcp_handlers

        action = {"action": "terminate_process", "target": "1234", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.system_intel.terminate_process", return_value="terminated"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_kill_process_action(self):
        from services.tools import mcp_handlers

        action = {"action": "kill_process", "target": "malware.exe", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch.object(mcp_handlers, "kill_process_by_name", new_callable=AsyncMock, return_value="killed"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_run_powershell_action(self):
        from services.tools import mcp_handlers

        action = {"action": "run_powershell", "target": "Get-Process", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools._run_powershell_exec", new_callable=AsyncMock, return_value="ok"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_screenshot_action(self):
        from services.tools import mcp_handlers

        action = {"action": "screenshot", "target": "", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools._local_screenshot_exec", return_value=b"screenshot"),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "✅" in result

    async def test_unknown_action_type(self):
        from services.tools import mcp_handlers

        action = {"action": "unknown_type", "target": "x", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "❌" in result
        assert "unknown_type" in result

    async def test_action_exception(self):
        from services.tools import mcp_handlers

        action = {"action": "block_ip", "target": "1.2.3.4", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
            patch("services.action_tools.block_ip", new_callable=AsyncMock, side_effect=RuntimeError("boom")),
        ):
            result = await mcp_handlers.approve_pending_action_tool()
        assert "❌" in result
        assert "boom" in result


class TestDenyPendingActionTool:
    async def test_no_pending(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=None):
            result = await mcp_handlers.deny_pending_action_tool()
        assert "אין פעולה" in result

    async def test_deny_action(self):
        from services.tools import mcp_handlers

        action = {"action": "block_ip", "target": "1.2.3.4", "reason": "test"}
        with (
            patch.object(mcp_handlers, "get_pending", new_callable=AsyncMock, return_value=action),
            patch.object(mcp_handlers, "clear_pending", new_callable=AsyncMock),
        ):
            result = await mcp_handlers.deny_pending_action_tool()
        assert "🚫" in result
        assert "block_ip" in result


class TestSentinelGetSystemSnapshotFull:
    async def test_snapshot_success(self):
        from services.tools import mcp_handlers

        snapshot = {
            "cpu": 50,
            "mem": 60,
            "gpu": {"name": "RTX 4090", "status": "OK"},
            "disk_alerts": [],
            "suspicious_net": [],
            "top_procs": [{"name": "chrome.exe", "cpu_percent": 30, "pid": 100}],
            "alert_needed": False,
        }
        with patch.object(mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, return_value=snapshot):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "תמונת מערכת" in result
        assert "CPU" in result

    async def test_snapshot_high_cpu(self):
        from services.tools import mcp_handlers

        snapshot = {
            "cpu": 90,
            "mem": 90,
            "gpu": {},
            "disk_alerts": [],
            "suspicious_net": [],
            "top_procs": [],
            "alert_needed": True,
        }
        with patch.object(mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, return_value=snapshot):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "🔴" in result
        assert "התראה פעילה" in result

    async def test_snapshot_gpu_error(self):
        from services.tools import mcp_handlers

        snapshot = {
            "cpu": 10,
            "mem": 20,
            "gpu": {"error": "GPU not found"},
            "disk_alerts": [],
            "suspicious_net": [],
            "top_procs": [],
            "alert_needed": False,
        }
        with patch.object(mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, return_value=snapshot):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "GPU" in result

    async def test_snapshot_disk_alerts(self):
        from services.tools import mcp_handlers

        snapshot = {
            "cpu": 10,
            "mem": 20,
            "gpu": {},
            "disk_alerts": ["C: 95%"],
            "suspicious_net": [],
            "top_procs": [],
            "alert_needed": False,
        }
        with patch.object(mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, return_value=snapshot):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "התראות דיסק" in result
        assert "C:" in result

    async def test_snapshot_suspicious_connections(self):
        """v2: snapshot hides suspicious connections — agent must call get_external_connections."""
        from services.tools import mcp_handlers

        snapshot = {
            "cpu": 10,
            "mem": 20,
            "gpu": {},
            "disk_alerts": [],
            "suspicious_net": ["1.2.3.4:443"],
            "top_procs": [],
            "alert_needed": False,
        }
        with patch.object(mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, return_value=snapshot):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "חיבורים חשודים" not in result and "1.2.3.4" not in result
        assert "get_external_connections" in result

    async def test_snapshot_exception(self):
        from services.tools import mcp_handlers

        with patch.object(
            mcp_handlers, "get_system_snapshot", new_callable=AsyncMock, side_effect=RuntimeError("fail")
        ):
            result = await mcp_handlers.sentinel_get_system_snapshot_full()
        assert "❌" in result


class TestSentinelGetPendingEvents:
    async def test_no_events(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=[]):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "אין אירועים" in result

    async def test_alert_event(self):
        from services.tools import mcp_handlers

        events = [
            {"timestamp": "2024-01-01", "event_type": "alert", "priority": "high", "data": {"analysis": "test alert"}}
        ]
        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=events):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "alert" in result
        assert "test alert" in result

    async def test_daily_digest_event(self):
        from services.tools import mcp_handlers

        events = [
            {
                "timestamp": "2024-01-01",
                "event_type": "daily_digest",
                "priority": "low",
                "data": {"ai_analysis": "digest text"},
            }
        ]
        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=events):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "daily_digest" in result
        assert "digest text" in result

    async def test_critical_override_event(self):
        from services.tools import mcp_handlers

        events = [
            {
                "timestamp": "2024-01-01",
                "event_type": "critical_override",
                "priority": "critical",
                "data": {"message": "override msg"},
            }
        ]
        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=events):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "critical_override" in result
        assert "override msg" in result

    async def test_unknown_event_type(self):
        from services.tools import mcp_handlers

        events = [{"timestamp": "2024-01-01", "event_type": "custom", "priority": "low", "data": {}}]
        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=events):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "custom" in result

    async def test_long_description_truncated(self):
        from services.tools import mcp_handlers

        long_desc = "x" * 300
        events = [
            {"timestamp": "2024-01-01", "event_type": "alert", "priority": "high", "data": {"analysis": long_desc}}
        ]
        with patch.object(mcp_handlers.event_bus, "get_pending_events", return_value=events):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "..." in result

    async def test_exception(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers.event_bus, "get_pending_events", side_effect=RuntimeError("fail")):
            result = await mcp_handlers.sentinel_get_pending_events()
        assert "❌" in result


class TestSentinelClearEventQueue:
    async def test_clear_success(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers.event_bus, "clear_queue", return_value=5):
            result = await mcp_handlers.sentinel_clear_event_queue()
        assert "5" in result

    async def test_clear_exception(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers.event_bus, "clear_queue", side_effect=RuntimeError("fail")):
            result = await mcp_handlers.sentinel_clear_event_queue()
        assert "❌" in result


class TestTelegramListPairings:
    async def test_no_channel(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers, "get_message_gateway", return_value=None):
            result = await mcp_handlers.telegram_list_pairings()
        assert "not available" in result

    async def test_no_pending_pairings(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.list_pending_pairings = AsyncMock(return_value=[])
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_list_pairings()
        assert "אין בקשות" in result

    async def test_with_pending_pairings(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.list_pending_pairings = AsyncMock(
            return_value=[{"code": "ABC123", "user_name": "user1", "user_id": "123", "created_at": "2024-01-01"}]
        )
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_list_pairings()
        assert "ABC123" in result
        assert "user1" in result

    async def test_exception(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.list_pending_pairings = AsyncMock(side_effect=RuntimeError("fail"))
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_list_pairings()
        assert "❌" in result


class TestTelegramApprovePairing:
    async def test_no_channel(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers, "get_message_gateway", return_value=None):
            result = await mcp_handlers.telegram_approve_pairing("CODE")
        assert "not available" in result

    async def test_approve_success(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.approve_pairing = AsyncMock(return_value={"user_name": "user1", "user_id": "123"})
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_approve_pairing("CODE")
        assert "✅" in result
        assert "user1" in result

    async def test_approve_not_found(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.approve_pairing = AsyncMock(return_value=None)
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_approve_pairing("CODE")
        assert "❌" in result
        assert "CODE" in result

    async def test_exception(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.approve_pairing = AsyncMock(side_effect=RuntimeError("fail"))
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_approve_pairing("CODE")
        assert "❌" in result


class TestTelegramSendMessage:
    async def test_no_channel(self):
        from services.tools import mcp_handlers

        with patch.object(mcp_handlers, "get_message_gateway", return_value=None):
            result = await mcp_handlers.telegram_send_message("123", "hello")
        assert "not available" in result

    async def test_send_success(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.send_message = AsyncMock(return_value=True)
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_send_message("123", "hello")
        assert "✅" in result

    async def test_send_failure(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.send_message = AsyncMock(return_value=False)
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_send_message("123", "hello")
        assert "❌" in result

    async def test_exception(self):
        from services.tools import mcp_handlers

        channel = MagicMock()
        channel.send_message = AsyncMock(side_effect=RuntimeError("fail"))
        with patch.object(mcp_handlers, "get_message_gateway", return_value=channel):
            result = await mcp_handlers.telegram_send_message("123", "hello")
        assert "❌" in result


# ──────────────────────────────────────────────────────────────────
# intel_enricher.py
# ──────────────────────────────────────────────────────────────────


class TestIsValidDomain:
    def test_valid_domain(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("example.com") is True

    def test_valid_subdomain(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("sub.example.com") is True

    def test_empty_string(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("") is False

    def test_version_number(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("9.2") is False

    def test_decimal(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("0.5") is False

    def test_too_long(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("a" * 300 + ".com") is False

    def test_numeric_tld(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("test.123") is False


class TestEnrichIp:
    async def test_empty_ip(self):
        from services.intel_enricher import enrich_ip

        assert await enrich_ip("") is None

    async def test_invalid_ip(self):
        from services.intel_enricher import enrich_ip

        assert await enrich_ip("not-an-ip") is None

    async def test_loopback_ip(self):
        from services.intel_enricher import enrich_ip

        assert await enrich_ip("127.0.0.1") is None

    async def test_private_ip(self):
        from services.intel_enricher import enrich_ip

        assert await enrich_ip("192.168.1.1") is not None  # M4: enriched

    async def test_link_local_ip(self):
        from services.intel_enricher import enrich_ip

        assert await enrich_ip("169.254.1.1") is None

    async def test_success_with_feed_hit(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_IPV4_RE", _IPV4_RE_PATCH),
            patch.object(intel_enricher, "_lookup_sync", return_value={"score": 30, "abuse": {}, "virustotal": {}}),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": True}
            ),
            patch("services.ioc_memory_store.recall_decayed_score", new_callable=AsyncMock, return_value=0),
            patch("services.ioc_memory_store.save_score", new_callable=AsyncMock),
        ):
            result = await intel_enricher.enrich_ip("8.8.8.8")
        assert result is not None
        assert result["score"] == 50  # 30 + 20 feed boost
        assert "threat_feeds" in result

    async def test_success_with_historical_boost(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_IPV4_RE", _IPV4_RE_PATCH),
            patch.object(intel_enricher, "_lookup_sync", return_value={"score": 40, "abuse": {}, "virustotal": {}}),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": False}
            ),
            patch("services.ioc_memory_store.recall_decayed_score", new_callable=AsyncMock, return_value=15),
            patch("services.ioc_memory_store.save_score", new_callable=AsyncMock),
        ):
            result = await intel_enricher.enrich_ip("8.8.8.8")
        assert result is not None
        assert result["score"] == 55  # 40 + 15 historical
        assert result.get("historical_boost") == 15.0

    async def test_lookup_returns_none(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_IPV4_RE", _IPV4_RE_PATCH),
            patch.object(intel_enricher, "_lookup_sync", return_value=None),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": False}
            ),
        ):
            result = await intel_enricher.enrich_ip("8.8.8.8")
        assert result is None


class TestEnrichDomain:
    async def test_empty_domain(self):
        from services.intel_enricher import enrich_domain

        assert await enrich_domain("") is None

    async def test_invalid_domain(self):
        from services.intel_enricher import enrich_domain

        assert await enrich_domain("9.2") is None

    async def test_success(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_virustotal", MagicMock()),
            patch.object(
                intel_enricher, "_lookup_domain_sync", return_value={"score": 20, "virustotal": {}, "rdap": {}}
            ),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": True}
            ),
        ):
            result = await intel_enricher.enrich_domain("example.com")
        assert result is not None
        assert result["score"] == 40

    async def test_lookup_returns_none(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_virustotal", MagicMock()),
            patch.object(intel_enricher, "_lookup_domain_sync", return_value=None),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": False}
            ),
        ):
            result = await intel_enricher.enrich_domain("example.com")
        assert result is None


class TestEnrichHash:
    async def test_empty_hash(self):
        from services.intel_enricher import enrich_hash

        assert await enrich_hash("") is None

    async def test_success(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_virustotal", MagicMock()),
            patch.object(
                intel_enricher, "_lookup_hash_sync", return_value={"score": 10, "virustotal": {}, "maltiverse": {}}
            ),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": True}
            ),
        ):
            result = await intel_enricher.enrich_hash("abcdef1234567890")
        assert result is not None
        assert result["score"] == 30

    async def test_lookup_returns_none(self):
        from services import intel_enricher

        with (
            patch.object(intel_enricher, "_virustotal", MagicMock()),
            patch.object(intel_enricher, "_lookup_hash_sync", return_value=None),
            patch.object(
                intel_enricher, "check_target_in_feeds", new_callable=AsyncMock, return_value={"matched": False}
            ),
        ):
            result = await intel_enricher.enrich_hash("abcdef1234567890")
        assert result is None


class TestIsCleanEnrichment:
    def test_score_zero_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 0}) is True

    def test_feed_hit_never_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 0, "threat_feeds": {"matched": True}}) is False

    def test_trusted_isp_override(self):
        from services.intel_enricher import is_clean_enrichment

        enrichment = {
            "score": 30,
            "abuse": {"isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 0},
        }
        assert is_clean_enrichment(enrichment) is True

    def test_trusted_isp_with_vt_malicious(self):
        from services.intel_enricher import is_clean_enrichment

        enrichment = {
            "score": 30,
            "abuse": {"isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 5},
        }
        assert is_clean_enrichment(enrichment) is False

    def test_high_score_not_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 80}) is False

    def test_trusted_isp_high_score_is_clean(self):
        """Trusted ISP (Google) + VT=0 → clean regardless of abuse-driven score.

        AbuseIPDB mass-reporting on multi-tenant cloud IPs is noise; VT=0 from
        a trusted ISP wins (deterministic cross-validation guard).
        """
        from services.intel_enricher import is_clean_enrichment

        enrichment = {
            "score": 60,
            "abuse": {"isp": "Google LLC"},
            "virustotal": {"available": True, "found": True, "malicious": 0},
        }
        assert is_clean_enrichment(enrichment) is True


class TestIsTrustedIsp:
    def test_microsoft(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({"isp": "Microsoft Corporation"}) is True

    def test_no_isp(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({}) is False

    def test_unknown_isp(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({"isp": "Random ISP"}) is False


# ──────────────────────────────────────────────────────────────────
# credential_monitor.py
# ──────────────────────────────────────────────────────────────────


class TestFetchRawContent:
    async def test_success(self):
        from services import credential_monitor

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "leaked content"
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client
            result = await credential_monitor._fetch_raw_content("https://pastebin.com/abc")
        assert "leaked content" in result

    async def test_403_returns_empty(self):
        from services import credential_monitor

        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client
            result = await credential_monitor._fetch_raw_content("https://pastebin.com/abc")
        assert result == ""

    async def test_exception_returns_empty(self):
        from services import credential_monitor

        with patch("httpx.AsyncClient", side_effect=Exception("network error")):
            result = await credential_monitor._fetch_raw_content("https://pastebin.com/abc")
        assert result == ""


class TestSearchPasteSites:
    async def test_empty_query(self):
        from services.credential_monitor import search_paste_sites

        result = await search_paste_sites("")
        assert result == []

    async def test_no_results(self):
        from services import credential_monitor

        with (
            patch.object(credential_monitor, "_JITTER_MIN", 0.0),
            patch.object(credential_monitor, "_JITTER_MAX", 0.0),
            patch.object(credential_monitor._ddg_engine, "search", new_callable=AsyncMock, return_value=[]),
            patch.object(credential_monitor._sp_engine, "search", new_callable=AsyncMock, return_value=[]),
        ):
            result = await credential_monitor.search_paste_sites("test")
        assert result == []


class TestSearchGithubCode:
    async def test_empty_query(self):
        from services.credential_monitor import search_github_code

        result = await search_github_code("")
        assert result == []

    async def test_no_token(self):
        from services import credential_monitor

        with patch.object(credential_monitor, "GITHUB_TOKEN", ""):
            result = await credential_monitor.search_github_code("test")
        assert result == []

    async def test_403_rate_limit(self):
        from services import credential_monitor

        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with (
            patch.object(credential_monitor, "GITHUB_TOKEN", "fake_token"),
            patch.object(credential_monitor.github_limiter, "acquire", new_callable=AsyncMock),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client
            result = await credential_monitor.search_github_code("test")
        assert result == []

    async def test_401_invalid_token(self):
        from services import credential_monitor

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with (
            patch.object(credential_monitor, "GITHUB_TOKEN", "fake_token"),
            patch.object(credential_monitor.github_limiter, "acquire", new_callable=AsyncMock),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client
            result = await credential_monitor.search_github_code("test")
        assert result == []

    async def test_success_with_items(self):
        from services import credential_monitor

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "items": [
                {
                    "html_url": "https://github.com/repo/file",
                    "repository": {"full_name": "repo/name"},
                    "name": "config.py",
                    "text_matches": [{"fragment": "api_key = 'sk-1234567890abcdef1234567890abcdef'"}],
                }
            ]
        }

        with (
            patch.object(credential_monitor, "GITHUB_TOKEN", "fake_token"),
            patch.object(credential_monitor.github_limiter, "acquire", new_callable=AsyncMock),
            patch("httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client_cls.return_value = mock_client
            result = await credential_monitor.search_github_code("test")
        assert len(result) == 1
        assert result[0]["repo"] == "repo/name"

    async def test_network_exception(self):
        from services import credential_monitor

        with (
            patch.object(credential_monitor, "GITHUB_TOKEN", "fake_token"),
            patch.object(credential_monitor.github_limiter, "acquire", new_callable=AsyncMock),
            patch("httpx.AsyncClient", side_effect=Exception("network error")),
        ):
            result = await credential_monitor.search_github_code("test")
        assert result == []


class TestScanCredentialLeaks:
    async def test_whitespace_query(self):
        from services.credential_monitor import scan_credential_leaks

        result = await scan_credential_leaks("   ")
        assert result["total_hits"] == 0
        assert result["sources"] == {}


# ──────────────────────────────────────────────────────────────────
# monitor_engine_helpers.py
# ──────────────────────────────────────────────────────────────────


class TestIsWhitelisted:
    def test_whitelisted_ip(self):
        from services.monitor_engine_helpers import is_whitelisted

        with patch("services.monitor_engine_helpers.is_ip_whitelisted", return_value=True):
            assert is_whitelisted("10.0.0.1") is True

    def test_not_whitelisted_ip(self):
        from services.monitor_engine_helpers import is_whitelisted

        with patch("services.monitor_engine_helpers.is_ip_whitelisted", return_value=False):
            assert is_whitelisted("8.8.8.8") is False


class TestIsBrowserConnection:
    def test_browser_on_web_port(self):
        from services.monitor_engine_helpers import is_browser_connection

        assert is_browser_connection("chrome.exe", 443) is True

    def test_browser_on_non_web_port(self):
        from services.monitor_engine_helpers import is_browser_connection

        assert is_browser_connection("chrome.exe", 22) is False

    def test_non_browser_on_web_port(self):
        from services.monitor_engine_helpers import is_browser_connection

        assert is_browser_connection("malware.exe", 443) is False

    def test_case_insensitive(self):
        from services.monitor_engine_helpers import is_browser_connection

        assert is_browser_connection("CHROME.EXE", 80) is True


class TestIsKnownGoodAsn:
    def test_known_asn(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn("AS15169", None) is True

    def test_known_org(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn(None, "Google LLC") is True

    def test_unknown_both(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn("AS99999", "Unknown ISP") is False

    def test_none_both(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn(None, None) is False

    def test_asn_without_prefix(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn("13335", None) is True


class TestGetProcNames:
    def test_valid_pid(self):
        from services.monitor_engine_helpers import _get_proc_names

        mock_proc = MagicMock()
        mock_proc.name.return_value = "test.exe"
        with patch("services.monitor_engine_helpers.psutil.Process", return_value=mock_proc):
            result = _get_proc_names({100})
        assert result[100] == "test.exe"

    def test_no_such_process(self):
        import psutil

        from services.monitor_engine_helpers import _get_proc_names

        with patch("services.monitor_engine_helpers.psutil.Process", side_effect=psutil.NoSuchProcess(100)):
            result = _get_proc_names({100})
        assert result[100] == "unknown"

    def test_access_denied(self):
        import psutil

        from services.monitor_engine_helpers import _get_proc_names

        with patch("services.monitor_engine_helpers.psutil.Process", side_effect=psutil.AccessDenied(100)):
            result = _get_proc_names({100})
        assert result[100] == "unknown"

    def test_empty_set(self):
        from services.monitor_engine_helpers import _get_proc_names

        assert _get_proc_names(set()) == {}


class TestCollectCandidates:
    def test_established_connection(self):
        from services.monitor_engine_helpers import _collect_candidates

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr.ip = "8.8.8.8"
        conn.raddr.port = 443
        conn.pid = 100

        with patch("services.monitor_engine_helpers.is_whitelisted", return_value=False):
            candidates, pids = _collect_candidates([conn], {})
        assert len(candidates) == 1
        assert 100 in pids

    def test_non_established_skipped(self):
        from services.monitor_engine_helpers import _collect_candidates

        conn = MagicMock()
        conn.status = "CLOSE_WAIT"
        conn.raddr.ip = "8.8.8.8"
        conn.raddr.port = 443
        conn.pid = 100

        candidates, pids = _collect_candidates([conn], {})
        assert len(candidates) == 0

    def test_whitelisted_skipped(self):
        from services.monitor_engine_helpers import _collect_candidates

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr.ip = "10.0.0.1"
        conn.raddr.port = 443
        conn.pid = 100

        with patch("services.monitor_engine_helpers.is_whitelisted", return_value=True):
            candidates, pids = _collect_candidates([conn], {})
        assert len(candidates) == 0

    def test_in_registry_skipped(self):
        from services.monitor_engine_helpers import _collect_candidates

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr.ip = "10.0.0.1"
        conn.raddr.port = 443
        conn.pid = 100

        candidates, pids = _collect_candidates([conn], {"10.0.0.1": {}})
        assert len(candidates) == 0

    def test_no_raddr_skipped(self):
        from services.monitor_engine_helpers import _collect_candidates

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.raddr = None
        conn.pid = 100

        candidates, pids = _collect_candidates([conn], {})
        assert len(candidates) == 0


class TestIsConnectionFiltered:
    def test_self_process_filtered(self):
        from services.monitor_engine_helpers import _is_connection_filtered

        with patch("services.self_whitelist.is_self_process", return_value=True):
            assert _is_connection_filtered(100, "devin.exe", 443, "8.8.8.8", {}) is True

    def test_browser_filtered(self):
        from services.monitor_engine_helpers import _is_connection_filtered

        with patch("services.self_whitelist.is_self_process", return_value=False):
            assert _is_connection_filtered(100, "chrome.exe", 443, "8.8.8.8", {}) is True

    def test_whitelisted_net_proc_known_good_asn(self):
        from services.monitor_engine_helpers import _is_connection_filtered

        with patch("services.self_whitelist.is_self_process", return_value=False):
            cache = {"8.8.8.8": {"asn": "15169", "org": "Google"}}
            assert _is_connection_filtered(100, "svchost.exe", 443, "8.8.8.8", cache) is True

    def test_not_filtered(self):
        from services.monitor_engine_helpers import _is_connection_filtered

        with patch("services.self_whitelist.is_self_process", return_value=False):
            cache = {"8.8.8.8": {"asn": "99999", "org": "Unknown"}}
            assert _is_connection_filtered(100, "malware.exe", 22, "8.8.8.8", cache) is False


class TestFormatConnection:
    def test_ipv4_format(self):
        from services.monitor_engine_helpers import _format_connection

        # ip_cache is keyed by IP address
        ip_cache = {"8.8.8.8": {"org": "Google", "asn": "15169"}}
        result = _format_connection("8.8.8.8", 443, 100, "chrome.exe", ip_cache)
        assert "8.8.8.8:443" in result
        assert "Google" in result
        assert "AS15169" in result

    def test_no_enrichment(self):
        from services.monitor_engine_helpers import _format_connection

        result = _format_connection("1.2.3.4", 80, None, "test.exe", {})
        assert "1.2.3.4:80" in result
        assert "unknown provider" in result
        assert "?" in result

    def test_ipv6_format(self):
        from services.monitor_engine_helpers import _format_connection

        result = _format_connection("::1", 443, 50, "test.exe", {})
        assert "[::1]:443" in result


class TestCheckDisks:
    async def test_no_alerts(self):
        from services import monitor_engine_helpers

        mock_part = MagicMock()
        mock_part.mountpoint = "C:\\"
        mock_part.device = "C:"

        mock_usage = MagicMock()
        mock_usage.percent = 50.0

        with (
            patch.object(monitor_engine_helpers.psutil, "disk_partitions", return_value=[mock_part]),
            patch.object(monitor_engine_helpers.psutil, "disk_usage", return_value=mock_usage),
            patch("config.DISK_THRESHOLD", 90),
        ):
            result = await monitor_engine_helpers._check_disks()
        assert result == []

    async def test_with_alert(self):
        from services import monitor_engine_helpers

        mock_part = MagicMock()
        mock_part.mountpoint = "C:\\"
        mock_part.device = "C:"

        mock_usage = MagicMock()
        mock_usage.percent = 95.0

        with (
            patch.object(monitor_engine_helpers.psutil, "disk_partitions", return_value=[mock_part]),
            patch.object(monitor_engine_helpers.psutil, "disk_usage", return_value=mock_usage),
            patch("config.DISK_THRESHOLD", 90),
        ):
            result = await monitor_engine_helpers._check_disks()
        assert len(result) == 1
        assert "95%" in result[0]

    async def test_permission_error(self):
        from services import monitor_engine_helpers

        mock_part = MagicMock()
        mock_part.mountpoint = "D:\\"
        mock_part.device = "D:"

        with (
            patch.object(monitor_engine_helpers.psutil, "disk_partitions", return_value=[mock_part]),
            patch.object(monitor_engine_helpers.psutil, "disk_usage", side_effect=PermissionError("denied")),
        ):
            result = await monitor_engine_helpers._check_disks()
        assert result == []


# ──────────────────────────────────────────────────────────────────
# reference_store.py
# ──────────────────────────────────────────────────────────────────


class TestReferenceStore:
    """Tests for reference_store — uses monkeypatch to isolate DB."""

    async def test_store_and_search_intel(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        async def _fake_embed(texts):
            return [[0.0] * 8 for _ in texts]

        monkeypatch.setattr(reference_store, "embed_texts", _fake_embed)

        await reference_store.store_intel("test_topic", "raw data here", {"ips": ["1.2.3.4"]})
        results = await reference_store.search_intel("raw data", limit=5)
        assert isinstance(results, list)

    async def test_search_intel_empty(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        async def _fake_embed(texts):
            return [[0.0] * 8 for _ in texts]

        monkeypatch.setattr(reference_store, "embed_texts", _fake_embed)

        results = await reference_store.search_intel("nonexistent query xyz", limit=5)
        assert results == []

    async def test_get_skill_state_missing_key(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        result = await reference_store.get_skill_state("nonexistent_key")
        assert result == {}

    async def test_save_and_get_skill_state(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        await reference_store.save_skill_state("test_key", {"status": "running", "count": 42})
        result = await reference_store.get_skill_state("test_key")
        assert result["status"] == "running"
        assert result["count"] == 42

    async def test_get_skill_state_invalid_json(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        await reference_store._ensure_init()
        async with new_pool.acquire() as db:
            await db.execute(
                "INSERT OR REPLACE INTO skill_state (key, value) VALUES (?, ?)",
                ("bad_json", "not-json{"),
            )
            await db.commit()
        result = await reference_store.get_skill_state("bad_json")
        assert result == {}

    async def test_migrate_no_source(self, monkeypatch, tmp_path):
        from services import reference_store
        from services.db_pool import get_pool

        ref_path = str(tmp_path / "test_reference.db")
        new_pool = get_pool(ref_path, max_connections=2)
        monkeypatch.setattr(reference_store, "_pool", new_pool)
        monkeypatch.setattr(reference_store, "_DB_PATH", ref_path)
        monkeypatch.setattr(reference_store, "_initialized", False)

        result = await reference_store.migrate_from_alert_history(str(tmp_path / "nonexistent.db"))
        assert result == 0


# ──────────────────────────────────────────────────────────────────
# night_watchman.py
# ──────────────────────────────────────────────────────────────────


class TestSummarizeChunk:
    async def test_success(self):
        from services import night_watchman
        from services.bot_memory.models import MemoryEntry

        entries = [MemoryEntry(query="q1", response="r1"), MemoryEntry(query="q2", response="r2")]
        engine = MagicMock()
        engine.complete = AsyncMock(return_value="- bullet 1\n- bullet 2")

        result = await night_watchman._summarize_chunk(entries, engine)
        assert "bullet 1" in result

    async def test_exception_fallback(self):
        from services import night_watchman
        from services.bot_memory.models import MemoryEntry

        entries = [MemoryEntry(query="q1", response="response text here")]
        engine = MagicMock()
        engine.complete = AsyncMock(side_effect=RuntimeError("LLM down"))

        result = await night_watchman._summarize_chunk(entries, engine)
        assert "response text here" in result


class TestRunMemoryCompaction:
    async def test_llm_circuit_open(self):
        from services import night_watchman

        mock_bridge = MagicMock()
        mock_bridge.should_accept_traffic.return_value = False
        with patch.object(night_watchman.LLMBridge, "get_instance", return_value=mock_bridge):
            result = await night_watchman.run_memory_compaction()
        assert result["chunks_processed"] == 0
        assert result["summaries_created"] == 0

    async def test_llm_check_exception(self):
        from services import night_watchman

        with patch.object(night_watchman.LLMBridge, "get_instance", side_effect=RuntimeError("no bridge")):
            result = await night_watchman.run_memory_compaction()
        assert result["chunks_processed"] == 0

    async def test_no_old_memories(self):
        from services import night_watchman

        mock_bridge = MagicMock()
        mock_bridge.should_accept_traffic.return_value = True
        with (
            patch.object(night_watchman.LLMBridge, "get_instance", return_value=mock_bridge),
            patch("services.night_watchman.fetch_old_memories_for_compaction", new_callable=AsyncMock, return_value=[]),
        ):
            result = await night_watchman.run_memory_compaction()
        assert result["chunks_processed"] == 0

    async def test_dry_run(self):
        from services import night_watchman
        from services.bot_memory.models import MemoryEntry

        entries = [MemoryEntry(id=1, query="q1", response="r1", context='{"topic": "cyber"}')]
        mock_bridge = MagicMock()
        mock_bridge.should_accept_traffic.return_value = True
        mock_bridge.complete = AsyncMock(return_value="- summary")
        with (
            patch.object(night_watchman.LLMBridge, "get_instance", return_value=mock_bridge),
            patch(
                "services.night_watchman.fetch_old_memories_for_compaction",
                new_callable=AsyncMock,
                return_value=[entries],
            ),
        ):
            result = await night_watchman.run_memory_compaction(dry_run=True)
        assert result["chunks_processed"] == 1
        assert result["summaries_created"] == 0
        assert result["rows_archived"] == 0

    async def test_dry_run_empty_chunk_topic(self):
        from services import night_watchman

        mock_bridge = MagicMock()
        mock_bridge.should_accept_traffic.return_value = True
        mock_bridge.complete = AsyncMock(return_value="- summary")
        with (
            patch.object(night_watchman.LLMBridge, "get_instance", return_value=mock_bridge),
            patch(
                "services.night_watchman.fetch_old_memories_for_compaction",
                new_callable=AsyncMock,
                return_value=[[]],
            ),
        ):
            result = await night_watchman.run_memory_compaction(dry_run=True)
        assert result["chunks_processed"] == 1

    async def test_dry_run_invalid_context_json(self):
        from services import night_watchman
        from services.bot_memory.models import MemoryEntry

        entries = [MemoryEntry(id=1, query="q1", response="r1", context="invalid-json{")]
        mock_bridge = MagicMock()
        mock_bridge.should_accept_traffic.return_value = True
        mock_bridge.complete = AsyncMock(return_value="- summary")
        with (
            patch.object(night_watchman.LLMBridge, "get_instance", return_value=mock_bridge),
            patch(
                "services.night_watchman.fetch_old_memories_for_compaction",
                new_callable=AsyncMock,
                return_value=[entries],
            ),
        ):
            result = await night_watchman.run_memory_compaction(dry_run=True)
        assert result["chunks_processed"] == 1

    async def test_compact_conversations_alias(self):
        from services import night_watchman

        assert night_watchman.compact_conversations is night_watchman.run_memory_compaction
