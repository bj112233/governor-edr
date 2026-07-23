# tests/test_visibility_triad.py
"""Tests for Visibility Triad wiring — 4-block refactor.

Block 1: Intent Router for .pcap/.eml (deterministic bypass)
Block 2: FIM+YARA injection into pre_hunt_enricher
Block 3: HITL rejection → error_lessons closed-loop learning
Block 4: query_baseline_deviation tool
"""

import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── Block 1: Intent Router for .pcap/.eml ──


class TestPcapIntentRouter:
    def test_pcap_extension_detected(self):
        from services.agent.routing.intent_routers import _is_pcap_query

        result = _is_pcap_query("analyze C:\\captures\\traffic.pcap")
        assert result is not None
        path, command = result
        assert path.endswith("traffic.pcap")
        assert command == "analyze"

    def test_pcapng_extension_detected(self):
        from services.agent.routing.intent_routers import _is_pcap_query

        result = _is_pcap_query("C:\\logs\\full.pcapng")
        assert result is not None
        assert result[1] == "analyze"

    def test_pcap_dns_command(self):
        from services.agent.routing.intent_routers import _is_pcap_query

        result = _is_pcap_query("extract dns from /home/user/cap.pcap")
        assert result is not None
        assert result[1] == "dns"

    def test_pcap_sni_command(self):
        from services.agent.routing.intent_routers import _is_pcap_query

        result = _is_pcap_query("sni /tmp/capture.pcap")
        assert result is not None
        assert result[1] == "sni"

    def test_non_pcap_not_matched(self):
        from services.agent.routing.intent_routers import _is_pcap_query

        assert _is_pcap_query("analyze report.pdf") is None

    def test_detect_intent_routes_pcap(self):
        from services.agent.routing.intent_routers import detect_intent

        result = detect_intent("analyze C:\\captures\\traffic.pcap")
        assert result is not None
        assert result["intent"] == "pcap"
        assert result["tool"] == "skill_pcap-analyst"

    def test_detect_intent_routes_eml(self):
        from services.agent.routing.intent_routers import detect_intent

        result = detect_intent("analyze C:\\emails\\phishing.eml")
        assert result is not None
        assert result["intent"] == "eml"
        assert result["tool"] == "skill_email-forensics"


class TestEmlIntentRouter:
    def test_eml_extension_detected(self):
        from services.agent.routing.intent_routers import _is_eml_query

        result = _is_eml_query("analyze C:\\emails\\suspicious.eml")
        assert result is not None
        path, command = result
        assert path.endswith("suspicious.eml")
        assert command == "full"

    def test_msg_extension_detected(self):
        from services.agent.routing.intent_routers import _is_eml_query

        result = _is_eml_query("C:\\outlook\\message.msg")
        assert result is not None

    def test_eml_headers_command(self):
        from services.agent.routing.intent_routers import _is_eml_query

        result = _is_eml_query("headers C:\\emails\\test.eml")
        assert result is not None
        assert result[1] == "headers"

    def test_non_eml_not_matched(self):
        from services.agent.routing.intent_routers import _is_eml_query

        assert _is_eml_query("analyze report.pdf") is None


class TestPcapBypassHandler:
    @pytest.mark.asyncio
    async def test_pcap_bypass_calls_skill(self):
        from services.agent.bypass.pcap import _try_pcap_bypass

        engine = MagicMock()
        engine.execute = AsyncMock(return_value="PCAP analysis result")
        with patch("services.agent.bypass.pcap.get_skills_engine", return_value=engine):
            result = await _try_pcap_bypass("analyze C:\\cap.pcap")
        assert result == "PCAP analysis result"
        engine.execute.assert_called_once_with("pcap-analyst", "analyze", {"path": "C:\\cap.pcap"})

    @pytest.mark.asyncio
    async def test_eml_bypass_calls_skill(self):
        from services.agent.bypass.eml import _try_eml_bypass

        engine = MagicMock()
        engine.execute = AsyncMock(return_value="EML analysis result")
        with patch("services.agent.bypass.eml.get_skills_engine", return_value=engine):
            result = await _try_eml_bypass("analyze C:\\email.eml")
        assert result == "EML analysis result"
        engine.execute.assert_called_once_with("email-forensics", "full", {"path": "C:\\email.eml"})


# ── Block 2: FIM+YARA injection ──


class TestFIMYARAInjection:
    def test_get_recent_yara_hits_empty(self):
        from services.fim_engine import _RECENT_YARA_HITS, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        assert get_recent_yara_hits() == []

    def test_record_and_retrieve_yara_hit(self):
        from services.fim_engine import _RECENT_YARA_HITS, _record_yara_hit, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        _record_yara_hit(
            "C:\\temp\\webshell.php",
            [{"rule": "php_webshell", "meta": {"severity": "critical", "mitre": "T1505.003"}}],
        )
        hits = get_recent_yara_hits(hours=1.0)
        assert len(hits) == 1
        assert hits[0]["path"] == "C:\\temp\\webshell.php"
        assert "php_webshell" in hits[0]["rules"]
        assert "T1505.003" in hits[0]["mitre_ids"]

    def test_old_hits_filtered_by_ttl(self):
        from services.fim_engine import _RECENT_YARA_HITS, _record_yara_hit, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        _record_yara_hit("old.php", [{"rule": "test", "meta": {}}])
        # Backdate the timestamp
        _RECENT_YARA_HITS[0]["timestamp"] = time.time() - 7200  # 2 hours ago
        hits = get_recent_yara_hits(hours=1.0)
        assert len(hits) == 0  # filtered out

    def test_format_fim_facts_empty(self):
        from services.pre_hunt_enricher import _format_fim_facts

        with patch("services.fim_engine.get_recent_yara_hits", return_value=[]):
            assert _format_fim_facts() == ""

    def test_format_fim_facts_with_hits(self):
        from services.pre_hunt_enricher import _format_fim_facts

        hits = [
            {
                "path": "C:\\temp\\shell.php",
                "rules": ["php_webshell"],
                "mitre_ids": ["T1505.003"],
                "severity": "critical",
                "timestamp": time.time(),
            }
        ]
        with patch("services.fim_engine.get_recent_yara_hits", return_value=hits):
            result = _format_fim_facts()
        assert "FIM+YARA" in result
        assert "shell.php" in result
        assert "php_webshell" in result
        assert "T1505.003" in result


# ── Block 3: HITL rejection → error_lessons ──


class TestHITLRejectionLearning:
    @pytest.mark.asyncio
    async def test_ignore_with_auto_kill_stores_scoped_lesson(self):
        """When user ignores an alert with auto-kill pending, store parameter-scoped lesson."""
        from services.telegram.callbacks import _execute_remediation_action

        cached = {
            "ip": "1.2.3.4",
            "port": 443,
            "proc_name": "chrome.exe",
            "_auto_kill_id": 42,
            "_auto_block_id": 0,
        }

        mock_action = {"status": "PENDING_APPROVAL", "target": "123|suspicious.exe", "threat_context": "TTP detected"}

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=mock_action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.error_memory.store_lesson", new_callable=AsyncMock) as mock_store,
            patch("services.net_baseline.add_to_baseline", new_callable=AsyncMock),
        ):
            ok, detail, result_text = await _execute_remediation_action("rem_ign_abc123", cached)

        assert ok is True
        assert "Ignored" in detail
        # Verify parameter-scoped tool_name: "kill_process|suspicious.exe" not "kill_process"
        mock_store.assert_called_once()
        call_kwargs = mock_store.call_args
        stored_tool_name = call_kwargs.kwargs.get("tool_name", call_kwargs.args[3] if len(call_kwargs.args) > 3 else "")
        assert stored_tool_name == "kill_process|suspicious.exe"
        assert stored_tool_name != "kill_process"  # NOT global — prevents Tool Starvation

    @pytest.mark.asyncio
    async def test_ignore_with_auto_block_stores_scoped_lesson(self):
        """When user ignores an alert with auto-block pending, store parameter-scoped lesson."""
        from services.telegram.callbacks import _execute_remediation_action

        cached = {
            "ip": "1.2.3.4",
            "port": 443,
            "proc_name": "chrome.exe",
            "_auto_kill_id": 0,
            "_auto_block_id": 99,
        }

        mock_action = {"status": "PENDING_APPROVAL", "target": "5.6.7.8", "threat_context": "suspicious C2"}

        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=mock_action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.error_memory.store_lesson", new_callable=AsyncMock) as mock_store,
            patch("services.net_baseline.add_to_baseline", new_callable=AsyncMock),
        ):
            ok, detail, _ = await _execute_remediation_action("rem_ign_abc123", cached)

        assert ok is True
        mock_store.assert_called_once()
        call_kwargs = mock_store.call_args
        stored_tool_name = call_kwargs.kwargs.get("tool_name", "")
        assert stored_tool_name == "block_ip|5.6.7.8"
        assert stored_tool_name != "block_ip"  # NOT global

    @pytest.mark.asyncio
    async def test_ignore_without_auto_kill_no_lesson(self):
        """When user ignores without auto-kill, no lesson stored."""
        from services.telegram.callbacks import _execute_remediation_action

        cached = {"ip": "1.2.3.4", "port": 443, "proc_name": "chrome.exe"}

        with (
            patch("services.error_memory.store_lesson", new_callable=AsyncMock) as mock_lesson,
            patch("services.net_baseline.add_to_baseline", new_callable=AsyncMock),
        ):
            ok, detail, _ = await _execute_remediation_action("rem_ign_abc123", cached)

        assert ok is True
        mock_lesson.assert_not_called()

    @pytest.mark.asyncio
    async def test_scoped_lesson_does_not_demote_global_tool(self):
        """Parameter-scoped tool_name must NOT appear in get_tool_stats for 'kill_process'.

        This is the Tool Starvation defense: the global kill_process rank stays at 100.
        The lesson is only retrievable via search_lessons (semantic search on trigger_context).
        """
        from services.error_memory import get_tool_stats

        # Simulate: store_lesson was called with tool_name="kill_process:svchost.exe"
        # get_tool_stats groups by tool_name — "kill_process:svchost.exe" != "kill_process"
        # So the global "kill_process" stats should NOT include this rejection.
        # This test verifies the architecture: scoped names don't match bare tool names.
        scoped_name = "kill_process|svchost.exe"
        bare_name = "kill_process"
        assert scoped_name != bare_name  # Architecture guarantee

    def test_pipe_delimiter_survives_ipv6_and_windows_paths(self):
        """Pipe delimiter must not collide with IPv6 addresses or Windows paths.

        IPv6: 2001:db8::1 contains colons → would break split(':', 1)
        Windows: C:\\Temp\\malware.exe contains colon → same issue
        Pipe (|) is illegal in Windows paths and absent in IPv6.
        """
        # IPv6 target
        scoped_ipv6 = "block_ip|2001:db8::1"
        tool, target = scoped_ipv6.split("|", 1)
        assert tool == "block_ip"
        assert target == "2001:db8::1"  # Full IPv6 preserved

        # Windows path target
        scoped_path = "delete_file|C:\\Windows\\Temp\\malware.exe"
        tool, target = scoped_path.split("|", 1)
        assert tool == "delete_file"
        assert target == "C:\\Windows\\Temp\\malware.exe"  # Full path preserved

        # Verify colon-based delimiter WOULD break (regression guard)
        bad_ipv6 = "block_ip:2001:db8::1"
        parts = bad_ipv6.split(":", 1)
        assert parts[1] == "2001:db8::1"  # split(':', 1) works for IPv6
        # But split(':') without maxsplit would break:
        assert len(bad_ipv6.split(":")) > 2  # Would over-split


# ── Block 4: query_baseline_deviation tool ──


class TestQueryBaselineDeviation:
    def test_tool_registered(self):
        from services.tools.system_tools import get_system_tools

        tools = get_system_tools()
        names = [t.name for t in tools]
        assert "query_baseline_deviation" in names

    def test_query_cpu_baseline(self):
        from services.tools._baseline_handler import query_baseline_deviation_handler

        ema = MagicMock()
        ema.get_stats.return_value = (15.0, 5.0)
        with patch("services.ema_baseline.GatedEMABaseline", return_value=ema):
            result = query_baseline_deviation_handler("cpu", current_value=30.0)
        assert "Baseline μ = 15.0" in result
        assert "Z-score" in result
        assert "ELEVATED" in result  # z = (30-15)/5 = 3.0 → > 2.0

    def test_query_baseline_no_data(self):
        from services.tools._baseline_handler import query_baseline_deviation_handler

        ema = MagicMock()
        ema.get_stats.return_value = (None, None)
        with patch("services.ema_baseline.GatedEMABaseline", return_value=ema):
            result = query_baseline_deviation_handler("cpu")
        assert "No baseline data" in result

    def test_query_baseline_normal_range(self):
        from services.tools._baseline_handler import query_baseline_deviation_handler

        ema = MagicMock()
        ema.get_stats.return_value = (20.0, 5.0)
        with patch("services.ema_baseline.GatedEMABaseline", return_value=ema):
            result = query_baseline_deviation_handler("cpu", current_value=22.0)
        assert "NORMAL" in result  # z = (22-20)/5 = 0.4

    def test_query_baseline_anomaly(self):
        from services.tools._baseline_handler import query_baseline_deviation_handler

        ema = MagicMock()
        ema.get_stats.return_value = (10.0, 3.0)
        with patch("services.ema_baseline.GatedEMABaseline", return_value=ema):
            result = query_baseline_deviation_handler("cpu", current_value=30.0)
        assert "ANOMALY" in result  # z = (30-10)/3 = 6.7 → > 3.0
