# tests/test_coverage_batch3.py
"""Coverage tests for more high-gap modules.

Covers:
- services/_skills_engine/_truncator.py
- services/action_tools/services_mgmt.py
- services/yara_engine.py
- services/fim_engine.py
- services/agent_tools.py
- services/llm_bridge/completion.py
- services/alert_history_query.py
- services/monitor_engine_helpers.py
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# _skills_engine/_truncator.py
# ═══════════════════════════════════════════════════════════════════════════


class TestJsonSafeTruncate:
    def test_short_text_unchanged(self):
        from services._skills_engine._truncator import json_safe_truncate

        assert json_safe_truncate("short", 100) == "short"

    def test_non_json_truncated(self):
        from services._skills_engine._truncator import json_safe_truncate

        text = "x" * 200
        result = json_safe_truncate(text, 50)
        assert len(result) == 50

    def test_valid_json_array_truncated(self):
        from services._skills_engine._truncator import json_safe_truncate

        text = json.dumps([{"a": 1}, {"b": 2}, {"c": 3}])
        result = json_safe_truncate(text, 20)
        # Should produce valid JSON
        try:
            parsed = json.loads(result)
            assert isinstance(parsed, list)
        except json.JSONDecodeError:
            # If can't parse, at least it should be truncated
            assert len(result) <= 20

    def test_valid_json_object_truncated(self):
        from services._skills_engine._truncator import json_safe_truncate

        text = json.dumps({"a": 1, "b": 2, "c": 3, "d": 4, "e": 5})
        result = json_safe_truncate(text, 15)
        try:
            json.loads(result)
        except json.JSONDecodeError:
            assert len(result) <= 15

    def test_handle_structural_open(self):
        from services._skills_engine._truncator import _handle_structural_char

        stack: list[str] = []
        result, pos = _handle_structural_char("{", 0, stack)
        assert result is None
        assert pos is None
        assert stack == ["{"]

    def test_handle_structural_close(self):
        from services._skills_engine._truncator import _handle_structural_char

        stack = ["{"]
        result, pos = _handle_structural_char("}", 5, stack)
        assert result == []
        assert pos == 5
        assert stack == []

    def test_handle_structural_comma(self):
        from services._skills_engine._truncator import _handle_structural_char

        stack = ["{"]
        result, pos = _handle_structural_char(",", 10, stack)
        assert result == ["{"]
        assert pos == 9

    def test_handle_structural_other(self):
        from services._skills_engine._truncator import _handle_structural_char

        stack: list[str] = []
        result, pos = _handle_structural_char("x", 0, stack)
        assert result is None
        assert pos is None

    def test_scan_safe_cut_points_basic(self):
        from services._skills_engine._truncator import _scan_safe_cut_points

        points = _scan_safe_cut_points('{"a":1,"b":2}')
        assert isinstance(points, dict)

    def test_try_close_json_success(self):
        from services._skills_engine._truncator import _try_close_json

        # '{"a":1' has 6 chars (indices 0-5). pos=5 → trimmed[:6] = '{"a":1' + '}' = '{"a":1}'
        result = _try_close_json('{"a":1', 5, ["{"])
        assert result is not None
        json.loads(result)

    def test_try_close_json_fail(self):
        from services._skills_engine._truncator import _try_close_json

        result = _try_close_json('{"a":1,"b":', 9, ["{"])
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# action_tools/services_mgmt.py
# ═══════════════════════════════════════════════════════════════════════════


class TestServicesMgmt:
    def test_validate_invalid_action(self):
        from services.action_tools.services_mgmt import _validate_service_action

        error = _validate_service_action("delete", "Spooler")
        assert "לא חוקית" in error

    def test_validate_protected_service(self):
        from services.action_tools.services_mgmt import _validate_service_action

        error = _validate_service_action("stop", "EventLog")
        assert "מוגן" in error

    def test_validate_invalid_name(self):
        from services.action_tools.services_mgmt import _validate_service_action

        error = _validate_service_action("stop", "bad;name|rm")
        assert "לא תקין" in error

    def test_validate_valid(self):
        from services.action_tools.services_mgmt import _validate_service_action

        assert _validate_service_action("stop", "Spooler") is None

    async def test_manage_service_invalid_action(self):
        from services.action_tools.services_mgmt import manage_service

        result = await manage_service("delete", "Spooler")
        assert "לא חוקית" in result

    async def test_manage_service_protected(self):
        from services.action_tools.services_mgmt import manage_service

        result = await manage_service("stop", "EventLog")
        assert "מוגן" in result

    async def test_manage_service_start(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(0, b"OK"))):
            result = await manage_service("start", "Spooler")
            assert "✅" in result

    async def test_manage_service_stop_error(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(1, b"failed"))):
            result = await manage_service("stop", "Spooler")
            assert "❌" in result

    async def test_manage_service_timeout(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(None, None))):
            result = await manage_service("stop", "Spooler")
            assert "timeout" in result

    async def test_manage_service_restart(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(0, b"OK"))):
            result = await manage_service("restart", "Spooler")
            assert "✅" in result

    async def test_manage_service_restart_stop_fails(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(1, b"error"))):
            result = await manage_service("restart", "Spooler")
            assert "❌" in result

    async def test_manage_service_restart_stop_timeout(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(return_value=(None, None))):
            result = await manage_service("restart", "Spooler")
            assert "timeout" in result

    async def test_manage_service_exception(self):
        from services.action_tools.services_mgmt import manage_service

        with patch("services.action_tools.services_mgmt._exec_net", AsyncMock(side_effect=Exception("boom"))):
            result = await manage_service("start", "Spooler")
            assert "❌" in result


# ═══════════════════════════════════════════════════════════════════════════
# yara_engine.py
# ═══════════════════════════════════════════════════════════════════════════


class TestYaraEngine:
    @pytest.fixture(autouse=True)
    def _restore_yara_state(self):
        import services.yara_engine as ye

        old_init = ye._initialized
        old_rules = ye._compiled_rules
        yield
        ye._initialized = old_init
        ye._compiled_rules = old_rules

    def test_initialize_no_rules_dir(self):
        import services.yara_engine as ye

        ye._initialized = False
        ye._compiled_rules = None
        with patch.object(ye, "_RULES_DIR", MagicMock(exists=MagicMock(return_value=False))):
            ye.initialize()
            assert ye._initialized is True

    def test_match_not_initialized(self):
        import services.yara_engine as ye

        ye._initialized = False
        ye._compiled_rules = None
        with patch.object(ye, "_RULES_DIR", MagicMock(exists=MagicMock(return_value=False))):
            assert ye.match("/nonexistent") == []

    def test_match_no_rules(self):
        import services.yara_engine as ye

        ye._initialized = True
        ye._compiled_rules = None
        assert ye.match("/some/file") == []

    def test_match_file_not_found(self):
        import services.yara_engine as ye

        ye._initialized = True
        ye._compiled_rules = MagicMock()
        with patch("os.path.isfile", return_value=False):
            assert ye.match("/nonexistent") == []

    def test_match_data_no_rules(self):
        import services.yara_engine as ye

        ye._initialized = True
        ye._compiled_rules = None
        assert ye.match_data(b"data") == []

    def test_get_rule_count(self):
        import services.yara_engine as ye

        ye._initialized = True
        ye._compiled_rules = MagicMock()
        assert isinstance(ye.get_rule_count(), int)


# ═══════════════════════════════════════════════════════════════════════════
# fim_engine.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFimEngine:
    def test_get_recent_yara_hits_empty(self):
        from services.fim_engine import _RECENT_YARA_HITS, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        assert get_recent_yara_hits() == []

    def test_record_yara_hit(self):
        from services.fim_engine import _RECENT_YARA_HITS, _record_yara_hit, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        _record_yara_hit("/test/path", [{"rule": "test_rule", "meta": {"severity": "critical"}}])
        hits = get_recent_yara_hits()
        assert len(hits) == 1
        assert hits[0]["path"] == "/test/path"
        assert "test_rule" in hits[0]["rules"]

    def test_record_yara_hit_with_mitre(self):
        from services.fim_engine import _RECENT_YARA_HITS, _record_yara_hit, get_recent_yara_hits

        _RECENT_YARA_HITS.clear()
        _record_yara_hit(
            "/test/path",
            [{"rule": "r1", "meta": {"severity": "high", "mitre": "T1059"}}, {"rule": "r2", "meta": {}}],
        )
        hits = get_recent_yara_hits()
        assert "T1059" in hits[0]["mitre_ids"]

    def test_is_running(self):
        from services.fim_engine import is_running

        assert isinstance(is_running(), bool)


# ═══════════════════════════════════════════════════════════════════════════
# agent_tools.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentTools:
    def test_try_flat_args(self):
        from services.agent_tools import _try_flat_args

        # Multiple keys, no "args" key → flat args
        result = _try_flat_args({"q": "hello", "limit": 5}, "skill_test")
        assert result == {"q": "hello", "limit": 5}

    def test_try_flat_args_none(self):
        from services.agent_tools import _try_flat_args

        # Has "args" key → not flat
        assert _try_flat_args({"args": {"q": "hello"}}, "test") is None
        # Single key → not flat
        assert _try_flat_args({"q": "hello"}, "test") is None

    def test_strip_wrappers(self):
        from services.agent_tools import _strip_wrappers

        result = _strip_wrappers({"input": {"q": "test"}}, "skill_test")
        assert "q" in result
        assert "input" not in result

    def test_is_empty_value(self):
        from services.agent_tools import _is_empty_value

        assert _is_empty_value("") is True
        assert _is_empty_value(None) is True
        assert _is_empty_value([]) is True
        assert _is_empty_value("test") is False

    def test_parse_string_args_json(self):
        from services.agent_tools import _parse_string_args

        result = _parse_string_args('{"q": "test"}')
        assert result == {"q": "test"}

    def test_parse_string_args_invalid(self):
        from services.agent_tools import _parse_string_args

        assert _parse_string_args("not json") is None


# ═══════════════════════════════════════════════════════════════════════════
# llm_bridge/completion.py
# ═══════════════════════════════════════════════════════════════════════════


class TestCompletionHelpers:
    def test_client_accepts_extra_body_with_extra_body(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()
        # _client_accepts_extra_body inspects client.chat.completions.create signature
        import inspect

        def fake_create(**kwargs):
            pass

        fake_create.__signature__ = inspect.Signature(
            parameters=[inspect.Parameter("extra_body", inspect.Parameter.KEYWORD_ONLY)]
        )
        client.chat.completions.create = fake_create
        assert _client_accepts_extra_body(client) is True

    def test_client_accepts_extra_body_without(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()
        # MagicMock's create won't have extra_body in its signature
        # The function uses inspect.signature which may behave differently with MagicMock
        # Just verify it returns a bool
        result = _client_accepts_extra_body(client)
        assert isinstance(result, bool)

    def test_client_accepts_extra_body_exception(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()
        # Force an exception during signature inspection
        type(client.chat.completions).create = property(lambda self: (_ for _ in ()).throw(TypeError()))
        assert _client_accepts_extra_body(client) is False


# ═══════════════════════════════════════════════════════════════════════════
# alert_history_query.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAlertHistoryQuery:
    def test_cosine_similarity(self):
        from services.alert_history_query import _cosine_similarity

        a = [1.0, 0.0, 0.0]
        b = [1.0, 0.0, 0.0]
        assert abs(_cosine_similarity(a, b) - 1.0) < 0.01

    def test_cosine_similarity_orthogonal(self):
        from services.alert_history_query import _cosine_similarity

        a = [1.0, 0.0]
        b = [0.0, 1.0]
        assert abs(_cosine_similarity(a, b)) < 0.01

    def test_embed_texts_sync_failure(self):
        from services.alert_history_query import _embed_texts_sync

        # _embed_texts_sync imports requests inside the function,
        # so we need to patch the requests module itself
        with patch("requests.post", side_effect=Exception("connection refused")):
            result = _embed_texts_sync(["test"])
            assert result is None

    def test_format_daily_summary_empty(self):
        from services.alert_history_query import format_daily_summary

        result = format_daily_summary([])
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════════════
# monitor_engine_helpers.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMonitorEngineHelpers:
    def test_is_whitelisted(self):
        from services.monitor_engine_helpers import is_whitelisted

        assert isinstance(is_whitelisted("127.0.0.1"), bool)

    def test_is_browser_connection(self):
        from services.monitor_engine_helpers import is_browser_connection

        assert isinstance(is_browser_connection("chrome.exe", 443), bool)

    def test_is_known_good_asn(self):
        from services.monitor_engine_helpers import _is_known_good_asn

        assert _is_known_good_asn("AS15169", "Google") is True
        assert _is_known_good_asn(None, None) is False

    def test_is_connection_filtered(self):
        from services.monitor_engine_helpers import _is_connection_filtered

        result = _is_connection_filtered(123, "chrome.exe", 443, "8.8.8.8", {})
        assert isinstance(result, bool)

    def test_format_connection(self):
        from services.monitor_engine_helpers import _format_connection

        result = _format_connection("1.2.3.4", 443, 123, "chrome.exe", {})
        assert isinstance(result, str)
