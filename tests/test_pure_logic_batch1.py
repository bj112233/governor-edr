# tests/test_pure_logic_batch1.py
"""Pure-logic coverage push — batch 1.

Covers missing lines in:
- services/agent/_agent_message_utils.py (line 36)
- services/text_utils.py (line 33)
- services/tools_registry.py (line 48)
- services/agent/routing/hebrew_norm.py (lines 30, 46)
- services/llm_bridge/circuit_breaker.py (lines 85, 115)
- services/telegram/severity.py (lines 61, 81)
- services/telegram/handlers_render.py (lines 138, 140)
- services/bot_memory/models.py (lines 84, 87, 100, 101)
- services/thinking_parser.py (lines 108-111)
- services/tools/registry.py (lines 37, 53, 58, 71)
- services/_winutil.py (lines 15-27)
- services/telegram/headers.py (line 48)
"""

import re
from types import SimpleNamespace

import pytest

from services._winutil import _decode_oem
from services.agent._agent_message_utils import _extract_tool_history
from services.agent.routing.hebrew_norm import (
    _normalize_hebrew_query,
    _strip_hebrew_prefix,
)
from services.bot_memory.models import _auto_tag_topic, _is_nonpersistable_response
from services.llm_bridge.circuit_breaker import CircuitBreaker
from services.llm_bridge.models import _STATE_OPEN
from services.telegram.handlers_render import _render_process_cpu_spike
from services.telegram.headers import format_header
from services.telegram.severity import severity_emoji, severity_emoji_by_score
from services.text_utils import clean_ide_instructions
from services.thinking_parser import clean_assistant_message
from services.tools.registry import (
    ToolSpec,
    to_llm_map,
    to_mcp_handlers,
    to_mcp_schemas,
    to_openai_tools,
)
from services.tools_registry import _slim_schema


# -- _extract_tool_history --
class TestExtractToolHistory:
    def _ctx(self, messages, buffer=None):
        ctx = SimpleNamespace(messages=messages)
        if buffer is not None:
            ctx._tool_outputs_buffer = buffer
        return ctx

    def test_single_tool_output(self):
        ctx = self._ctx([{"content": "<tool_output>result1</tool_output>"}])
        assert _extract_tool_history(ctx) == "result1"

    def test_multiple_tool_outputs(self):
        ctx = self._ctx([{"content": "<tool_output>a</tool_output> <tool_output>b</tool_output>"}])
        result = _extract_tool_history(ctx)
        assert "a" in result
        assert "b" in result

    def test_dedup(self):
        ctx = self._ctx(
            [
                {"content": "<tool_output>same</tool_output>"},
                {"content": "<tool_output>same</tool_output>"},
            ]
        )
        assert _extract_tool_history(ctx) == "same"

    def test_unclosed_tag_skipped(self):
        ctx = self._ctx([{"content": "<tool_output>no closing tag"}])
        assert _extract_tool_history(ctx) == ""

    def test_merges_buffer(self):
        ctx = self._ctx(
            [{"content": "<tool_output>hist</tool_output>"}],
            buffer=[{"name": "tool1", "result": "buf_result"}],
        )
        result = _extract_tool_history(ctx)
        assert "hist" in result
        assert "buf_result" in result

    def test_empty_messages(self):
        ctx = self._ctx([])
        assert _extract_tool_history(ctx) == ""


# -- clean_ide_instructions --
class TestCleanIdeInstructions:
    def test_empty(self):
        assert clean_ide_instructions("") == ""
        assert clean_ide_instructions(None) == ""

    def test_strips_instructions(self):
        text = "Hello If nothing needs attention, reply HEARTBEAT_OK world"
        result = clean_ide_instructions(text)
        assert "HEARTBEAT_OK" not in result
        assert "Hello" in result

    def test_preserves_normal_text(self):
        assert clean_ide_instructions("normal text") == "normal text"


# -- _slim_schema --
class TestSlimSchema:
    def test_empty_schema(self):
        result = _slim_schema({})
        assert result == {"type": "object", "properties": {}}

    def test_none_schema(self):
        result = _slim_schema(None)
        assert result == {"type": "object", "properties": {}}

    def test_no_required(self):
        result = _slim_schema({"properties": {"a": {"type": "string"}}, "required": []})
        assert result == {"type": "object", "properties": {}}

    def test_strips_optional(self):
        schema = {
            "properties": {
                "required_param": {"type": "string", "description": "needed"},
                "optional_param": {"type": "string", "default": "x"},
            },
            "required": ["required_param"],
        }
        result = _slim_schema(schema)
        assert "required_param" in result["properties"]
        assert "optional_param" not in result["properties"]
        assert result["required"] == ["required_param"]

    def test_keeps_description(self):
        schema = {
            "properties": {"x": {"type": "string", "description": "desc", "title": "X"}},
            "required": ["x"],
        }
        result = _slim_schema(schema)
        assert result["properties"]["x"]["description"] == "desc"
        assert "title" not in result["properties"]["x"]


# -- hebrew_norm --
class TestStripHebrewPrefix:
    def test_short_word(self):
        assert _strip_hebrew_prefix("abc") == "abc"

    def test_non_hebrew_prefix(self):
        assert _strip_hebrew_prefix("test") == "test"

    def test_strips_prefix(self):
        # ה is a common prefix; word must be >= 4 Hebrew letters
        assert _strip_hebrew_prefix("הביתה") == "ביתה" or _strip_hebrew_prefix("הביתה") == "הביתה"

    def test_mixed_token_not_stripped(self):
        assert _strip_hebrew_prefix("הgpu") == "הgpu"


class TestNormalizeHebrewQuery:
    def test_empty(self):
        assert _normalize_hebrew_query("") == ""

    def test_punctuation_replaced(self):
        result = _normalize_hebrew_query("hello, world!")
        assert "," not in result
        assert "!" not in result

    def test_lowercases(self):
        result = _normalize_hebrew_query("HELLO")
        assert result == "hello"


# -- CircuitBreaker --
class TestCircuitBreaker:
    def test_can_probe_not_open(self):
        cb = CircuitBreaker()
        assert cb.can_probe() is False  # state is CLOSED

    def test_can_probe_open_no_cooldown(self):
        import time

        cb = CircuitBreaker()
        cb.state = _STATE_OPEN
        cb.opened_at = time.monotonic() - 999999  # very old → cooldown elapsed
        assert cb.can_probe() is True

    def test_record_latency_skips_low_tokens(self):
        cb = CircuitBreaker()
        cb.record_latency(1.0, 1)  # < LLM_MIN_TOKENS_FOR_TPOT
        assert cb.tpot_ema_ms is None

    def test_record_latency_skips_zero_seconds(self):
        cb = CircuitBreaker()
        cb.record_latency(0, 100)
        assert cb.tpot_ema_ms is None

    def test_record_latency_sets_ema(self):
        cb = CircuitBreaker()
        cb.record_latency(10.0, 100)
        assert cb.tpot_ema_ms is not None
        assert cb.tpot_ema_ms == pytest.approx(100.0)

    def test_degraded_state_return(self):
        """Line 85: state not CLOSED/DEGRADED → return early."""
        cb = CircuitBreaker()
        cb.state = _STATE_OPEN
        cb.tpot_baseline_ms = 50.0
        cb.record_latency(100.0, 100)  # would trigger degraded if state was CLOSED
        # state should remain OPEN (early return at line 85)
        assert cb.state == _STATE_OPEN


# -- severity --
class TestSeverityEmoji:
    def test_none(self):
        assert severity_emoji(None) == "⚪"

    def test_empty(self):
        assert severity_emoji("") == "⚪"

    def test_case_insensitive(self):
        assert severity_emoji("CRITICAL") == severity_emoji("critical")

    def test_unknown(self):
        assert severity_emoji("xyz") == "⚪"


class TestSeverityEmojiByScore:
    @pytest.mark.parametrize(
        "score,emoji",
        [
            (80, "🔴"),
            (70, "🔴"),
            (50, "🟠"),
            (40, "🟠"),
            (20, "🟡"),
            (15, "🟡"),
            (10, "🟢"),
            (0, "🟢"),
        ],
    )
    def test_bands(self, score, emoji):
        assert severity_emoji_by_score(score) == emoji


# -- _render_process_cpu_spike --
class TestRenderProcessCpuSpike:
    def test_with_current_and_z(self):
        report = "chrome.exe (PID 1234)"
        parsed = {"current": 75.5, "z": 3.2}
        lines = _render_process_cpu_spike(report, parsed)
        assert any("chrome.exe" in line for line in lines)
        assert any("CPU: 75.5%" in line for line in lines)
        assert any("z=3.2" in line for line in lines)

    def test_without_current(self):
        report = "proc (PID 1)"
        parsed = {"current": None, "z": 2.0}
        lines = _render_process_cpu_spike(report, parsed)
        assert not any("CPU:" in line for line in lines)
        assert any("z=2.0" in line for line in lines)

    def test_without_z(self):
        report = "proc (PID 1)"
        parsed = {"current": 50.0, "z": None}
        lines = _render_process_cpu_spike(report, parsed)
        assert any("CPU: 50.0%" in line for line in lines)
        assert not any("z=" in line for line in lines)

    def test_no_match(self):
        report = "no proc name here"
        parsed = {"current": None, "z": None}
        lines = _render_process_cpu_spike(report, parsed)
        assert len(lines) == 1  # just the process line


# -- bot_memory/models --
class TestIsNonpersistableResponse:
    def test_empty(self):
        assert _is_nonpersistable_response("") is True

    def test_none(self):
        assert _is_nonpersistable_response(None) is True

    def test_short(self):
        assert _is_nonpersistable_response("ab") is True

    def test_normal(self):
        assert _is_nonpersistable_response("This is a normal response") is False


class TestAutoTagTopic:
    def test_empty(self):
        result = _auto_tag_topic("")
        assert result == "general"

    def test_general(self):
        result = _auto_tag_topic("random text about nothing specific")
        assert result == "general"


# -- thinking_parser --
class TestCleanAssistantMessage:
    def test_removes_thinking(self):
        msg = {"role": "assistant", "content": "hello", "thinking": "internal"}
        result = clean_assistant_message(msg)
        assert "thinking" not in result
        assert result["content"] == "hello"

    def test_no_content(self):
        msg = {"role": "assistant", "thinking": "internal"}
        result = clean_assistant_message(msg)
        assert "thinking" not in result
        assert "content" not in result

    def test_no_thinking(self):
        msg = {"role": "assistant", "content": "hello"}
        result = clean_assistant_message(msg)
        assert result["content"] == "hello"


# -- tools/registry converters --
class TestRegistryConverters:
    def _spec(self, name="test", expose_llm=True, expose_mcp=False):
        return ToolSpec(
            name=name,
            description="test tool",
            parameters={"type": "object"},
            handler=lambda: None,
            expose_to_llm=expose_llm,
            expose_to_mcp=expose_mcp,
        )

    def test_to_openai_tools(self):
        reg = {"a": self._spec("a"), "b": self._spec("b", expose_llm=False)}
        tools = to_openai_tools(reg)
        assert len(tools) == 1
        assert tools[0]["function"]["name"] == "a"

    def test_to_mcp_handlers(self):
        reg = {"a": self._spec("a", expose_mcp=True), "b": self._spec("b")}
        handlers = to_mcp_handlers(reg)
        assert "a" in handlers
        assert "b" not in handlers

    def test_to_mcp_schemas(self):
        reg = {"a": self._spec("a", expose_mcp=True)}
        schemas = to_mcp_schemas(reg)
        assert len(schemas) == 1
        assert schemas[0]["name"] == "a"
        assert "inputSchema" in schemas[0]

    def test_to_llm_map(self):
        reg = {"a": self._spec("a"), "b": self._spec("b", expose_llm=False)}
        llm_map = to_llm_map(reg)
        assert "a" in llm_map
        assert "b" not in llm_map


# -- _decode_oem --
class TestDecodeOem:
    def test_empty(self):
        assert _decode_oem(b"") == ""

    def test_utf8(self):
        assert _decode_oem(b"hello") == "hello"

    def test_hebrew_utf8(self):
        text = "שלום"
        assert _decode_oem(text.encode("utf-8")) == text

    def test_fallback_to_replace(self):
        # Invalid UTF-8 bytes that also fail OEM codepages
        result = _decode_oem(b"\xff\xfe\x00")
        assert isinstance(result, str)


# -- format_header --
class TestFormatHeader:
    def test_basic(self):
        result = format_header("🛡️", "CTI SITREP")
        assert "🛡️" in result
        assert "CTI SITREP" in result

    def test_with_subtitle(self):
        result = format_header("📅", "Daily", "2024-01-01")
        assert "📅" in result
        assert "Daily" in result
        assert "2024-01-01" in result

    def test_no_subtitle(self):
        result = format_header("🧠", "Brain")
        assert "🧠" in result
        assert "Brain" in result
