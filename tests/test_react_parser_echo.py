# tests/test_react_parser_echo.py
"""Regression tests for <tool_output> echo detection in ReAct parser.

Bug: when the model echoes a <tool_output> block verbatim instead of
synthesizing an answer, the parser detected it but didn't signal it
to the executor. The executor's echo check tested _fallback_text (raw
tool data WITHOUT the <tool_output> wrapper) so it never matched,
causing the echo to fall through to termination fallback and send raw
data as the answer instead of nudging for synthesis.

Fix: parser sets result["echo_detected"] = True; executor checks it.
"""

from services.agent._react_parser import parse_react_response


def test_echo_detected_flag_set_on_tool_output_echo():
    """Parser must set echo_detected=True when model echoes <tool_output>."""
    result = parse_react_response("<tool_output>\nעומסי מערכת:\n🟢 CPU: 1%\n")
    assert result.get("echo_detected") is True
    assert result["tool_calls"] == []  # not salvaged


def test_echo_detected_not_set_on_normal_text():
    """Normal text without <tool_output> must NOT set echo_detected."""
    result = parse_react_response("Thought: Need data.\nAction: get_system_snapshot\nAction Input: {}")
    assert result.get("echo_detected") is not True
    assert len(result["tool_calls"]) == 1


def test_echo_detected_not_set_on_plain_answer():
    """Plain text answer (no ReAct, no echo) should be salvaged, not flagged."""
    result = parse_react_response("המערכת תקינה, אין בעיות.")
    assert result.get("echo_detected") is not True
    # Plain text is salvaged to final_answer
    assert len(result["tool_calls"]) == 1
    assert result["tool_calls"][0]["name"] == "final_answer"


def test_thinking_final_answer_without_input_does_not_salvage_planning():
    """Internal <thinking> planning must not become final_answer text."""
    result = parse_react_response("<thinking>I will structure the Hebrew report.</thinking>\nAction: final_answer")
    assert result["tool_calls"] == [{"name": "final_answer", "arguments": {}}]


def test_explicit_thought_final_answer_without_input_still_salvages():
    """Explicit Thought: synthesis remains a valid salvage source."""
    result = parse_react_response("Thought: דוח עברי מלא\nAction: final_answer")
    assert result["tool_calls"] == [{"name": "final_answer", "arguments": {"text": "דוח עברי מלא"}}]


def test_explicit_thought_takes_precedence_over_thinking_tag():
    """When both exist, Thought: is the salvage source, not <thinking>."""
    result = parse_react_response("<thinking>internal plan</thinking>\nThought: דוח עברי מלא\nAction: final_answer")
    assert result["thought"] == "דוח עברי מלא"
    assert result["tool_calls"] == [{"name": "final_answer", "arguments": {"text": "דוח עברי מלא"}}]


def test_echo_with_leading_whitespace():
    """Echo detection must handle leading whitespace before <tool_output>."""
    result = parse_react_response("  <tool_output>\nנתונים\n")
    assert result.get("echo_detected") is True


def test_echo_with_error_message_inside():
    """Echo containing an error message must still be flagged as echo."""
    result = parse_react_response(
        "<tool_output>\n**🔴 שגיאה במערכת!**\n```\n❌ צווחה: 'get_listening_ports' לא מוגדר\n```\n</tool_output>"
    )
    assert result.get("echo_detected") is True
    assert result["tool_calls"] == []
