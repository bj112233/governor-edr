# tests/test_error_memory.py
"""Tests for error_memory pure-logic functions.

Covers: _embed_text, format_lessons_for_prompt.
No mocking needed — pure string operations.
"""

from services.error_memory import _embed_text, format_lessons_for_prompt


class TestEmbedText:
    def test_basic(self):
        result = _embed_text("TypeError", "called with None")
        assert "TypeError" in result
        assert "called with None" in result

    def test_strips_whitespace(self):
        result = _embed_text("  Error  ", "  context  ")
        # .strip() on the combined string, but inner whitespace preserved
        assert "Error" in result
        assert "context" in result
        assert not result.startswith(" ")
        assert not result.endswith(" ")

    def test_empty_context(self):
        result = _embed_text("Error", "")
        assert result == "Error"

    def test_both_empty(self):
        assert _embed_text("", "") == ""


class TestFormatLessonsForPrompt:
    def test_empty_returns_empty(self):
        assert format_lessons_for_prompt([]) == ""

    def test_single_lesson(self):
        lessons = [{"error_signature": "TimeoutError", "resolution": "retry with backoff"}]
        result = format_lessons_for_prompt(lessons)
        assert "TimeoutError" in result
        assert "retry with backoff" in result
        assert result.startswith("- When:")

    def test_multiple_lessons(self):
        lessons = [
            {"error_signature": "Error1", "resolution": "Fix1"},
            {"error_signature": "Error2", "resolution": "Fix2"},
        ]
        result = format_lessons_for_prompt(lessons)
        assert "Error1" in result
        assert "Error2" in result
        assert len(result.split("\n")) == 2

    def test_resolution_truncated(self):
        long_res = "x" * 500
        lessons = [{"error_signature": "Err", "resolution": long_res}]
        result = format_lessons_for_prompt(lessons, max_resolution_chars=50)
        assert "…" in result
        assert len(result) < len(long_res)

    def test_signature_truncated(self):
        long_sig = "x" * 200
        lessons = [{"error_signature": long_sig, "resolution": "fix"}]
        result = format_lessons_for_prompt(lessons)
        # Signature truncated to 120 chars
        assert len([ch for ch in result.split("→")[0] if ch == "x"]) <= 120
