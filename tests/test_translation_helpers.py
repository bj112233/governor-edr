# tests/test_translation_handlers.py
"""Tests for _translation_handlers pure-logic functions.

Covers: _truncate_text, _dedupe_parts.
No mocking needed — pure string operations.
"""

from services.agent.bypass._translation_handlers import _dedupe_parts, _truncate_text


class TestTruncateText:
    def test_short_text_not_truncated(self):
        text = "short text"
        result, truncated = _truncate_text(text)
        assert result == "short text"
        assert truncated is False

    def test_long_text_truncated(self):
        text = "x" * 25000
        result, truncated = _truncate_text(text)
        assert len(result) == 24000
        assert truncated is True

    def test_exact_cap_not_truncated(self):
        text = "x" * 24000
        result, truncated = _truncate_text(text)
        assert len(result) == 24000
        assert truncated is False


class TestDedupeParts:
    def test_empty_parts(self):
        assert _dedupe_parts([]) == []

    def test_no_duplicates(self):
        parts = ["part one", "part two", "part three"]
        assert _dedupe_parts(parts) == parts

    def test_exact_duplicates(self):
        parts = ["hello world", "hello world", "hello world"]
        assert _dedupe_parts(parts) == ["hello world"]

    def test_whitespace_normalized(self):
        """Parts differing only in whitespace are deduped."""
        parts = ["hello   world", "hello world", "hello  world"]
        result = _dedupe_parts(parts)
        assert len(result) == 1

    def test_empty_strings_skipped(self):
        parts = ["", "real content", ""]
        assert _dedupe_parts(parts) == ["real content"]

    def test_first_160_chars_key(self):
        """Dedup uses first 160 chars as key."""
        part1 = "x" * 160 + " unique1"
        part2 = "x" * 160 + " unique2"
        result = _dedupe_parts([part1, part2])
        # First 160 chars are identical → deduped
        assert len(result) == 1

    def test_preserves_order(self):
        parts = ["first", "second", "third"]
        assert _dedupe_parts(parts) == ["first", "second", "third"]
