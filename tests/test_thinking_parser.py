# tests/test_thinking_parser.py
"""
Regression tests for services.thinking_parser._extract_final_answer.

Covers the boundary-safety bug where the legacy rfind-based extractor would
mistakenly cut on a substring marker ('תשובה:') appearing mid-paragraph
inside legitimate content.
"""

from services.thinking_parser import (
    _extract_final_answer,
    strip_thinking_content,
)


def test_extract_final_answer_boundary_safety():
    """
    Variant B must ignore in-paragraph 'התשובה:' and only honour the
    start-of-line 'תשובה סופית:' marker.
    """
    test_text = (
        "Thinking: ...\nהניתוח הושלם. לגבי השאלה השנייה שלך, התשובה: לא מצאתי חריגות.\n\nתשובה סופית:\nמערכת תקינה."
    )
    assert _extract_final_answer(test_text).strip() == "מערכת תקינה."


def test_extract_final_answer_longest_marker_wins():
    """'תשובה סופית:' must take precedence over its substring 'תשובה:'."""
    text = "תשובה סופית:\nOK"
    assert _extract_final_answer(text).strip() == "OK"


def test_extract_final_answer_no_marker_returns_input():
    text = "Plain answer without any marker."
    assert _extract_final_answer(text) == text


def test_extract_final_answer_english_marker_start_of_line():
    text = "Reasoning: blah blah.\nFinal Answer:\n42"
    assert _extract_final_answer(text).strip() == "42"


def test_extract_final_answer_inline_marker_ignored():
    """An inline 'Answer: 42' mid-sentence must NOT trigger extraction."""
    text = "The user asked. Answer: 42 was wrong, but here is the real one."
    # No start-of-line marker → return original.
    assert _extract_final_answer(text) == text


def test_strip_thinking_content_integration():
    """End-to-end: <think> block stripped, then start-of-line marker honoured."""
    raw = "<think>internal CoT עם התשובה: 123 בתוך הניתוח</think>\nתשובה סופית:\nהכל בסדר."
    assert strip_thinking_content(raw) == "הכל בסדר."
