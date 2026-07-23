# tests/test_memory_summarizer_json.py
"""Regression tests for _safe_parse_json repetition-loop repair.

Bug (bot.log 2026-06-26 02:30): the 4B model entered a degenerate repetition
loop during daily summarization, repeating the same 10 preferences 19 times
until max_tokens=1024 exhausted. The resulting truncated JSON (no closing
brackets) was unparseable — _try_parse appended ]} but the last string was
unterminated, and _extract_first_dict_block found no closing }.

Fix: _detect_repetition scans for a chunk (30-200 chars) that repeats 3+
times consecutively at any position, truncates after the 2nd occurrence,
closes strings + brackets/braces in correct nesting order, then feeds the
repaired text through the normal parse pipeline.
"""

import asyncio
import json
from unittest.mock import AsyncMock, patch

from services.memory_summarizer_json import _detect_repetition, _safe_parse_json

# ── Regression: response_format must never be passed to the 4B engine ──
# KoboldCpp deterministically collapses to "not json at all {{{" under grammar
# enforcement (6 failures on 2026-07-04). See lessons.md 2026-06-16 + the
# matching Planner guard in test_planner_smoke.py.

# ── Real failure case (truncated from bot.log 2026-06-26 02:30) ──
# The original was 1912 chars with 19 repetitions. This synthetic version
# uses the same structure with enough repetitions to exceed the 200-char
# detection threshold.

_UNIT = '"דוחות מערכת", "מחיר מטבעות דיגיטליים", "כתבות כלכלה בארץ", "שער דולר", "תוכן אבטחת מידע", '
_REAL_REPETITION = (
    '[\n {"preferences": ["תוכן ספורטיבי", "חדשות מהיר", "תקציר כתבות", '
    '"תגובות לוגיות", "מזג אוויר", ' + _UNIT * 6 + '"מחיר מטבע'
)

# ── Real failure case (bot.log 2026-07-09 02:31) ──
# max_tokens=1024 exhausted mid-string inside the entities array. The LLM
# output was 2288 chars, truncated at "נתניה (no closing quote, no closing
# brackets). _try_parse appended ]} but the unterminated string absorbed them.
# Fix: _try_parse now calls _close_open_string before _close_brackets.

_MID_STRING_TRUNCATED = (
    "{\n"
    '  "preferences": ["עברית", "דוחות ציד איומים"],\n'
    '  "topics": ["ציד איומים", "PowerShell"],\n'
    '  "patterns": ["ניתוח תהליכים"],\n'
    '  "entities": [\n'
    '    "Sentinel", "Devin", "powershell.exe", "MITRE ATT&CK",\n'
    '    "T1059.001", "Claude Code", "TRUMP", "נתניה'
)


def test_detect_repetition_real_case():
    """The actual failure case must be detected as a repetition loop."""
    repaired = _detect_repetition(_REAL_REPETITION)
    assert repaired is not None
    # Repaired text must be shorter than original
    assert len(repaired) < len(_REAL_REPETITION)
    # Repaired text must end with valid JSON closing (]}] for [{...}])
    assert repaired.rstrip().endswith("]}]")


def test_safe_parse_json_recovers_from_repetition():
    """Full pipeline: _safe_parse_json must return a valid dict from
    repetition-truncated JSON."""
    result = _safe_parse_json(_REAL_REPETITION)
    assert result is not None
    assert isinstance(result, dict)
    assert "preferences" in result
    prefs = result["preferences"]
    assert isinstance(prefs, list)
    # Should contain the unique preferences (at least the first 10)
    assert "תוכן ספורטיבי" in prefs
    assert "חדשות מהיר" in prefs


# ── Synthetic cases ──


def test_detect_repetition_simple_array():
    """Simple array with repeated elements should be detected."""
    unit = '"alpha", "beta", "gamma", "delta", "epsilon", '
    text = '["start", ' + unit * 6 + '"tru'
    assert len(text) >= 200
    repaired = _detect_repetition(text)
    assert repaired is not None
    # Should be parseable after repair
    import json

    data = json.loads(repaired)
    assert isinstance(data, list)


def test_detect_repetition_no_false_positive_on_normal_json():
    """Normal JSON without repetition must NOT trigger the detector."""
    normal = '{"name": "test", "value": 42, "items": ["a", "b", "c"]}'
    assert _detect_repetition(normal) is None


def test_detect_repetition_short_text_ignored():
    """Text shorter than 200 chars should not trigger detection."""
    short = '["a", "b", "a", "b", "a", "b"]'
    assert _detect_repetition(short) is None


def test_safe_parse_json_normal_json_unaffected():
    """Normal valid JSON must pass through the repetition layer unchanged."""
    normal = '{"preferences": ["sports", "news"], "version": 1}'
    result = _safe_parse_json(normal)
    assert result == {"preferences": ["sports", "news"], "version": 1}


def test_safe_parse_json_mid_string_truncation():
    """Mid-string truncation (max_tokens exhaustion) must be repaired.

    Regression for bot.log 2026-07-09 02:31: the 4B model's output was cut
    at "נתניה (no closing quote). _try_parse must close the string, then
    close brackets/braces, yielding a valid dict with all completed keys.
    """
    result = _safe_parse_json(_MID_STRING_TRUNCATED)
    assert result is not None
    assert isinstance(result, dict)
    assert result["preferences"] == ["עברית", "דוחות ציד איומים"]
    assert result["topics"] == ["ציד איומים", "PowerShell"]
    assert result["patterns"] == ["ניתוח תהליכים"]
    entities = result["entities"]
    assert isinstance(entities, list)
    # The truncated last entity "נתניה" should be preserved as a string
    assert "Sentinel" in entities
    assert "Devin" in entities
    assert entities[-1] == "נתניה"


def test_detect_repetition_nested_structure():
    """Repetition inside a nested array within a dict within an array."""
    unit = '"item_one", "item_two", "item_three", "item_four", '
    text = '[{"prefs": ["first", "second", ' + unit * 6 + '"tru'
    assert len(text) >= 200
    repaired = _detect_repetition(text)
    assert repaired is not None
    import json

    data = json.loads(repaired)
    assert isinstance(data, list)
    assert data[0]["prefs"][0] == "first"


async def test_run_daily_summarization_no_response_format():
    """Regression: response_format=json_object MUST NOT be passed to the 4B engine.

    KoboldCpp deterministically collapses to "not json at all {{{" under grammar
    enforcement (6 failures on 2026-07-04). See lessons.md 2026-06-16 and the
    matching Planner regression guard in test_planner_smoke.py.
    """
    from services import memory_summarizer as ms

    captured: dict = {}
    profile = '{"preferences": [], "topics": [], "patterns": [], "entities": []}'

    class CapturingBridge:
        async def complete(self, **kwargs):
            captured.update(kwargs)
            return profile

    with (
        patch.object(ms, "_fetch_last_24h_conversations", new=AsyncMock(return_value=["user: hi"])),
        patch.object(ms, "_fetch_latest_profile", new=AsyncMock(return_value=None)),
        patch.object(ms, "LLMBridge") as MockBridge,
    ):
        MockBridge.get_instance.return_value = CapturingBridge()
        with patch.object(ms, "get_memory_pool") as MockPool:
            MockPool.return_value.acquire.return_value.__aenter__ = AsyncMock()
            MockPool.return_value.acquire.return_value.__aexit__ = AsyncMock()
            await ms.run_daily_summarization()

    assert "response_format" not in captured, (
        "MEMORY SUMMARIZER REGRESSION: response_format must NEVER be set "
        "(KoboldCpp 4B grammar enforcement breaks JSON — see lessons.md 2026-06-16)"
    )


if __name__ == "__main__":
    test_detect_repetition_real_case()
    test_safe_parse_json_recovers_from_repetition()
    test_detect_repetition_simple_array()
    test_detect_repetition_no_false_positive_on_normal_json()
    test_detect_repetition_short_text_ignored()
    test_safe_parse_json_normal_json_unaffected()
    test_detect_repetition_nested_structure()
    test_safe_parse_json_mid_string_truncation()
    asyncio.run(test_run_daily_summarization_no_response_format())
    print("OK")
