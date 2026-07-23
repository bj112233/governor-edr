# tests/test_memory_summarizer_normalize.py
"""Regression tests for _normalize_profile (schema regression guard + dedup).

Bug (user_profiles id=27 → id=28, 2026-07-16 23:31): the daily merge LLM call
returned a profile with ONLY `preferences` (87 entries, 47 duplicates) and
silently dropped `topics`, `patterns`, `entities` that existed in id=27.
The previous code persisted the LLM output as-is, so a single bad LLM turn
permanently erased three schema fields and bloated `preferences` by 117%.

Fix: _normalize_profile
1. Carries over any canonical key the LLM dropped from `previous`.
2. Dedups each list[str] field preserving first-seen order.
3. Drops unknown keys (keeps persisted schema canonical).
"""

from services.memory_summarizer import _normalize_profile


def test_dropped_keys_carried_over_from_previous():
    previous = {
        "preferences": ["עברית", "דוחות איומים"],
        "topics": ["MITRE ATT&CK", "PowerShell"],
        "patterns": ["חקירה לפני סיכום"],
        "entities": ["KoboldCpp", "T1059.001"],
    }
    new = {"preferences": ["עברית", "ניתוח רשת"]}  # LLM dropped 3 keys

    out = _normalize_profile(new, previous)

    assert set(out.keys()) == {"preferences", "topics", "patterns", "entities"}
    assert out["topics"] == ["MITRE ATT&CK", "PowerShell"]
    assert out["patterns"] == ["חקירה לפני סיכום"]
    assert out["entities"] == ["KoboldCpp", "T1059.001"]
    assert out["preferences"] == ["עברית", "ניתוח רשת"]


def test_dedup_preserves_first_seen_order():
    previous = {"preferences": ["עברית"]}
    # 4× duplication of the same 3 strings (mirrors id=28: 87 entries, 40 unique).
    # `עברית` from previous is NOT carried over because the LLM provided the key
    # (carry-over only fires when the key is dropped entirely).
    new = {
        "preferences": [
            "ניתוח תהליכים (Processes)",
            "ניתוח חיבורי רשת (Network)",
            "זיהוי תהליכים חשודים",
            "ניתוח תהליכים (Processes)",
            "ניתוח חיבורי רשת (Network)",
            "זיהוי תהליכים חשודים",
            "ניתוח תהליכים (Processes)",
            "ניתוח חיבורי רשת (Network)",
        ],
        "topics": [],
        "patterns": [],
        "entities": [],
    }

    out = _normalize_profile(new, previous)

    assert out["preferences"] == [
        "ניתוח תהליכים (Processes)",
        "ניתוח חיבורי רשת (Network)",
        "זיהוי תהליכים חשודים",
    ]


def test_unknown_keys_dropped():
    new = {
        "preferences": ["a"],
        "topics": [],
        "patterns": [],
        "entities": [],
        "rogue_field": ["should be dropped"],
        "version": 99,
    }
    out = _normalize_profile(new, None)
    assert set(out.keys()) == {"preferences", "topics", "patterns", "entities"}


def test_no_previous_no_dropped_keys_warning_path():
    """First-ever run: previous=None, all keys present → empty lists for missing."""
    new = {"preferences": ["a", "a", "b"]}
    out = _normalize_profile(new, None)
    assert out["preferences"] == ["a", "b"]
    assert out["topics"] == []
    assert out["patterns"] == []
    assert out["entities"] == []


def test_string_value_coerced_to_single_element_list():
    """Robustness: LLM occasionally returns a bare string instead of a list."""
    new = {"preferences": "עברית בלבד"}
    out = _normalize_profile(new, None)
    assert out["preferences"] == ["עברית בלבד"]


def test_whitespace_only_entries_dropped():
    new = {"preferences": ["עברית", "   ", "", "ניתוח"]}
    out = _normalize_profile(new, None)
    assert out["preferences"] == ["עברית", "ניתוח"]


def test_non_string_entries_dropped():
    new = {"preferences": ["עברית", 42, None, {"x": 1}, "ניתוח"]}
    out = _normalize_profile(new, None)
    assert out["preferences"] == ["עברית", "ניתוח"]
