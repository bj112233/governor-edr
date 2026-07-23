# tests/test_threat_score_parser.py
"""Regression: THREAT_SCORE parser must handle XML tags + liberal fallback.

Bug: The 4B model often ignores the requested format and writes
"Threat Score: 0.8" or "ציון איום: 85" instead of "THREAT_SCORE: 0.8".
The old single-regex parser failed on all variants, returning 0.1
(analysis failure) even when the agent produced a valid report.

Fix: Two-layer parser — XML tag first (<SCORE>0.8</SCORE>), then
liberal fallback (any number near score keywords). Auto-corrects
values >1.0 (e.g. 85 → 0.85).
"""

from services.hunt_prompt import extract_threat_score as _extract_threat_score

# ── XML tag (primary path) ──


def test_xml_tag_exact():
    assert _extract_threat_score("Report...\n<SCORE>0.8</SCORE>") == 0.8


def test_xml_tag_with_spaces():
    assert _extract_threat_score("<SCORE> 0.3 </SCORE>") == 0.3


def test_xml_tag_case_insensitive():
    assert _extract_threat_score("<score>0.5</score>") == 0.5


def test_xml_tag_zero():
    assert _extract_threat_score("<SCORE>0.0</SCORE>") == 0.0


def test_xml_tag_one():
    assert _extract_threat_score("<SCORE>1.0</SCORE>") == 1.0


# ── Liberal fallback (old format variants) ──


def test_threat_score_colon_format():
    assert _extract_threat_score("THREAT_SCORE: 0.7") == 0.7


def test_threat_score_space_format():
    assert _extract_threat_score("Threat Score: 0.4") == 0.4


def test_hebrew_score_format():
    assert _extract_threat_score("ציון איום: 0.6") == 0.6


def test_hebrew_score_short():
    assert _extract_threat_score("ציון: 0.2") == 0.2


def test_english_score_lowercase():
    assert _extract_threat_score("threat score: 0.9") == 0.9


# ── Auto-correction (model writes 85 instead of 0.85) ──


def test_auto_correct_two_digit():
    assert _extract_threat_score("<SCORE>85</SCORE>") == 0.85


def test_auto_correct_single_digit():
    assert _extract_threat_score("<SCORE>8</SCORE>") == 0.8


def test_auto_correct_three_digit():
    assert _extract_threat_score("<SCORE>100</SCORE>") == 1.0


def test_auto_correct_fallback_path():
    assert _extract_threat_score("Threat Score: 75") == 0.75


# ── Fallback (no score found) ──


def test_no_score_returns_fallback():
    assert _extract_threat_score("Just a report with no score") == 0.1


def test_empty_string():
    assert _extract_threat_score("") == 0.1


# ── Edge cases ──


def test_score_in_middle_of_text():
    assert _extract_threat_score("Analysis done. <SCORE>0.35</SCORE> End.") == 0.35


def test_xml_takes_priority_over_fallback():
    """If both XML and keyword exist, XML wins."""
    text = "THREAT_SCORE: 0.9\n<SCORE>0.3</SCORE>"
    assert _extract_threat_score(text) == 0.3


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print("OK")
