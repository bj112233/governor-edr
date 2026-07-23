# tests/test_two_stage_classifier.py
"""Two-Stage Classifier tests — secondary keywords require context modifiers.

Prevents false positives like "נתניהו בחיפה" (location without security
context) while keeping true alerts like "אזעקה בחיפה" (location + context).
"""

import re

import pytest

from services.breaking_news.filtering import filter_by_keywords


def _build_regexes(urgent, secondary, context):
    """Build the three regexes the same way config.py does."""
    prefix = r"(?:^|\s|[בהולמשכ])"
    suffix = r'(?:\s|[.,:;?!\'"\-]|$)'
    kw_re = re.compile(f"{prefix}({'|'.join(map(re.escape, urgent))}){suffix}", re.IGNORECASE)
    sec_re = re.compile(f"^({'|'.join(map(re.escape, secondary))})$", re.IGNORECASE) if secondary else None
    ctx_re = re.compile(f"(?:{'|'.join(map(re.escape, context))})", re.IGNORECASE) if context else None
    return kw_re, sec_re, ctx_re


# Realistic config subsets
_URGENT = ["חיפה", "ירושלים", "פיגוע", "מחבל", "אזעקה", "חיסול", "איראן", "מלחמה"]
_SECONDARY = ["חיפה", "ירושלים", "איראן"]
_CONTEXT = ["אזעק", "פיגוע", "מחבל", "חיסול", "ירי", "נפיל", "התקפ", "רקט", "טיל"]


class TestTwoStageClassifier:
    """Verify secondary keywords are dropped without context modifiers."""

    @pytest.fixture
    def regexes(self):
        return _build_regexes(_URGENT, _SECONDARY, _CONTEXT)

    def test_primary_keyword_passes(self, regexes):
        """Primary keyword (פיגוע) always triggers — no context needed."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1
        assert result[0]["matched_keyword"] == "פיגוע"

    def test_secondary_without_context_dropped(self, regexes):
        """Secondary keyword (חיפה) without context modifier → dropped."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "נתניהו בבסיס חיל הים בחיפה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0, f"Should drop false positive, got {len(result)}"

    def test_secondary_with_context_passes(self, regexes):
        """Secondary keyword (חיפה) WITH context modifier (אזעקה) → passes."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "אזעקה בחיפה, יירוט רקטה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        # אזעקה is primary → passes immediately; חיפה would be secondary
        assert len(result) >= 1

    def test_jerusalem_without_context_dropped(self, regexes):
        """'בירושלים עוקבים בדאגה' → ירושלים is secondary, no context → dropped."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "בירושלים עוקבים בדאגה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0

    def test_iran_without_context_dropped(self, regexes):
        """'טראמפ מודה לארדואן: תודה שלא התערבת בעימות בין ישראל לאיראן' → dropped."""
        kw_re, sec_re, ctx_re = regexes
        items = [
            {"title": "טראמפ מודה לארדואן: תודה שלא התערבת בעימות בין ישראל לאיראן", "summary": "", "source": "test"}
        ]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0

    def test_iran_with_context_passes(self, regexes):
        """'תקיפה באיראן' → איראן is secondary but תקיפ is context → passes."""
        kw_re, sec_re, ctx_re = regexes
        # Need תקיפ in context list — add it
        ctx_re_with_takif = re.compile(r"(?:תקיפ|אזעק|פיגוע|מחבל|חיסול|ירי|נפיל|התקפ|רקט|טיל)", re.IGNORECASE)
        items = [{"title": "תקיפה באיראן לפני שעה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re_with_takif)
        assert len(result) == 1

    def test_no_secondary_regex_backward_compat(self, regexes):
        """Without secondary_regex, all matches pass (backward compat)."""
        kw_re, _, _ = regexes
        items = [{"title": "נתניהו בחיפה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, secondary_regex=None, context_regex=None)
        assert len(result) == 1, "Without two-stage, old behavior preserved"

    def test_no_context_regex_backward_compat(self, regexes):
        """With secondary_regex but no context_regex, secondary keywords pass."""
        kw_re, sec_re, _ = regexes
        items = [{"title": "נתניהו בחיפה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, context_regex=None)
        assert len(result) == 1, "Without context_regex, secondary passes (safe default)"

    def test_football_in_haifa_dropped(self, regexes):
        """'משחק כדורגל סוער בחיפה' → חיפה secondary, no context → dropped."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "משחק כדורגל סוער בחיפה", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0

    def test_stabbing_in_jerusalem_passes(self, regexes):
        """'פיגוע דקירה בירושלים' → פיגוע is primary → passes immediately."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "פיגוע דקירה בירושלים", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1
        assert result[0]["matched_keyword"] == "פיגוע"

    def test_context_in_summary_not_title(self, regexes):
        """Context modifier in summary (not title) still counts."""
        kw_re, sec_re, ctx_re = regexes
        items = [{"title": "חיפה", "summary": "דיווח על יירוט רקטה", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1, "Context in summary should amplify secondary in title"
