"""Tests for freshness filter, cross-cycle title dedup, and actor-required clustering.

Covers the four fixes after commit 9924ddb:
1. Freshness gate — stale items (>60 min) rejected before keyword matching.
2. Actor-required clustering — no actor → singleton (prevents 15 different
   "תקיפה_כללית|איראן|" headlines merging into one cluster).
3. Cross-cycle title dedup — is_title_sent wired into link_dedup.
4. Context modifier coverage — תוקפ/תקוף stems catch active-voice verbs.
"""

import re
import time

import pytest

from services.breaking_news.dedup import cluster_dedup, link_dedup
from services.breaking_news.filtering import _title_signature, filter_by_keywords
from services.breaking_news.state import MonitorState

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _build_regexes(urgent, secondary, context):
    prefix = r"(?:^|\s|[בהולמשכ])"
    suffix = r'(?:\s|[.,:;?!\'"\-]|$)'
    kw_re = re.compile(f"{prefix}({'|'.join(map(re.escape, urgent))}){suffix}", re.IGNORECASE)
    sec_re = re.compile(f"^({'|'.join(map(re.escape, secondary))})$", re.IGNORECASE) if secondary else None
    ctx_re = re.compile(f"(?:{'|'.join(map(re.escape, context))})", re.IGNORECASE) if context else None
    return kw_re, sec_re, ctx_re


_URGENT = ["חיפה", "ירושלים", "פיגוע", "מחבל", "אזעקה", "חיסול", "איראן", "מלחמה", "תקיפה"]
_SECONDARY = ["חיפה", "ירושלים", "איראן"]
_CONTEXT = ["אזעק", "פיגוע", "מחבל", "חיסול", "ירי", "נפיל", "התקפ", "תוקפ", "תקף", "רקט", "טיל", "תקיפ"]


# ─── 1. Freshness filter ─────────────────────────────────────────────────────


class TestFreshnessFilter:
    """Stale items (>60 min) must be rejected before keyword matching."""

    def test_fresh_item_passes(self):
        """Item published 5 min ago → passes freshness gate."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 300))
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test", "published": now_iso}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1

    def test_stale_item_dropped(self):
        """Item published 3 hours ago → dropped by freshness gate."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        old_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 10800))
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test", "published": old_iso}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0, "Stale item (>60 min) should be dropped"

    def test_no_published_field_passes(self):
        """Item without published field → None epoch → passes (backward compat)."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1

    def test_boundary_59_min_passes(self):
        """Item published 59 min ago → still fresh, passes."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 59 * 60))
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test", "published": now_iso}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1

    def test_boundary_61_min_dropped(self):
        """Item published 61 min ago → stale, dropped."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        old_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() - 61 * 60))
        items = [{"title": "פיגוע דקירה בתל אביב", "summary": "", "source": "test", "published": old_iso}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 0


# ─── 2. Actor-required clustering ────────────────────────────────────────────


class TestActorRequiredClustering:
    """No actor → singleton. Prevents merging unrelated events with same type+location."""

    def test_no_actor_singleton(self):
        """Two items with same type+location but no actor → 2 singletons, not 1 cluster."""
        state = MonitorState()
        now = time.time()
        items = [
            {"title": "תקיפה באיראן: דיווח על פיצוצים", "summary": "", "source": "A", "link": "a1"},
            {"title": 'תקיפה באיראן: צבא ארה"ב מאשר', "summary": "", "source": "B", "link": "b1"},
        ]
        clusters = cluster_dedup(items, state, now)
        assert len(clusters) == 2, f"Without actor, each item should be singleton, got {len(clusters)}"

    def test_with_actor_clusters(self):
        """Two items with same type+location+actor → 1 cluster (corroboration)."""
        state = MonitorState()
        now = time.time()
        items = [
            {"title": 'צה"ל תקף באיראן', "summary": "", "source": "A", "link": "a1"},
            {"title": 'צה"ל תקף באיראן הלילה', "summary": "", "source": "B", "link": "b1"},
        ]
        clusters = cluster_dedup(items, state, now)
        assert len(clusters) == 1, f"Same actor+type+loc should cluster, got {len(clusters)}"

    def test_different_actors_separate(self):
        """Same type+location but different actors → 2 clusters."""
        state = MonitorState()
        now = time.time()
        items = [
            {"title": 'צה"ל תקף באיראן', "summary": "", "source": "A", "link": "a1"},
            {"title": "חמאס תקף באיראן", "summary": "", "source": "B", "link": "b1"},
        ]
        clusters = cluster_dedup(items, state, now)
        assert len(clusters) == 2


# ─── 3. Cross-cycle title dedup ──────────────────────────────────────────────


class TestCrossCycleTitleDedup:
    """is_title_sent wired into link_dedup — catches same headline, different link."""

    def test_same_title_different_link_dropped(self):
        """Same title signature but different link → dropped by title dedup."""
        state = MonitorState()
        now = time.time()
        state.add_sent("https://t.me/ramreports/100", _title_signature("פיגוע בירושלים"), now)
        # Different link (new Telegram message ID), same title
        items = [{"title": "פיגוע בירושלים", "summary": "", "source": "TG", "link": "https://t.me/ramreports/200"}]
        result = link_dedup(items, state)
        assert len(result) == 0, "Same title (different link) should be caught by title dedup"

    def test_different_title_different_link_passes(self):
        """Different title + different link → passes."""
        state = MonitorState()
        now = time.time()
        state.add_sent("https://t.me/ramreports/100", _title_signature("פיגוע בירושלים"), now)
        items = [
            {"title": "רקטה נורתה לעבר תל אביב", "summary": "", "source": "TG", "link": "https://t.me/ramreports/200"}
        ]
        result = link_dedup(items, state)
        assert len(result) == 1

    def test_same_link_dropped(self):
        """Same link → dropped (existing behavior, unchanged)."""
        state = MonitorState()
        now = time.time()
        state.add_sent("https://t.me/ramreports/100", _title_signature("פיגוע בירושלים"), now)
        items = [{"title": "פיגוע בירושלים", "summary": "", "source": "TG", "link": "https://t.me/ramreports/100"}]
        result = link_dedup(items, state)
        assert len(result) == 0


# ─── 4. Context modifier coverage ────────────────────────────────────────────


class TestContextModifierCoverage:
    """תוקפ/תקוף stems catch active-voice verbs (תוקפת/נתקף)."""

    def test_tokef_active_voice_passes(self):
        """'איראן תוקפת במפרץ' → תוקפ stem matches → secondary איראן passes."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        items = [{"title": "איראן תוקפת במפרץ", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1, "תוקפ stem should match תוקפת (active voice)"

    def test_nitkaf_passive_passes(self):
        """'נתקף באיראן' → תקוף stem matches → secondary איראן passes."""
        kw_re, sec_re, ctx_re = _build_regexes(_URGENT, _SECONDARY, _CONTEXT)
        items = [{"title": "בסיס נתקף באיראן", "summary": "", "source": "test"}]
        result = filter_by_keywords(items, kw_re, sec_re, ctx_re)
        assert len(result) == 1, "תקוף stem should match נתקף (passive voice)"
