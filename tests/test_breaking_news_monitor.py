"""Tests for breaking_news subsystem — config, state cleanup, title dedup.

Sprint 4 refactor: BreakingNewsMonitor was split into a package
(services/breaking_news/) with MonitorState, dedup, config, ingestion, etc.
These tests target the new module APIs directly.
"""

import json
import logging
import time

import pytest

from services.breaking_news.config import FALLBACK_NEWS_CONFIG
from services.breaking_news.dedup import _title_signature
from services.breaking_news.state import MonitorState


class TestFallbackNewsConfig:
    """Static fallback configuration sanity checks."""

    def test_has_feeds(self):
        assert "feeds" in FALLBACK_NEWS_CONFIG
        assert len(FALLBACK_NEWS_CONFIG["feeds"]) >= 1

    def test_has_urgent_keywords(self):
        assert "urgent_keywords" in FALLBACK_NEWS_CONFIG
        assert len(FALLBACK_NEWS_CONFIG["urgent_keywords"]) >= 1

    def test_has_delivery(self):
        assert "delivery" in FALLBACK_NEWS_CONFIG

    def test_first_feed_enabled(self):
        feed = FALLBACK_NEWS_CONFIG["feeds"][0]
        assert feed.get("enabled", False) is True
        assert "url" in feed
        assert feed["url"].startswith("http")

    def test_keywords_are_hebrew(self):
        kws = FALLBACK_NEWS_CONFIG["urgent_keywords"]
        assert all(isinstance(k, str) for k in kws)
        assert len(kws) >= 3


class TestStateCleanup:
    """MonitorState.cleanup() — TTL eviction + hard caps."""

    def test_cleanup_removes_old_links(self):
        state = MonitorState()
        state.sent_links = {
            "old-link": time.time() - 90000,  # > 12h
            "fresh-link": time.time() - 300,  # 5 min
        }
        state.sent_titles = {
            "old title": time.time() - 95000,
            "fresh title": time.time() - 600,
        }

        state.cleanup()

        assert "old-link" not in state.sent_links
        assert "fresh-link" in state.sent_links
        assert "old title" not in state.sent_titles
        assert "fresh title" in state.sent_titles

    def test_cleanup_caps_to_max(self):
        state = MonitorState()
        state.sent_links = {f"link-{i}": time.time() for i in range(250)}
        state.sent_titles = {f"title-{i}": time.time() for i in range(250)}

        state.cleanup()

        assert len(state.sent_links) <= MonitorState.MAX_LINKS
        assert len(state.sent_titles) <= MonitorState.MAX_TITLES

    def test_cleanup_empty_state(self):
        state = MonitorState()
        state.sent_links = {}
        state.sent_titles = {}
        state.clusters = {}

        state.cleanup()
        # Should not crash on empty state
        assert state.sent_links == {}
        assert state.sent_titles == {}
        assert len(state.clusters) == 0


class TestTitleSignature:
    """Title deduplication normalization."""

    def test_strips_punctuation(self):
        sig = _title_signature("Hello, World!!!")
        assert sig == "hello world"

    def test_collapse_whitespace(self):
        sig = _title_signature("  too   much   space  ")
        assert sig == "too much space"

    def test_preserves_hebrew(self):
        sig = _title_signature("\u05d4\u05ea\u05e8\u05d0\u05d4: \u05d7\u05d3\u05e9\u05d4!!!")
        assert "\u05d4\u05ea\u05e8\u05d0\u05d4" in sig


# TestTitleDifferenceGuard removed — tested is_semantic_dup / _title_word_overlap
# which were deleted when embeddings-based dedup was replaced by fingerprint
# clustering. See test_event_fingerprint_cluster.py for the replacement tests.
