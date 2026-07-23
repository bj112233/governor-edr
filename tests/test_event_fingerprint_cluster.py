# tests/test_event_fingerprint_cluster.py
"""Tests for Event Fingerprint Clustering — the replacement for the dead
embeddings-based semantic dedup.

Covers:
- fingerprint.py: deterministic entity extraction (event_type, location, actor)
- state.py: EventCluster + sliding-window validation
- dedup.py: cluster_dedup consolidates cross-feed reports of the same event
- dispatch.py: format_cluster_alert consolidated format with corroboration count
"""

import time

import pytest

from services.breaking_news.fingerprint import EventFingerprint, extract_fingerprint
from services.breaking_news.state import (
    CLUSTER_STALE_SECONDS,
    CLUSTER_WINDOW_SECONDS,
    EventCluster,
    MonitorState,
)

# ═══════════════════════════════════════════════════════════════════════════
# fingerprint.py — entity extraction
# ═══════════════════════════════════════════════════════════════════════════


class TestFingerprintExtraction:
    """Deterministic entity extraction from titles."""

    def test_stabbing_attack_extracts_all_three(self):
        fp = extract_fingerprint("פיגוע דקירה בירושלים: מחבל דקר אזרח")
        assert fp.event_type == "פיגוע_דקירה"
        assert fp.location == "ירושלים"
        assert fp.actor == "מחבל"

    def test_air_force_training_extracts_type_and_actor(self):
        fp = extract_fingerprint('דובר צה"ל: השבוע יערכו אימוני חיל האוויר בשמי באר שבע')
        assert fp.event_type == "אימון_צבאי"
        assert fp.actor == "צהל"
        assert fp.location == "באר_שבע"

    def test_hezbollah_lebanon_strike(self):
        """צה"ל strikes Hezbollah in Lebanon — actor is צה"ל (the striker)."""
        fp = extract_fingerprint('צה"ל תקף חוליית מחבלי חיזבאללה בלבנון')
        assert fp.event_type == "תקיפה_צבאית"
        assert fp.location == "לבנון"
        assert fp.actor == "צהל"  # צה"ל is the actor (striker), חיזבאללה is the target

    def test_weapons_cache_discovery(self):
        """The exact log-proven duplicate: '150 אמצעי לחימה אותרו בכפר חדאת'."""
        fp1 = extract_fingerprint('צה"ל: יותר מ־150 אמצעי לחימה אותרו במרחב הכפר חדאת')
        fp2 = extract_fingerprint('צה"ל: יותר מ-150 אמצעי לחימה אותרו במרחב הבטחוני בכפר חדאת')
        assert fp1.key == fp2.key, "Same event with different wording must produce same fingerprint"

    def test_different_events_different_fingerprints(self):
        """Beirut strike vs Haifa strike — different location+actor → different keys."""
        fp1 = extract_fingerprint('צה"ל תקף בביירות')
        fp2 = extract_fingerprint("חיזבאללה תקף בחיפה")
        assert fp1.key != fp2.key
        assert fp1.location == "לבנון"
        assert fp2.location == "חיפה"
        assert fp1.actor == "צהל"
        assert fp2.actor == "חיזבאללה"

    def test_different_cities_different_fingerprints(self):
        """Sirens in Sderot vs Ashkelon — different locations → different keys."""
        fp1 = extract_fingerprint("אזעקה בשדרות")
        fp2 = extract_fingerprint("אזעקה באשקלון")
        assert fp1.key != fp2.key

    def test_empty_title_yields_empty_fingerprint(self):
        fp = extract_fingerprint("")
        assert fp.is_empty

    def test_no_match_yields_empty_fingerprint(self):
        fp = extract_fingerprint("מזג האוויר מחר יהיה נעים")
        assert fp.is_empty

    def test_fingerprint_is_hashable_and_stable(self):
        fp = extract_fingerprint("פיגוע דקירה בירושלים")
        assert isinstance(fp.key, str)
        assert len(fp.key) == 16
        # Same input → same key
        fp2 = extract_fingerprint("פיגוע דקירה בירושלים")
        assert fp.key == fp2.key

    def test_summary_fallback_for_event_type(self):
        """When title has no event verb but summary does, summary is consulted."""
        fp = extract_fingerprint("חדשות מהזירה", summary="פיגוע דקירה בירושלים")
        assert fp.event_type == "פיגוע_דקירה"

    def test_multi_word_phrase_takes_precedence(self):
        """פיגוע דקירה should match before דקירה (more specific first)."""
        fp = extract_fingerprint("פיגוע דקירה בשוק")
        assert fp.event_type == "פיגוע_דקירה"

    def test_frozen_dataclass(self):
        """EventFingerprint must be hashable/immutable."""
        fp = extract_fingerprint("פיגוע בירושלים")
        with pytest.raises(AttributeError):
            fp.event_type = "other"  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════
# state.py — EventCluster
# ═══════════════════════════════════════════════════════════════════════════


class TestEventCluster:
    """EventCluster properties — corroboration, best_item, best_image."""

    def test_corroboration_count_single_source(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "link": "L1"}, now=1000.0)
        assert c.corroboration_count == 1

    def test_corroboration_count_multi_source(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "link": "L1"}, now=1000.0)
        c.add({"source": "Walla", "title": "T2", "link": "L2"}, now=1001.0)
        c.add({"source": "Ynet", "title": "T3", "link": "L3"}, now=1002.0)  # dup source
        assert c.corroboration_count == 2  # Ynet + Walla

    def test_source_names_distinct_ordered(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1"}, now=1000.0)
        c.add({"source": "Walla", "title": "T2"}, now=1001.0)
        c.add({"source": "Maariv", "title": "T3"}, now=1002.0)
        assert c.source_names == ["Ynet", "Walla", "Maariv"]

    def test_best_item_prefers_rss_image(self):
        c = EventCluster(fingerprint_key="k1")
        c.add(
            {"source": "Ynet", "title": "Short", "link": "L1", "_image_from_rss": False, "image": "favicon"}, now=1000.0
        )
        c.add(
            {
                "source": "Walla",
                "title": "Longer title here",
                "link": "L2",
                "_image_from_rss": True,
                "image": "real_photo.jpg",
            },
            now=1001.0,
        )
        best = c.best_item
        assert best["source"] == "Walla"  # Has real RSS image

    def test_best_item_longest_title_when_no_rss_image(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "Short", "link": "L1", "_image_from_rss": False}, now=1000.0)
        c.add(
            {"source": "Walla", "title": "Much longer title with more detail", "link": "L2", "_image_from_rss": False},
            now=1001.0,
        )
        best = c.best_item
        assert best["source"] == "Walla"  # Longer title

    def test_best_image_prefers_rss_over_favicon(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "_image_from_rss": False, "image": "favicon.ico"}, now=1000.0)
        c.add({"source": "Walla", "title": "T2", "_image_from_rss": True, "image": "real_photo.jpg"}, now=1001.0)
        assert c.best_image == "real_photo.jpg"

    def test_best_image_falls_back_to_favicon(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "_image_from_rss": False, "image": "favicon.ico"}, now=1000.0)
        assert c.best_image == "favicon.ico"

    def test_best_image_empty_when_none(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "image": ""}, now=1000.0)
        assert c.best_image == ""

    def test_all_links(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1", "link": "http://ynet.co.il/1"}, now=1000.0)
        c.add({"source": "Walla", "title": "T2", "link": "http://walla.co.il/2"}, now=1001.0)
        links = c.all_links
        assert len(links) == 2
        assert links[0] == ("Ynet", "http://ynet.co.il/1")
        assert links[1] == ("Walla", "http://walla.co.il/2")

    def test_is_active_within_window(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1"}, now=1000.0)
        assert c.is_active(1000.0 + CLUSTER_WINDOW_SECONDS - 1) is True

    def test_is_active_past_window(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1"}, now=1000.0)
        assert c.is_active(1000.0 + CLUSTER_WINDOW_SECONDS + 1) is False

    def test_is_stale_past_24h(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1"}, now=1000.0)
        assert c.is_stale(1000.0 + CLUSTER_STALE_SECONDS + 1) is True

    def test_is_stale_within_24h(self):
        c = EventCluster(fingerprint_key="k1")
        c.add({"source": "Ynet", "title": "T1"}, now=1000.0)
        assert c.is_stale(1000.0 + CLUSTER_STALE_SECONDS - 1) is False


# ═══════════════════════════════════════════════════════════════════════════
# state.py — MonitorState cluster management
# ═══════════════════════════════════════════════════════════════════════════


class TestMonitorStateClusters:
    """Sliding-window cluster lookup + stale eviction."""

    def test_find_cluster_none_when_empty(self):
        state = MonitorState()
        assert state.find_cluster("k1", now=1000.0) is None

    def test_find_cluster_active(self):
        state = MonitorState()
        state.get_or_create_cluster("k1", now=1000.0)
        assert state.find_cluster("k1", now=1000.0 + 60) is not None

    def test_find_cluster_stale_returns_none(self):
        state = MonitorState()
        state.get_or_create_cluster("k1", now=1000.0)
        # Past stale threshold
        assert state.find_cluster("k1", now=1000.0 + CLUSTER_STALE_SECONDS + 1) is None

    def test_get_or_create_replaces_stale(self):
        state = MonitorState()
        old = state.get_or_create_cluster("k1", now=1000.0)
        old.add({"source": "Ynet", "title": "Old"}, now=1000.0)
        # Way past stale
        new = state.get_or_create_cluster("k1", now=1000.0 + CLUSTER_STALE_SECONDS + 100)
        assert len(new.items) == 0  # Fresh cluster, old one replaced

    def test_add_sent_records_link_and_title(self):
        state = MonitorState()
        state.add_sent("http://link1", "title_sig1", now=1000.0)
        assert state.is_link_sent("http://link1")
        assert state.is_title_sent("title_sig1")

    def test_cleanup_evicts_stale_clusters(self):
        state = MonitorState()
        state.get_or_create_cluster("k1", now=1000.0)
        # Cleanup at now=1000 + TTL → cluster is stale
        state.cleanup(now=1000.0 + 50000)
        assert "k1" not in state.clusters

    def test_cleanup_keeps_active_clusters(self):
        state = MonitorState()
        state.get_or_create_cluster("k1", now=1000.0)
        state.cleanup(now=1100.0)  # 100s later, well within TTL
        assert "k1" in state.clusters


# ═══════════════════════════════════════════════════════════════════════════
# dedup.py — cluster_dedup
# ═══════════════════════════════════════════════════════════════════════════


class TestClusterDedup:
    """Cross-feed consolidation via fingerprint clustering."""

    def test_empty_items(self):
        from services.breaking_news.dedup import cluster_dedup

        state = MonitorState()
        clusters = cluster_dedup([], state, now=1000.0)
        assert clusters == []

    def test_same_event_two_feeds_one_cluster(self):
        """The core use case: Ynet + Walla report the same event → 1 cluster."""
        from services.breaking_news.dedup import cluster_dedup

        state = MonitorState()
        items = [
            {
                "title": 'צה"ל: יותר מ־150 אמצעי לחימה אותרו במרחב הכפר חדאת',
                "source": "Ynet מבזקים",
                "link": "http://ynet/1",
                "summary": "",
            },
            {
                "title": 'צה"ל: יותר מ-150 אמצעי לחימה אותרו במרחב הבטחוני בכפר חדאת',
                "source": "Walla מבזקים",
                "link": "http://walla/1",
                "summary": "",
            },
        ]
        clusters = cluster_dedup(items, state, now=1000.0)
        assert len(clusters) == 1
        assert clusters[0].corroboration_count == 2

    def test_different_events_two_clusters(self):
        from services.breaking_news.dedup import cluster_dedup

        state = MonitorState()
        items = [
            {"title": "פיגוע דקירה בירושלים", "source": "Ynet", "link": "L1", "summary": ""},
            {"title": "רקטה נורתה לעבר אשקלון", "source": "Walla", "link": "L2", "summary": ""},
        ]
        clusters = cluster_dedup(items, state, now=1000.0)
        assert len(clusters) == 2

    def test_no_fingerprint_singleton_clusters(self):
        """Items with no extractable entities get singleton clusters (not merged)."""
        from services.breaking_news.dedup import cluster_dedup

        state = MonitorState()
        items = [
            {"title": "מזג האוויר מחר", "source": "Ynet", "link": "http://L1", "summary": ""},
            {"title": "ספורט: ניצחון גדול", "source": "Walla", "link": "http://L2", "summary": ""},
        ]
        clusters = cluster_dedup(items, state, now=1000.0)
        assert len(clusters) == 2  # Each gets its own singleton

    def test_existing_cluster_appended(self):
        """Second cycle with same event → appends to existing cluster."""
        from services.breaking_news.dedup import cluster_dedup

        state = MonitorState()
        # First cycle — actor required for clustering
        cluster_dedup(
            [{"title": "פיגוע דקירה בירושלים: מחבל דקר אזרח", "source": "Ynet", "link": "L1", "summary": ""}],
            state,
            now=1000.0,
        )
        # Second cycle — same event (same type+location+actor), different feed
        clusters = cluster_dedup(
            [{"title": "מחבל דקר אזרח בירושלים: מצבו קשה", "source": "Walla", "link": "L2", "summary": ""}],
            state,
            now=1100.0,
        )
        assert len(clusters) == 1
        assert clusters[0].corroboration_count == 2  # Ynet + Walla


# ═══════════════════════════════════════════════════════════════════════════
# dispatch.py — format_cluster_alert
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatClusterAlert:
    """Consolidated alert formatting with corroboration count."""

    def test_single_source_no_corroboration_line(self):
        cluster = EventCluster(fingerprint_key="k1")
        cluster.add(
            {"title": "פיגוע בירושלים", "source": "Ynet", "link": "L1", "matched_keyword": "פיגוע", "published": ""},
            now=1000.0,
        )
        message, best_item, image = _format_alert(cluster)
        assert "מקורות מאשרים" not in message
        assert best_item["source"] == "Ynet"

    def test_multi_source_shows_corroboration(self):
        cluster = EventCluster(fingerprint_key="k1")
        cluster.add(
            {"title": "פיגוע בירושלים", "source": "Ynet", "link": "L1", "matched_keyword": "פיגוע", "published": ""},
            now=1000.0,
        )
        cluster.add(
            {"title": "דקירה בירושלים", "source": "Walla", "link": "L2", "matched_keyword": "דקירה", "published": ""},
            now=1001.0,
        )
        message, best_item, image = _format_alert(cluster)
        assert "מקורות מאשרים (2)" in message
        assert "Ynet" in message
        assert "Walla" in message

    def test_html_escaped_title(self):
        cluster = EventCluster(fingerprint_key="k1")
        cluster.add(
            {
                "title": "<script>alert(1)</script>",
                "source": "Ynet",
                "link": "L1",
                "matched_keyword": "פיגוע",
                "published": "",
            },
            now=1000.0,
        )
        message, _, _ = _format_alert(cluster)
        assert "<script>" not in message  # Escaped
        assert "&lt;script&gt;" in message

    def test_best_image_returned(self):
        cluster = EventCluster(fingerprint_key="k1")
        cluster.add(
            {
                "title": "T1",
                "source": "Ynet",
                "link": "L1",
                "_image_from_rss": False,
                "image": "fav.ico",
                "matched_keyword": "פיגוע",
                "published": "",
            },
            now=1000.0,
        )
        cluster.add(
            {
                "title": "T2",
                "source": "Walla",
                "link": "L2",
                "_image_from_rss": True,
                "image": "real.jpg",
                "matched_keyword": "פיגוע",
                "published": "",
            },
            now=1001.0,
        )
        _, _, image = _format_alert(cluster)
        assert image == "real.jpg"


def _format_alert(cluster):
    """Helper — call format_cluster_alert without needing full item fields."""
    from services.breaking_news.dispatch import format_cluster_alert

    return format_cluster_alert(cluster)
