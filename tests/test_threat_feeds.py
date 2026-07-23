"""Tests for services/threat_feeds.py — Abuse.ch feed integration."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestCheckTargetInFeeds:
    @pytest.mark.asyncio
    async def test_no_hit_returns_empty(self):
        from services.threat_feeds import check_target_in_feeds

        with patch("services.threat_feeds._fetch_threatfox_sync", return_value=[]):
            with patch("services.threat_feeds._fetch_urlhaus_sync", return_value=[]):
                result = await check_target_in_feeds("1.2.3.4", "ip")
        assert result["matched"] is False
        assert result["threatfox"] is False
        assert result["urlhaus"] is False

    @pytest.mark.asyncio
    async def test_threatfox_hit_returns_malware(self):
        from services.threat_feeds import check_target_in_feeds

        tf_rows = [{"ioc": "1.2.3.4", "ioc_type": "ip:port", "malware_printable": "Emotet", "threat_type": "botnet_cc"}]
        with patch("services.threat_feeds._fetch_threatfox_sync", return_value=tf_rows):
            with patch("services.threat_feeds._fetch_urlhaus_sync", return_value=[]):
                result = await check_target_in_feeds("1.2.3.4", "ip")
        assert result["matched"] is True
        assert result["threatfox"] is True
        assert result["malware"] == "Emotet"
        assert result["threat_type"] == "botnet_cc"

    @pytest.mark.asyncio
    async def test_urlhaus_hit_via_url_substring(self):
        from services.threat_feeds import check_target_in_feeds

        uh_rows = [{"url": "http://evil.com/payload", "threat": "malware_download", "tags": "exe"}]
        with patch("services.threat_feeds._fetch_threatfox_sync", return_value=[]):
            with patch("services.threat_feeds._fetch_urlhaus_sync", return_value=uh_rows):
                result = await check_target_in_feeds("evil.com", "domain")
        assert result["matched"] is True
        assert result["urlhaus"] is True

    @pytest.mark.asyncio
    async def test_threatfox_ip_with_port_stripped(self):
        from services.threat_feeds import check_target_in_feeds

        tf_rows = [{"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "CobaltStrike"}]
        with patch("services.threat_feeds._fetch_threatfox_sync", return_value=tf_rows):
            with patch("services.threat_feeds._fetch_urlhaus_sync", return_value=[]):
                result = await check_target_in_feeds("1.2.3.4", "ip")
        assert result["matched"] is True
        assert result["malware"] == "CobaltStrike"

    @pytest.mark.asyncio
    async def test_feed_error_returns_not_matched(self):
        from services.threat_feeds import check_target_in_feeds

        with patch("services.threat_feeds._fetch_threatfox_sync", side_effect=Exception("network")):
            with patch("services.threat_feeds._fetch_urlhaus_sync", side_effect=Exception("network")):
                result = await check_target_in_feeds("1.2.3.4", "ip")
        assert result["matched"] is False


class TestRefreshFeeds:
    @pytest.mark.asyncio
    async def test_refresh_returns_counts(self):
        from services.threat_feeds import refresh_feeds

        with patch("services.threat_feeds._fetch_urlhaus_sync", return_value=[{"url": "a"}]):
            with patch("services.threat_feeds._fetch_threatfox_sync", return_value=[{"ioc": "b"}]):
                counts = await refresh_feeds()
        assert counts["urlhaus"] == 1
        assert counts["threatfox"] == 1


class TestFeedIntegrationInEnricher:
    """Test that enrich_ip/domain/hash integrate feed hits correctly."""

    @pytest.mark.asyncio
    async def test_enrich_ip_feed_hit_boosts_score(self):
        from services.intel_enricher import enrich_ip

        base_data = {"score": 30, "abuse": {"country": "RU", "isp": "X"}, "virustotal": {"malicious": 0}}
        feed_hit = {
            "matched": True,
            "threatfox": True,
            "urlhaus": False,
            "malware": "Emotet",
            "threat_type": "botnet_cc",
        }
        with patch("services.intel_enricher._lookup_sync", return_value=base_data):
            with patch("services.intel_enricher._IPV4_RE"):
                with patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock) as mock_feed:
                    mock_feed.return_value = feed_hit
                    with patch("services.intel_enricher._VT_CONCURRENCY"):
                        with patch(
                            "services.ioc_memory_store.recall_decayed_score", new_callable=AsyncMock
                        ) as mock_recall:
                            mock_recall.return_value = 0.0
                            with patch("services.ioc_memory_store.save_score", new_callable=AsyncMock):
                                result = await enrich_ip("1.2.3.4")
        assert result is not None
        assert result["score"] == 50  # 30 + 20
        assert result["threat_feeds"]["malware"] == "Emotet"

    @pytest.mark.asyncio
    async def test_enrich_ip_no_feed_hit_no_boost(self):
        from services.intel_enricher import enrich_ip

        base_data = {"score": 10, "abuse": {"country": "US", "isp": "AWS"}, "virustotal": {"malicious": 0}}
        feed_hit = {"matched": False, "threatfox": False, "urlhaus": False, "malware": None, "threat_type": None}
        with patch("services.intel_enricher._lookup_sync", return_value=base_data):
            with patch("services.intel_enricher._IPV4_RE"):
                with patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock) as mock_feed:
                    mock_feed.return_value = feed_hit
                    with patch("services.intel_enricher._VT_CONCURRENCY"):
                        with patch(
                            "services.ioc_memory_store.recall_decayed_score", new_callable=AsyncMock
                        ) as mock_recall:
                            mock_recall.return_value = 0.0
                            with patch("services.ioc_memory_store.save_score", new_callable=AsyncMock):
                                result = await enrich_ip("1.2.3.4")
        assert result is not None
        assert result["score"] == 10  # no boost
        assert "threat_feeds" not in result

    @pytest.mark.asyncio
    async def test_feed_hit_makes_is_clean_false(self):
        from services.intel_enricher import is_clean_enrichment

        data = {"score": 0, "threat_feeds": {"matched": True, "malware": "Emotet"}}
        assert is_clean_enrichment(data) is False

    @pytest.mark.asyncio
    async def test_no_feed_hit_score_zero_is_clean(self):
        from services.intel_enricher import is_clean_enrichment

        data = {"score": 0, "threat_feeds": {"matched": False}}
        assert is_clean_enrichment(data) is True


class TestFeedHitInPreHunt:
    """Test that pre_hunt_enricher treats feed hits as malicious + hard facts stamp."""

    def test_is_malicious_with_feed_hit(self):
        from services.pre_hunt_enricher import _is_malicious

        data = {"score": 10, "threat_feeds": {"matched": True, "malware": "Emotet"}}
        assert _is_malicious(data) is True

    def test_is_malicious_without_feed_hit_low_score(self):
        from services.pre_hunt_enricher import _is_malicious

        data = {"score": 10, "threat_feeds": {"matched": False}}
        assert _is_malicious(data) is False

    def test_format_hard_facts_includes_feed_stamp(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["evil.com"] = {
            "score": 40,
            "virustotal": {"malicious": 0},
            "threat_feeds": {"matched": True, "threatfox": True, "urlhaus": False, "malware": "Emotet"},
        }
        report.ioc_types["evil.com"] = "domain"
        facts = format_hard_facts(report)
        assert "Found in ThreatFox: Emotet" in facts
        assert "MALICIOUS" in facts

    def test_format_hard_facts_no_feed_stamp_when_clean(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["good.com"] = {"score": 0, "virustotal": {"malicious": 0}}
        report.ioc_types["good.com"] = "domain"
        facts = format_hard_facts(report)
        assert "Found in" not in facts
        assert "CLEAN" in facts

    def test_format_hard_facts_both_feeds_stamp(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {
            "score": 60,
            "abuse": {"country": "RU", "isp": "X"},
            "virustotal": {"malicious": 5, "available": True, "found": True},
            "threat_feeds": {"matched": True, "threatfox": True, "urlhaus": True, "malware": "TrickBot"},
        }
        report.ioc_types["1.2.3.4"] = "ip"
        facts = format_hard_facts(report)
        assert "ThreatFox+URLhaus" in facts
        assert "TrickBot" in facts
