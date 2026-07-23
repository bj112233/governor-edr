# tests/test_pre_hunt_enricher.py
"""Tests for pre-hunt deterministic enrichment pipeline.

Covers: IP extraction from snapshot/alerts, enrichment orchestration,
HARD FACTS formatting, malicious/clean detection for scoring v2.0.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ── IOC extraction tests ──


class TestExtractIOCs:
    def test_extracts_ipv4_from_snapshot(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 1.2.3.4:443 (chrome.exe)"]}
        alerts: list[tuple] = []
        public, internal, domains, hashes = _extract_iocs_from_context(snapshot, alerts)
        assert "1.2.3.4" in public
        assert internal == []
        assert domains == []
        assert hashes == []

    def test_extracts_ipv4_from_alert_text(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot: dict = {}
        alerts = [("2026-01-01", "net:new_external_ip", "connection to 46.101.206.53 established")]
        public, _internal, _domains, _hashes = _extract_iocs_from_context(snapshot, alerts)
        assert "46.101.206.53" in public

    def test_skips_private_ips_to_internal_bucket(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 192.168.1.1:443 (chrome.exe)"]}
        public, internal, _d, _h = _extract_iocs_from_context(snapshot, [])
        assert public == []
        assert "192.168.1.1" in internal

    def test_skips_loopback_to_internal_bucket(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 127.0.0.1:8080 (python.exe)"]}
        public, internal, _d, _h = _extract_iocs_from_context(snapshot, [])
        assert public == []
        assert "127.0.0.1" in internal

    def test_deduplicates_ips(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 1.2.3.4:443", "tcp 1.2.3.4:80"]}
        public, _i, _d, _h = _extract_iocs_from_context(snapshot, [])
        assert public.count("1.2.3.4") == 1

    def test_caps_public_at_10(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": [f"tcp {i}.{i}.{i}.{i}:443" for i in range(1, 20)]}
        public, _i, _d, _h = _extract_iocs_from_context(snapshot, [])
        assert len(public) <= 10

    def test_extracts_domains(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        snapshot = {"suspicious_net": ["tcp evil.com:443 (chrome.exe)"]}
        _p, _i, domains, _h = _extract_iocs_from_context(snapshot, [])
        assert "evil.com" in domains

    def test_extracts_hashes(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        sha256 = "a" * 64
        snapshot = {"suspicious_net": [f"malware hash {sha256} detected"]}
        _p, _i, _d, hashes = _extract_iocs_from_context(snapshot, [])
        assert sha256 in hashes

    def test_empty_context_returns_empty(self):
        from services.pre_hunt_enricher import _extract_iocs_from_context

        assert _extract_iocs_from_context({}, []) == ([], [], [], [])


# ── Enrichment orchestration tests ──


class TestEnrichIOCs:
    @pytest.mark.asyncio
    async def test_enriches_extracted_ips(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 1.2.3.4:443 (chrome.exe)"]}
        mock_data = {"score": 85, "abuse": {"country": "RU", "isp": "Evict"}, "virustotal": {"malicious": 3}}
        with patch("services.pre_hunt_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await enrich_iocs_from_context(snapshot, [])
        assert "1.2.3.4" in report.enriched
        assert report.has_any_ioc is True
        assert report.has_malicious is True

    @pytest.mark.asyncio
    async def test_clean_ip_not_malicious(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 46.101.206.53:443 (chrome.exe)"]}
        mock_data = {"score": 0, "abuse": {"country": "US", "isp": "DigitalOcean"}, "virustotal": {"malicious": 0}}
        with patch("services.pre_hunt_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await enrich_iocs_from_context(snapshot, [])
        assert report.has_malicious is False
        assert report.all_clean is True

    @pytest.mark.asyncio
    async def test_timeout_goes_to_failed(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 1.2.3.4:443 (chrome.exe)"]}

        async def _timeout(ip):
            await asyncio.sleep(10)

        with patch("services.pre_hunt_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.side_effect = _timeout
            report = await enrich_iocs_from_context(snapshot, [])
        assert "1.2.3.4" in report.failed
        assert report.enriched == {}

    @pytest.mark.asyncio
    async def test_no_ips_returns_empty_report(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        report = await enrich_iocs_from_context({}, [])
        assert report.has_any_ioc is False
        assert report.enriched == {}

    @pytest.mark.asyncio
    async def test_internal_only_populates_internal_ips_seen(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 10.0.0.138:1900 (svchost.exe)"]}
        report = await enrich_iocs_from_context(snapshot, [])
        assert report.has_external_ioc is False
        assert report.enriched == {}
        assert "10.0.0.138" in report.internal_ips_seen

    @pytest.mark.asyncio
    async def test_mixed_public_and_internal(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp 1.2.3.4:443", "tcp 10.0.0.5:1900"]}
        mock_data = {"score": 0, "abuse": {"country": "US", "isp": "X"}, "virustotal": {"malicious": 0}}
        with patch("services.pre_hunt_enricher.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await enrich_iocs_from_context(snapshot, [])
        assert "1.2.3.4" in report.enriched
        assert "10.0.0.5" in report.internal_ips_seen
        assert report.has_external_ioc is True


# ── HARD FACTS formatting tests ──


class TestFormatHardFacts:
    def test_empty_report_returns_empty_string(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        assert format_hard_facts(PreHuntReport()) == ""

    def test_internal_only_injects_no_external_directive(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.internal_ips_seen = ["10.0.0.138", "fe80::1"]
        facts = format_hard_facts(report)
        assert "NO EXTERNAL IOCs" in facts
        assert "10.0.0.138" in facts
        assert "do not call skill_intel-skill" in facts.lower()
        assert "HARD FACTS" in facts

    def test_internal_only_no_internal_ips_returns_empty(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()  # no internal_ips_seen, no enriched
        assert format_hard_facts(report) == ""

    def test_includes_ip_and_score(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {
            "score": 85,
            "abuse": {"country": "RU", "isp": "Evict"},
            "virustotal": {"malicious": 3, "available": True, "found": True},
        }
        facts = format_hard_facts(report)
        assert "1.2.3.4" in facts
        assert "85" in facts
        assert "RU" in facts
        assert "MALICIOUS" in facts

    def test_clean_ip_labeled_clean(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["46.101.206.53"] = {
            "score": 0,
            "abuse": {"country": "US", "isp": "DigitalOcean"},
            "virustotal": {"malicious": 0, "available": True, "found": True},
        }
        facts = format_hard_facts(report)
        assert "CLEAN" in facts

    def test_failed_ip_labeled_unknown(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.failed.append("1.2.3.4")
        facts = format_hard_facts(report)
        assert "FAILED" in facts or "unknown" in facts

    def test_includes_do_not_contradict_directive(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {"score": 0, "abuse": {"country": "US", "isp": "X"}, "virustotal": {}}
        facts = format_hard_facts(report)
        assert "HARD FACTS" in facts
        assert "do not contradict" in facts.lower()


# ── Scoring v2.0: any_ioc_malicious tests ──


class TestAnyIocMalicious:
    def test_malicious_ip_returns_true(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {"score": 85, "abuse": {}, "virustotal": {"malicious": 0}}
        assert any_ioc_malicious(report) is True

    def test_vt_malicious_returns_true(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {
            "score": 10,
            "abuse": {},
            "virustotal": {"malicious": 5, "available": True, "found": True},
        }
        assert any_ioc_malicious(report) is True

    def test_clean_ips_returns_false(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["1.2.3.4"] = {"score": 0, "abuse": {}, "virustotal": {"malicious": 0}}
        assert any_ioc_malicious(report) is False

    def test_empty_report_returns_false(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        assert any_ioc_malicious(PreHuntReport()) is False

    def test_mixed_ips_true_if_any_malicious(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["1.1.1.1"] = {"score": 0, "abuse": {}, "virustotal": {"malicious": 0}}
        report.enriched["2.2.2.2"] = {"score": 90, "abuse": {}, "virustotal": {"malicious": 0}}
        assert any_ioc_malicious(report) is True

    def test_malicious_domain_returns_true(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["evil.com"] = {"score": 80, "virustotal": {"malicious": 12, "available": True, "found": True}}
        assert any_ioc_malicious(report) is True

    def test_malicious_hash_returns_true(self):
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["a" * 64] = {"score": 90, "virustotal": {"malicious": 45, "available": True, "found": True}}
        assert any_ioc_malicious(report) is True

    def test_azure_ip_abuse_100_vt_clean_not_malicious(self):
        """Regression: Azure IP with AbuseIPDB=100 but VT=0/90 must NOT be MALICIOUS.

        Multi-tenant cloud IPs get mass-reported by Fail2Ban-style automation;
        without VT corroboration the abuse score alone is noise.
        """
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["13.69.116.104"] = {
            "score": 100,
            "abuse": {"available": True, "abuse_confidence": 100, "isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 0, "suspicious": 0},
        }
        assert any_ioc_malicious(report) is False

    def test_azure_ip_all_clean_triggers_clamp_path(self):
        """Same Azure IP must register as all_clean → hunt score clamped, no dispatch."""
        from services.pre_hunt_enricher import PreHuntReport

        report = PreHuntReport()
        report.enriched["13.69.116.104"] = {
            "score": 100,
            "abuse": {"available": True, "abuse_confidence": 100, "isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 0, "suspicious": 0},
        }
        assert report.has_malicious is False
        assert report.all_clean is True

    def test_trusted_isp_feed_hit_still_malicious(self):
        """Feed hit (ThreatFox/URLhaus) overrides the trusted-ISP guard."""
        from services.pre_hunt_enricher import PreHuntReport, any_ioc_malicious

        report = PreHuntReport()
        report.enriched["13.69.116.104"] = {
            "score": 100,
            "abuse": {"available": True, "abuse_confidence": 100, "isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 0, "suspicious": 0},
            "threat_feeds": {"matched": True, "malware": "AsyncRAT"},
        }
        assert any_ioc_malicious(report) is True


# ── Quota allocation tests (pure function) ──


class TestAllocateQuota:
    def test_hash_gets_priority_over_domain_and_ip(self):
        from services.pre_hunt_enricher import _allocate_quota

        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        domains = ["evil.com", "bad.com"]
        hashes = ["a" * 64]
        alloc = _allocate_quota(ips, domains, hashes)
        assert alloc["a" * 64] == "full_intel"
        assert alloc["evil.com"] == "full_intel"
        assert alloc["1.1.1.1"] == "full_intel"
        assert alloc["2.2.2.2"] == "full_intel"
        # Overflow: 2nd domain and 3rd IP → fallback_only
        assert alloc["bad.com"] == "fallback_only"
        assert alloc["3.3.3.3"] == "fallback_only"

    def test_only_2_ip_slots_max_even_without_hash_domain(self):
        from services.pre_hunt_enricher import _allocate_quota

        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]
        alloc = _allocate_quota(ips, [], [])
        full_count = sum(1 for v in alloc.values() if v == "full_intel")
        assert full_count == 2  # _VT_QUOTA_IP = 2, IPs are lowest priority
        assert alloc["1.1.1.1"] == "full_intel"
        assert alloc["2.2.2.2"] == "full_intel"
        assert alloc["3.3.3.3"] == "fallback_only"
        assert alloc["4.4.4.4"] == "fallback_only"
        assert alloc["5.5.5.5"] == "fallback_only"

    def test_empty_inputs_returns_empty(self):
        from services.pre_hunt_enricher import _allocate_quota

        assert _allocate_quota([], [], []) == {}

    def test_domain_takes_slot_from_ip_quota(self):
        from services.pre_hunt_enricher import _allocate_quota

        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        domains = ["evil.com"]
        alloc = _allocate_quota(ips, domains, [])
        assert alloc["evil.com"] == "full_intel"
        # Only 2 IP slots remain (4 total - 1 domain)
        assert alloc["1.1.1.1"] == "full_intel"
        assert alloc["2.2.2.2"] == "full_intel"
        assert alloc["3.3.3.3"] == "fallback_only"


# ── Domain/Hash enrichment orchestration tests ──


class TestEnrichDomainsHashes:
    @pytest.mark.asyncio
    async def test_enriches_domain(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        snapshot = {"suspicious_net": ["tcp evil.com:443 (chrome.exe)"]}
        mock_data = {"score": 80, "virustotal": {"malicious": 12, "available": True, "found": True}}
        with patch("services.pre_hunt_enricher.enrich_domain", new_callable=AsyncMock) as mock_d:
            mock_d.return_value = mock_data
            report = await enrich_iocs_from_context(snapshot, [])
        assert "evil.com" in report.enriched
        assert report.ioc_types["evil.com"] == "domain"
        assert report.has_malicious is True

    @pytest.mark.asyncio
    async def test_enriches_hash(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        sha256 = "a" * 64
        snapshot = {"suspicious_net": [f"malware hash {sha256} detected"]}
        mock_data = {"score": 90, "virustotal": {"malicious": 45, "available": True, "found": True}}
        with patch("services.pre_hunt_enricher.enrich_hash", new_callable=AsyncMock) as mock_h:
            mock_h.return_value = mock_data
            report = await enrich_iocs_from_context(snapshot, [])
        assert sha256 in report.enriched
        assert report.ioc_types[sha256] == "hash"
        assert report.has_malicious is True

    @pytest.mark.asyncio
    async def test_overflow_ip_routed_to_skipped(self):
        from services.pre_hunt_enricher import enrich_iocs_from_context

        # 5 IPs → only 2 get full_intel (after hash+domain take their slots)
        sha = "b" * 64
        snapshot = {
            "suspicious_net": [f"hash {sha}", "evil.com", "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]
        }
        with (
            patch("services.pre_hunt_enricher.enrich_hash", new_callable=AsyncMock) as mock_h,
            patch("services.pre_hunt_enricher.enrich_domain", new_callable=AsyncMock) as mock_d,
            patch("services.pre_hunt_enricher.enrich_ip", new_callable=AsyncMock) as mock_ip,
        ):
            mock_h.return_value = {"score": 0, "virustotal": {"malicious": 0}}
            mock_d.return_value = {"score": 0, "virustotal": {"malicious": 0}}
            mock_ip.return_value = {"score": 0, "abuse": {}, "virustotal": {"malicious": 0}}
            report = await enrich_iocs_from_context(snapshot, [])
        # hash + domain + 2 IPs = 4 full_intel; 3 IPs skipped
        assert len(report.skipped) == 3
        assert sha in report.enriched
        assert "evil.com" in report.enriched

    @pytest.mark.asyncio
    async def test_format_hard_facts_includes_domain_and_hash(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.enriched["evil.com"] = {"score": 80, "virustotal": {"malicious": 12, "available": True, "found": True}}
        report.ioc_types["evil.com"] = "domain"
        report.enriched["a" * 64] = {"score": 90, "virustotal": {"malicious": 45, "available": True, "found": True}}
        report.ioc_types["a" * 64] = "hash"
        facts = format_hard_facts(report)
        assert "Domain evil.com" in facts
        assert "Hash" in facts
        assert "MALICIOUS" in facts

    @pytest.mark.asyncio
    async def test_format_hard_facts_skipped_stamp(self):
        from services.pre_hunt_enricher import PreHuntReport, format_hard_facts

        report = PreHuntReport()
        report.skipped.append("5.5.5.5")
        report.ioc_types["5.5.5.5"] = "ip"
        report.enriched["1.1.1.1"] = {"score": 0, "abuse": {}, "virustotal": {"malicious": 0}}
        report.ioc_types["1.1.1.1"] = "ip"
        facts = format_hard_facts(report)
        assert "quota reserved" in facts.lower()
        assert "5.5.5.5" in facts
