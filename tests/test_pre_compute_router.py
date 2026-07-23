# tests/test_pre_compute_router.py
"""Tests for pre-compute router — deterministic enrichment before LLM.

Covers: IOC extraction from text, enrichment gating, hard-facts formatting,
intent detection integration, fail-soft behavior.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.pre_compute_router import (
    PreComputeReport,
    _extract_iocs_from_text,
    format_pre_compute_facts,
    pre_compute,
)

# ── IOC extraction from text ──


class TestExtractIOCsFromText:
    def test_extracts_ipv4(self):
        ips, internal, domains, hashes = _extract_iocs_from_text("connect to 8.8.8.8 now")
        assert "8.8.8.8" in ips
        assert internal == []

    def test_separates_internal_ips(self):
        ips, internal, domains, hashes = _extract_iocs_from_text("local 192.168.1.1 and 10.0.0.1")
        assert ips == []
        assert "192.168.1.1" in internal
        assert "10.0.0.1" in internal

    def test_extracts_domain(self):
        ips, internal, domains, hashes = _extract_iocs_from_text("visit evil.com for info")
        assert "evil.com" in domains

    def test_extracts_hash(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        ips, internal, domains, hashes = _extract_iocs_from_text(f"file hash {h}")
        assert h in hashes

    def test_empty_text(self):
        assert _extract_iocs_from_text("") == ([], [], [], [])

    def test_no_iocs(self):
        assert _extract_iocs_from_text("what is the weather") == ([], [], [], [])

    def test_dedup_ips(self):
        ips, _, _, _ = _extract_iocs_from_text("8.8.8.8 and 8.8.8.8 again")
        assert ips.count("8.8.8.8") == 1


# ── Pre-compute (enrichment gating) ──


class TestPreCompute:
    @pytest.mark.asyncio
    async def test_no_iocs_no_enrichment(self):
        """Query with no IOCs → no enrichment calls, intent may still be set."""
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            report = await pre_compute("what is the weather today")
        assert not report.has_ioc
        mock_enrich.assert_not_called()

    @pytest.mark.asyncio
    async def test_ioc_triggers_enrichment(self):
        """Query with an IP → enrichment called."""
        mock_data = {"score": 0, "abuse": {"country": "US"}}
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await pre_compute("check 8.8.8.8 reputation")
        assert "8.8.8.8" in report.enriched
        mock_enrich.assert_awaited()

    @pytest.mark.asyncio
    async def test_internal_ip_only_no_enrichment(self):
        """Internal IP → no enrichment (private network)."""
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            report = await pre_compute("scan 192.168.1.1")
        assert not report.enriched
        assert "192.168.1.1" in report.internal_ips
        mock_enrich.assert_not_called()

    @pytest.mark.asyncio
    async def test_enrichment_timeout_is_fail_soft(self):
        """Enrichment timeout → IOC in failed list, no exception."""
        with patch("services.pre_compute_router.enrich_ip", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.side_effect = TimeoutError()
            report = await pre_compute("check 8.8.8.8")
        assert "8.8.8.8" in report.failed
        assert not report.enriched

    @pytest.mark.asyncio
    async def test_intent_always_detected(self):
        """Intent detection runs even with no IOCs."""
        report = await pre_compute("CVE-2024-3094")
        assert report.intent is not None
        assert report.intent["intent"] == "cve"

    @pytest.mark.asyncio
    async def test_no_intent_for_general_query(self):
        report = await pre_compute("tell me a joke")
        assert report.intent is None


# ── Hard facts formatting ──


class TestFormatPreComputeFacts:
    def test_empty_report_returns_empty(self):
        report = PreComputeReport()
        assert format_pre_compute_facts(report) == ""

    def test_internal_ips_only(self):
        report = PreComputeReport()
        report.internal_ips = ["192.168.1.1", "10.0.0.1"]
        result = format_pre_compute_facts(report)
        assert "INTERNAL" in result
        assert "192.168.1.1" in result

    def test_enriched_ip(self):
        report = PreComputeReport()
        report.enriched = {"8.8.8.8": {"score": 95, "virustotal": {"available": True, "found": True, "malicious": 5}}}
        report.ioc_types = {"8.8.8.8": "ip"}
        result = format_pre_compute_facts(report)
        assert "8.8.8.8" in result
        assert "MALICIOUS" in result
        assert "Do NOT call skill_intel-skill" in result

    def test_clean_ip(self):
        report = PreComputeReport()
        report.enriched = {"8.8.8.8": {"score": 0, "virustotal": {"available": True, "found": True, "malicious": 0}}}
        report.ioc_types = {"8.8.8.8": "ip"}
        result = format_pre_compute_facts(report)
        assert "CLEAN" in result

    def test_failed_ioc(self):
        report = PreComputeReport()
        report.failed = ["1.2.3.4"]
        report.ioc_types = {"1.2.3.4": "ip"}
        result = format_pre_compute_facts(report)
        assert "FAILED" in result
        assert "1.2.3.4" in result

    def test_skipped_ioc(self):
        report = PreComputeReport()
        report.skipped = ["extra.com"]
        report.ioc_types = {"extra.com": "domain"}
        result = format_pre_compute_facts(report)
        assert "quota" in result.lower()
        assert "extra.com" in result


# ── PreComputeReport properties ──


class TestPreComputeReportProperties:
    def test_has_ioc_false_when_empty(self):
        assert not PreComputeReport().has_ioc

    def test_has_ioc_true_with_enriched(self):
        r = PreComputeReport()
        r.enriched = {"x": {}}
        assert r.has_ioc

    def test_has_ioc_true_with_internal_only(self):
        r = PreComputeReport()
        r.internal_ips = ["10.0.0.1"]
        assert r.has_ioc

    def test_has_malicious_false_when_clean(self):
        r = PreComputeReport()
        r.enriched = {"x": {"score": 0, "virustotal": {"malicious": 0}}}
        assert not r.has_malicious

    def test_has_malicious_true_when_score_high(self):
        r = PreComputeReport()
        r.enriched = {"x": {"score": 95}}
        assert r.has_malicious
