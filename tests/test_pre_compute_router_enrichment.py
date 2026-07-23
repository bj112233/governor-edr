# tests/test_pre_compute_router_enrichment.py
"""Tests for pre-compute router enrichment paths — domains, hashes, formatting.

Covers missing lines in pre_compute_router.py:
- _enrich_iocs with domains (lines 114-119, 127-131, 133-137)
- _format_enriched_ioc for domain/hash types (lines 217-222)
- _format_no_enrichment (lines 225-232)
- format_pre_compute_facts with domains (line 262)
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
    _format_enriched_ioc,
    _format_no_enrichment,
    format_pre_compute_facts,
    pre_compute,
)


class TestPreComputeReportProperties:
    def test_all_clean_true(self):
        """all_clean property: all enriched IOCs are clean (lines 63-65)."""
        r = PreComputeReport()
        r.enriched = {
            "8.8.8.8": {"score": 0, "virustotal": {"available": True, "found": True, "malicious": 0}},
            "evil.com": {"score": 0, "virustotal": {"available": True, "found": True, "malicious": 0}},
        }
        assert r.all_clean is True

    def test_all_clean_false_when_malicious(self):
        """all_clean property: False when any IOC is malicious."""
        r = PreComputeReport()
        r.enriched = {"8.8.8.8": {"score": 95}}
        assert r.all_clean is False

    def test_all_clean_false_when_empty(self):
        """all_clean property: False when no enriched IOCs."""
        r = PreComputeReport()
        assert r.all_clean is False


class TestExtractIocsEdgeCases:
    def test_duplicate_ip_deduped(self):
        """Duplicate IP in extraction → deduped (line 80-81)."""
        from services.pre_compute_router import _extract_iocs_from_text

        ips, _, _, _ = _extract_iocs_from_text("8.8.8.8 and 8.8.8.8 again")
        assert ips.count("8.8.8.8") == 1

    def test_loopback_ip_is_internal(self):
        """127.0.0.1 → internal, not public (line 85-86)."""
        from services.pre_compute_router import _extract_iocs_from_text

        ips, internal, _, _ = _extract_iocs_from_text("connect to 127.0.0.1")
        assert ips == []
        assert "127.0.0.1" in internal


class TestFormatEnrichedIoc:
    def test_domain_format(self):
        """Domain IOC → 'Domain {key}: score=...' format (line 218)."""
        data = {"score": 50, "virustotal": {"available": True, "found": True, "malicious": 3}}
        result = _format_enriched_ioc("evil.com", data, "domain")
        assert "Domain evil.com" in result
        assert "score=50" in result

    def test_hash_format(self):
        """Hash IOC → 'Hash {short}: score=...' format (line 220-221)."""
        data = {"score": 90, "virustotal": {"available": True, "found": True, "malicious": 10}}
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = _format_enriched_ioc(h, data, "hash")
        assert "Hash" in result
        assert "..." in result  # truncated hash
        assert "score=90" in result

    def test_hash_short_not_truncated(self):
        """Short hash (< 12 chars) → not truncated."""
        data = {"score": 0, "virustotal": {"available": False, "found": False, "malicious": 0}}
        result = _format_enriched_ioc("abc123def456", data, "hash")
        assert "abc123def456" in result
        assert "..." not in result

    def test_unknown_type_fallback(self):
        """Unknown IOC type → generic format (line 222)."""
        data = {"score": 50, "virustotal": {"available": True, "found": True, "malicious": 5}}
        result = _format_enriched_ioc("some_key", data, "unknown")
        assert "some_key" in result
        assert "score=50" in result


class TestFormatNoEnrichment:
    def test_internal_ips_only(self):
        """Only internal IPs → no enrichment block (line 228-230)."""
        report = PreComputeReport()
        report.internal_ips = ["192.168.1.1", "10.0.0.1"]
        result = _format_no_enrichment(report)
        assert "INTERNAL" in result
        assert "192.168.1.1" in result
        assert "Do NOT claim malicious" in result

    def test_no_internal_ips(self):
        """No internal IPs → still has header and footer."""
        report = PreComputeReport()
        result = _format_no_enrichment(report)
        assert "PRE-COMPUTED HARD FACTS" in result
        assert "Do NOT claim malicious" in result


class TestFormatPreComputeFactsDomains:
    def test_domain_in_facts(self):
        """Enriched domain → appears in formatted facts (line 262)."""
        report = PreComputeReport()
        report.enriched = {"evil.com": {"score": 80, "virustotal": {"available": True, "found": True, "malicious": 7}}}
        report.ioc_types = {"evil.com": "domain"}
        result = format_pre_compute_facts(report)
        assert "Domain evil.com" in result
        assert "MALICIOUS" in result

    def test_hash_in_facts(self):
        """Enriched hash → appears in formatted facts."""
        report = PreComputeReport()
        h = "d41d8cd98f00b204e9800998ecf8427e"
        report.enriched = {h: {"score": 95, "virustotal": {"available": True, "found": True, "malicious": 15}}}
        report.ioc_types = {h: "hash"}
        result = format_pre_compute_facts(report)
        assert "Hash" in result
        assert "MALICIOUS" in result


class TestPreComputeDomainEnrichment:
    @pytest.mark.asyncio
    async def test_domain_triggers_enrichment(self):
        """Query with a domain → domain enrichment called (lines 114-115)."""
        mock_data = {"score": 50, "virustotal": {"available": True, "found": True, "malicious": 3}}
        with patch("services.pre_compute_router.enrich_domain", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await pre_compute("check evil.com reputation")
        assert "evil.com" in report.enriched
        mock_enrich.assert_awaited()

    @pytest.mark.asyncio
    async def test_hash_triggers_enrichment(self):
        """Query with a hash → hash enrichment called (lines 116-117)."""
        h = "d41d8cd98f00b204e9800998ecf8427e"
        mock_data = {"score": 90, "virustotal": {"available": True, "found": True, "malicious": 10}}
        with patch("services.pre_compute_router.enrich_hash", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.return_value = mock_data
            report = await pre_compute(f"analyze file hash {h}")
        assert h in report.enriched
        mock_enrich.assert_awaited()

    @pytest.mark.asyncio
    async def test_domain_enrichment_timeout(self):
        """Domain enrichment timeout → domain in failed list (line 120-122)."""
        with patch("services.pre_compute_router.enrich_domain", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.side_effect = TimeoutError()
            report = await pre_compute("check evil.com")
        assert "evil.com" in report.failed
        assert "evil.com" not in report.enriched

    @pytest.mark.asyncio
    async def test_hash_enrichment_exception(self):
        """Hash enrichment exception → hash in failed list (line 120-122)."""
        h = "d41d8cd98f00b204e9800998ecf8427e"
        with patch("services.pre_compute_router.enrich_hash", new_callable=AsyncMock) as mock_enrich:
            mock_enrich.side_effect = RuntimeError("API error")
            report = await pre_compute(f"analyze {h}")
        assert h in report.failed
