"""Tests for the Auto-Enrichment Pipeline (intel_enricher)."""

import asyncio

import pytest

from services.intel_enricher import enrich_ip, format_enrichment_summary


def test_format_enrichment_summary_clean():
    enrichment = {
        "score": 5,
        "abuse": {"available": True, "abuse_confidence": 0, "country": "US", "total_reports": 0},
        "virustotal": {"available": True, "found": True, "malicious": 0, "suspicious": 0},
    }
    text = format_enrichment_summary(enrichment)
    assert "נקי / Clean" in text
    assert "`5/100`" in text
    assert "US" in text


def test_format_enrichment_summary_malicious():
    enrichment = {
        "score": 85,
        "abuse": {"available": True, "abuse_confidence": 95, "country": "RU", "total_reports": 42},
        "virustotal": {"available": True, "found": True, "malicious": 8, "suspicious": 2},
    }
    text = format_enrichment_summary(enrichment)
    assert "זדוני / Malicious" in text
    assert "95%" in text
    assert "42 דיווחים" in text
    assert "RU" in text
    assert "8 malicious / 2 suspicious" in text


def test_format_enrichment_summary_suspicious():
    enrichment = {
        "score": 50,
        "abuse": {"available": False},
        "virustotal": {"available": True, "found": True, "malicious": 3, "suspicious": 1},
    }
    text = format_enrichment_summary(enrichment)
    assert "חשוד / Suspicious" in text
    assert "3 malicious / 1 suspicious" in text


@pytest.mark.asyncio
async def test_enrich_ip_invalid_ip():
    result = await enrich_ip("not-an-ip")
    assert result is None


@pytest.mark.asyncio
async def test_enrich_ip_timeout_fail_soft():
    """enrich_ip must return None quickly for unreachable/private IPs."""
    result = await enrich_ip("127.0.0.1")
    assert result is None


@pytest.mark.asyncio
async def test_enrich_ip_none_input():
    result = await enrich_ip("")
    assert result is None
    result = await enrich_ip(None)  # type: ignore[arg-type]
    assert result is None


# ── is_clean_enrichment: trusted-ISP cross-validation ──


def _azure_enrichment(abuse_conf: int = 100, vt_mal: int = 0, **extra):
    """Azure IP: AbuseIPDB mass-reported, VT verified clean."""
    return {
        "score": abuse_conf,
        "abuse": {
            "available": True,
            "abuse_confidence": abuse_conf,
            "country": "NL",
            "isp": "Microsoft Corporation",
        },
        "virustotal": {"available": True, "found": True, "malicious": vt_mal, "suspicious": 0},
        **extra,
    }


def test_clean_trusted_isp_overrides_abuse_100():
    """Azure IP with AbuseIPDB=100 but VT=0/90 → CLEAN (cloud noise, not malware)."""
    from services.intel_enricher import is_clean_enrichment

    assert is_clean_enrichment(_azure_enrichment(abuse_conf=100, vt_mal=0)) is True


def test_clean_trusted_isp_requires_vt_data():
    """Trusted ISP alone is NOT enough — VT must have actually returned data."""
    from services.intel_enricher import is_clean_enrichment

    enrichment = _azure_enrichment(abuse_conf=100)
    enrichment["virustotal"] = {"available": False}
    assert is_clean_enrichment(enrichment) is False


def test_clean_trusted_isp_vt_detections_block_override():
    """Trusted ISP with VT detections → NOT clean (real compromise on cloud infra)."""
    from services.intel_enricher import is_clean_enrichment

    assert is_clean_enrichment(_azure_enrichment(abuse_conf=100, vt_mal=3)) is False


def test_clean_feed_hit_always_wins():
    """URLhaus/ThreatFox hit → never clean, even for a trusted ISP."""
    from services.intel_enricher import is_clean_enrichment

    enrichment = _azure_enrichment(threat_feeds={"matched": True, "malware": "Cobalt Strike"})
    assert is_clean_enrichment(enrichment) is False


def test_clean_untrusted_isp_high_score_not_clean():
    """Non-cloud ISP with abuse=100 → stays suspicious/malicious."""
    from services.intel_enricher import is_clean_enrichment

    enrichment = _azure_enrichment(abuse_conf=100)
    enrichment["abuse"]["isp"] = "Bulletproof Hosting Ltd"
    assert is_clean_enrichment(enrichment) is False
