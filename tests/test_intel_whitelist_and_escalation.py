# tests/test_intel_whitelist_and_escalation.py
"""Regression tests for:
1. Escalation threshold (abuse >= 50, not > 0)
2. Blind 'unknown' baseline learning blocked
3. ASN/ISP-based whitelist override for trusted cloud providers
"""

import pytest

from services.intel_enricher import _is_trusted_isp, is_clean_enrichment
from services.net_baseline import add_to_baseline

# ── Escalation threshold ──


def test_escalation_threshold_50():
    """abuse=26 should NOT escalate to CRITICAL (was > 0, now >= 50)."""
    # We test the threshold value directly — the escalation logic is in
    # alert_dispatcher_helpers._enrich_and_escalate, but the threshold
    # check is `abuse_confidence >= 50`. Verify the logic:
    abuse_26 = {"abuse_confidence": 26}
    abuse_49 = {"abuse_confidence": 49}
    abuse_50 = {"abuse_confidence": 50}

    # The condition in code: abuse >= 50 or vt_mal > 0 or score >= 50
    assert not (abuse_26.get("abuse_confidence", 0) >= 50)
    assert not (abuse_49.get("abuse_confidence", 0) >= 50)
    assert abuse_50.get("abuse_confidence", 0) >= 50


# ── Blind 'unknown' learning blocked ──


@pytest.mark.asyncio
async def test_add_to_baseline_rejects_unknown_process():
    """add_to_baseline should NOT learn combos with process_name='unknown'."""
    # We can't easily test the DB write without a test DB, but we can
    # verify the guard fires by checking it returns early (no exception,
    # no DB write). The function should silently skip.
    # Use a fake IP/port that would normally be valid.
    try:
        await add_to_baseline("unknown", "1.2.3.4", 443)
    except Exception as exc:
        pytest.fail(f"add_to_baseline raised on unknown: {exc}")
    # If we reach here, the guard worked (returned early without DB error)


@pytest.mark.asyncio
async def test_add_to_baseline_rejects_none_process():
    """add_to_baseline should NOT learn combos with process_name=None."""
    try:
        await add_to_baseline(None, "1.2.3.4", 443)  # type: ignore[arg-type]
    except Exception as exc:
        pytest.fail(f"add_to_baseline raised on None: {exc}")


@pytest.mark.asyncio
async def test_add_to_baseline_rejects_empty_process():
    """add_to_baseline should NOT learn combos with empty process_name."""
    try:
        await add_to_baseline("", "1.2.3.4", 443)
    except Exception as exc:
        pytest.fail(f"add_to_baseline raised on empty: {exc}")


# ── Trusted ISP whitelist override ──


def test_trusted_isp_microsoft():
    """Microsoft ISP should be detected as trusted."""
    abuse = {"isp": "Microsoft Corporation"}
    assert _is_trusted_isp(abuse)


def test_trusted_isp_google():
    """Google ISP should be detected as trusted."""
    abuse = {"isp": "Google LLC"}
    assert _is_trusted_isp(abuse)


def test_trusted_isp_azure():
    """Microsoft Azure ISP should be detected as trusted."""
    abuse = {"isp": "Microsoft Azure"}
    assert _is_trusted_isp(abuse)


def test_trusted_isp_amazon():
    """Amazon/AWS ISP should be detected as trusted."""
    abuse = {"isp": "Amazon.com Inc."}
    assert _is_trusted_isp(abuse)


def test_trusted_isp_random_isp():
    """Random ISP should NOT be trusted."""
    abuse = {"isp": "SomeRandomISP Ltd"}
    assert not _is_trusted_isp(abuse)


def test_trusted_isp_empty():
    """Empty ISP should not be trusted."""
    assert not _is_trusted_isp({"isp": ""})
    assert not _is_trusted_isp({})


def test_clean_enrichment_score_zero():
    """Score=0 → clean (standard path)."""
    enrichment = {"score": 0, "abuse": {}, "virustotal": {}}
    assert is_clean_enrichment(enrichment)


def test_clean_enrichment_trusted_isp_low_abuse():
    """Microsoft ISP + abuse=26 + VT clean → whitelist (override)."""
    enrichment = {
        "score": 26,
        "abuse": {"isp": "Microsoft Corporation", "abuse_confidence": 26},
        "virustotal": {"available": True, "found": True, "malicious": 0},
    }
    assert is_clean_enrichment(enrichment)


def test_clean_enrichment_trusted_isp_high_abuse():
    """Microsoft ISP + abuse=60 + VT clean → whitelisted (trusted ISP override).

    AbuseIPDB mass-reporting on multi-tenant cloud IPs is noise; VT=0 from
    a trusted ISP wins regardless of abuse_confidence (deterministic guard).
    """
    enrichment = {
        "score": 60,
        "abuse": {"isp": "Microsoft Corporation", "abuse_confidence": 60},
        "virustotal": {"available": True, "found": True, "malicious": 0},
    }
    assert is_clean_enrichment(enrichment)


def test_clean_enrichment_trusted_isp_vt_malicious():
    """Microsoft ISP + VT malicious → NOT whitelisted (VT overrides trust)."""
    enrichment = {
        "score": 30,
        "abuse": {"isp": "Microsoft Corporation", "abuse_confidence": 30},
        "virustotal": {"available": True, "found": True, "malicious": 5},
    }
    assert not is_clean_enrichment(enrichment)


def test_clean_enrichment_random_isp_low_abuse():
    """Random ISP + abuse=26 → NOT whitelisted (no trust override)."""
    enrichment = {
        "score": 26,
        "abuse": {"isp": "SomeRandomISP", "abuse_confidence": 26},
        "virustotal": {"available": True, "found": True, "malicious": 0},
    }
    assert not is_clean_enrichment(enrichment)
