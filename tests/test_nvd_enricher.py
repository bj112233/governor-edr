# tests/test_nvd_enricher.py
"""Tests for NVD NIST CVE enrichment."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from services.nvd_enricher import enrich_cve, enrich_cves, format_cve_hard_facts


def _mock_nvd_response(cve_id: str, status_code: int = 200) -> httpx.Response:
    """Build a mock NVD API v2.0 response."""
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2026-01-15T00:00:00.000",
                    "lastModified": "2026-07-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": "Buffer overflow in example allows RCE via crafted packet."},
                        {"lang": "es", "value": "Desbordamiento de búfer."},
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 9.8,
                                    "attackVector": "NETWORK",
                                    "baseSeverity": "CRITICAL",
                                },
                                "baseSeverity": "CRITICAL",
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
                                        {"criteria": "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"},
                                    ]
                                }
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234"},
                        {"url": "https://example.com/advisory"},
                    ],
                }
            }
        ]
    }
    req = httpx.Request("GET", f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    return httpx.Response(status_code, json=data, request=req)


@pytest.mark.asyncio
async def test_enrich_cve_success():
    """Valid CVE → full enrichment with CVSS, vector, products."""
    cve_id = "CVE-2026-1234"
    mock_resp = _mock_nvd_response(cve_id)

    with patch("services.nvd_enricher.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await enrich_cve(cve_id)

    assert result["available"] is True
    assert result["cve_id"] == "CVE-2026-1234"
    assert result["cvss_score"] == 9.8
    assert result["cvss_severity"] == "CRITICAL"
    assert result["attack_vector"] == "NETWORK"
    assert "Buffer overflow" in result["description"]
    assert len(result["affected_products"]) == 2
    assert len(result["references"]) == 2


@pytest.mark.asyncio
async def test_enrich_cve_not_found():
    """404 → available=False, error set."""
    mock_resp = httpx.Response(404, request=httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-9999"))

    with patch("services.nvd_enricher.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await enrich_cve("CVE-2099-9999")

    assert result["available"] is False
    assert "not found" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_enrich_cve_invalid_format():
    """Invalid CVE ID → available=False."""
    result = await enrich_cve("not-a-cve")
    assert result["available"] is False
    assert "invalid" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_enrich_cve_normalizes_case():
    """Lowercase input → normalized to uppercase."""
    cve_id = "cve-2026-1234"
    mock_resp = _mock_nvd_response("CVE-2026-1234")

    with patch("services.nvd_enricher.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await enrich_cve(cve_id)

    assert result["cve_id"] == "CVE-2026-1234"


@pytest.mark.asyncio
async def test_enrich_cves_batch():
    """Batch enrichment of multiple CVEs."""
    cve_ids = ["CVE-2026-1111", "CVE-2026-2222"]
    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        resp = _mock_nvd_response(cve_ids[call_count])
        call_count += 1
        return resp

    with patch("services.nvd_enricher.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get
        mock_client_cls.return_value = mock_client

        results = await enrich_cves(cve_ids)

    assert len(results) == 2
    assert all(r["available"] for r in results)


def test_format_cve_hard_facts():
    """Format result as hard-facts string for LLM injection."""
    cve_result = {
        "cve_id": "CVE-2026-1234",
        "available": True,
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "attack_vector": "NETWORK",
        "description": "Buffer overflow in example allows RCE.",
        "affected_products": ["cpe:2.3:a:vendor:product:1.0"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"],
    }
    text = format_cve_hard_facts(cve_result)
    assert "CVE-2026-1234" in text
    assert "9.8" in text
    assert "CRITICAL" in text
    assert "NETWORK" in text
    assert "Buffer overflow" in text


def test_format_cve_hard_facts_unavailable():
    """Unavailable result → empty string."""
    text = format_cve_hard_facts({"cve_id": "CVE-2099-9999", "available": False})
    assert text == ""
