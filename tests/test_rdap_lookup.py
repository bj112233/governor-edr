# tests/test_rdap_lookup.py
"""Tests for RDAP domain age lookup — zero-day infrastructure detection."""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from services.rdap_lookup import check_domains_age, lookup_domain_age


def _mock_rdap_response(domain: str, registered: str | None, status_code: int = 200) -> httpx.Response:
    """Build a mock RDAP JSON response."""
    events = []
    if registered:
        events.append({"eventAction": "registration", "eventDate": registered})
    data = {
        "handle": f"{domain}-handle",
        "ldhName": domain,
        "events": events,
        "status": ["active"],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", "Test Registrar"]]]}],
    }
    req = httpx.Request("GET", f"https://rdap.org/domain/{domain}")
    return httpx.Response(status_code, json=data, request=req)


@pytest.mark.asyncio
async def test_fresh_domain_critical():
    """Domain registered 3 days ago → is_critical=True."""
    registered = (datetime.now(UTC) - timedelta(days=3)).isoformat()
    domain = "evil-c2.com"
    mock_resp = _mock_rdap_response(domain, registered)

    with patch("services.rdap_lookup.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await lookup_domain_age(domain)

    assert result["available"] is True
    assert result["age_days"] is not None
    assert result["age_days"] < 30
    assert result["is_critical"] is True
    assert result["is_suspicious"] is True


@pytest.mark.asyncio
async def test_old_domain_safe():
    """Domain registered 5 years ago → not critical, not suspicious."""
    registered = (datetime.now(UTC) - timedelta(days=1825)).isoformat()
    domain = "legit-site.com"
    mock_resp = _mock_rdap_response(domain, registered)

    with patch("services.rdap_lookup.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await lookup_domain_age(domain)

    assert result["available"] is True
    assert result["age_days"] is not None
    assert result["age_days"] > 90
    assert result["is_critical"] is False
    assert result["is_suspicious"] is False


@pytest.mark.asyncio
async def test_domain_not_found_404():
    """404 response → available=False, error set."""
    domain = "nonexistent.xyz"
    mock_resp = httpx.Response(404, request=httpx.Request("GET", f"https://rdap.org/domain/{domain}"))

    with patch("services.rdap_lookup.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        result = await lookup_domain_age(domain)

    assert result["available"] is False
    assert "not found" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_invalid_domain():
    """Invalid domain → available=False."""
    result = await lookup_domain_age("no-dot-here")
    assert result["available"] is False
    assert "invalid" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_check_domains_age_batch():
    """Batch check with one fresh + one old domain."""
    fresh_date = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    old_date = (datetime.now(UTC) - timedelta(days=1000)).isoformat()

    domains = ["fresh.com", "old.com"]
    responses = [
        _mock_rdap_response("fresh.com", fresh_date),
        _mock_rdap_response("old.com", old_date),
    ]
    # Pre-build requests for each domain so mock_get can return the right response
    call_count = 0

    async def mock_get(url, **kwargs):
        nonlocal call_count
        resp = responses[call_count]
        call_count += 1
        return resp

    with patch("services.rdap_lookup.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.get = mock_get
        mock_client_cls.return_value = mock_client

        result = await check_domains_age(domains)

    assert result["checked"] == 2
    assert result["has_critical"] is True
    assert len(result["critical_domains"]) == 1
    assert result["critical_domains"][0]["domain"] == "fresh.com"


@pytest.mark.asyncio
async def test_check_domains_empty():
    """Empty domain list → checked=0, has_critical=False."""
    result = await check_domains_age([])
    assert result["checked"] == 0
    assert result["has_critical"] is False
