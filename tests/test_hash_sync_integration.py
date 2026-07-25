# tests/test_hash_sync_integration.py
"""Integration test: ThreatFox feed → sync_hashes_from_threatfox → _KNOWN_BAD_HASHES.

Verifies the wiring that was missing: register_malicious_hash was never
called from anywhere outside process_analyzer.py, so the T1027 check
was a no-op in production. This test confirms the background sync job
populates the set with real ThreatFox sha256 IOCs.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_sync_hashes_from_threatfox_populates_known_bad_set():
    """sync_hashes_from_threatfox pulls ThreatFox sha256 IOCs into the set."""
    from services.process_analyzer import (
        _KNOWN_BAD_HASHES,
        known_bad_hash_count,
        sync_hashes_from_threatfox,
    )

    # Mock ThreatFox response with 2 sha256 IOCs + 1 non-sha256 (should be skipped)
    mock_iocs = [
        {"ioc": "a" * 64, "ioc_type": "sha256_hash", "confidence_level": 80},
        {"ioc": "b" * 64, "ioc_type": "sha256_hash", "confidence_level": 90},
        {"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "confidence_level": 70},
        {"ioc": "c" * 40, "ioc_type": "sha1_hash", "confidence_level": 60},
    ]
    before = known_bad_hash_count()
    try:
        with patch(
            "services.threat_feeds._fetch_threatfox_sync",
            return_value=mock_iocs,
        ):
            added = await sync_hashes_from_threatfox()

        assert added == 2  # only the 2 sha256_hash IOCs
        assert ("a" * 64) in _KNOWN_BAD_HASHES
        assert ("b" * 64) in _KNOWN_BAD_HASHES
        assert ("c" * 40) not in _KNOWN_BAD_HASHES  # sha1, not sha256
    finally:
        _KNOWN_BAD_HASHES.discard("a" * 64)
        _KNOWN_BAD_HASHES.discard("b" * 64)


@pytest.mark.asyncio
async def test_sync_hashes_handles_fetch_failure():
    """If ThreatFox fetch raises, sync returns 0 and doesn't crash."""
    from services.process_analyzer import sync_hashes_from_threatfox

    with patch(
        "services.threat_feeds._fetch_threatfox_sync",
        side_effect=RuntimeError("Network down"),
    ):
        added = await sync_hashes_from_threatfox()

    assert added == 0


@pytest.mark.asyncio
async def test_sync_hashes_skips_already_registered():
    """Re-running sync doesn't double-count already-registered hashes."""
    from services.process_analyzer import (
        _KNOWN_BAD_HASHES,
        sync_hashes_from_threatfox,
    )

    mock_iocs = [
        {"ioc": "d" * 64, "ioc_type": "sha256_hash", "confidence_level": 80},
    ]
    _KNOWN_BAD_HASHES.add("d" * 64)  # pre-register
    try:
        with patch(
            "services.threat_feeds._fetch_threatfox_sync",
            return_value=mock_iocs,
        ):
            added = await sync_hashes_from_threatfox()

        assert added == 0  # already in set
    finally:
        _KNOWN_BAD_HASHES.discard("d" * 64)
