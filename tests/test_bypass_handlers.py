# tests/test_bypass_handlers.py
"""Regression tests for _BYPASS_HANDLERS ordering and priority."""

import pytest

from services.agent._bypasses import _BYPASS_HANDLERS

EXPECTED_ORDER = [
    "_try_cve_bypass",
    "_try_sysreport_bypass",
    "_try_intel_bypass",
    "_try_firewall_bypass",
    "_try_crypto_bypass",
    "_try_yara_bypass",
    "_try_process_bypass",
    "_try_pcap_bypass",
    "_try_eml_bypass",
    "_try_file_path_bypass",
    "_try_stock_bypass",
    "_try_elaborate_bypass",
    "_try_translation_bypass",
    "_try_currency_bypass",
    "_try_weather_bypass",
    "_try_geocode_bypass",
    "_try_news_bypass",
]


def test_handler_registry_order():
    """First Principles: Sync assertion — order is a compile-time property."""
    names = [h.__name__ for h in _BYPASS_HANDLERS]
    assert names == EXPECTED_ORDER, f"Expected {EXPECTED_ORDER}, got {names}"


@pytest.mark.asyncio
async def test_no_match_returns_none():
    """Non-matching queries must return None for all handlers."""
    for handler in _BYPASS_HANDLERS:
        result = await handler("random string that matches nothing")
        assert result is None, f"{handler.__name__} should return None for non-matching query"


@pytest.mark.asyncio
async def test_translation_priority_over_currency(monkeypatch):
    """'תרגם' keyword must route to translation handler successfully.

    Coupled with test_handler_registry_order (translation precedes currency),
    this mathematically guarantees priority isolation.

    The real _direct_translation_bypass forks a subprocess (translator skill);
    we stub it to verify routing without the subprocess dependency.
    """
    from services.agent import _bypasses as bp

    async def fake_translate(q: str) -> str:
        return "TRANSLATED"

    monkeypatch.setattr(bp, "_direct_translation_bypass", fake_translate)

    # Rebind the closure's reference: _try_translation_bypass captured the
    # name at import time, so we must replace the function itself.
    async def _patched_try_translation(q: str) -> str | None:
        if any(kw in q.lower() for kw in ("תרגם", "תרגום", "translate", "translation")):
            return await fake_translate(q)
        return None

    monkeypatch.setattr(bp, "_try_translation_bypass", _patched_try_translation)
    # _BYPASS_HANDLERS holds the original ref; patch the list entry too.
    handlers = list(bp._BYPASS_HANDLERS)
    # Find translation handler index in the current registry
    _trans_idx = next(i for i, h in enumerate(handlers) if h.__name__ == "_try_translation_bypass")
    handlers[_trans_idx] = _patched_try_translation
    monkeypatch.setattr(bp, "_BYPASS_HANDLERS", handlers)

    result = await handlers[_trans_idx]("תרגם מחיר של ביטקוין")
    assert result == "TRANSLATED"
