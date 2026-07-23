# services/agent/_bypasses.py
"""Bypass dispatcher: routes simple queries directly to skills without LLM."""

import logging
from collections.abc import Awaitable, Callable

from config import ENABLE_NEWS_BYPASS
from services.agent.bypass.crypto import _detect_crypto_query, _direct_crypto_bypass
from services.agent.bypass.currency import (
    _TRANSLATION_INTENT_RE,
    _detect_currency_query,
    _direct_currency_bypass,
)
from services.agent.bypass.cve import _try_cve_bypass
from services.agent.bypass.elaborate import (
    _detect_elaborate_query,
    _direct_elaborate_bypass,
)
from services.agent.bypass.eml import _try_eml_bypass
from services.agent.bypass.file_path import _try_file_path_bypass
from services.agent.bypass.firewall import _detect_firewall_query, _direct_firewall_bypass
from services.agent.bypass.geocode import _detect_geocode_query, _direct_geocode_bypass
from services.agent.bypass.intel import _detect_intel_query, _direct_intel_bypass
from services.agent.bypass.news import _detect_news_topic, _direct_news_bypass
from services.agent.bypass.pcap import _try_pcap_bypass
from services.agent.bypass.process import _try_process_bypass
from services.agent.bypass.stocks import _detect_stock_query, _direct_stock_bypass

# Top-level imports: Fail-Loud on missing dependencies, zero overhead in hot path.
from services.agent.bypass.sysreport import _detect_sysreport_query, _direct_sysreport_bypass
from services.agent.bypass.translation import _direct_translation_bypass
from services.agent.bypass.weather import _detect_weather_query, _direct_weather_bypass
from services.agent.bypass.yara import _try_yara_bypass

__all__ = ["_BYPASS_HANDLERS"]

logger = logging.getLogger(__name__)


async def _try_sysreport_bypass(q: str) -> str | None:
    if _detect_sysreport_query(q):
        logger.info("[AGENT] Sysreport bypass activated")
        return await _direct_sysreport_bypass(q)
    return None


async def _try_stock_bypass(q: str) -> str | None:
    ticker = _detect_stock_query(q)
    if ticker:
        logger.info("[AGENT] Stock bypass activated: ticker=%s", ticker)
        return await _direct_stock_bypass(ticker, q)
    return None


async def _try_elaborate_bypass(q: str) -> str | None:
    if _detect_elaborate_query(q):
        logger.info("[AGENT] Elaborate bypass: trigger matched — querying memory")
        result = await _direct_elaborate_bypass(q)
        if result is not None:
            logger.info("[AGENT] Elaborate bypass activated")
            return result
        logger.info("[AGENT] Elaborate bypass: no prior context, falling through")
    return None


async def _try_translation_bypass(q: str) -> str | None:
    """Translation bypass — unified with real translator skill."""
    if _TRANSLATION_INTENT_RE:
        intent_match = _TRANSLATION_INTENT_RE.search(q)
        if intent_match:
            logger.info("[AGENT] Translation bypass activated (priority over currency)")
            return await _direct_translation_bypass(q)
    if any(kw in q.lower() for kw in ("תרגם", "תרגום", "translate", "translation")):
        logger.info("[AGENT] Translation bypass activated")
        return await _direct_translation_bypass(q)
    return None


async def _try_currency_bypass(q: str) -> str | None:
    if _detect_currency_query(q):
        logger.info("[AGENT] Currency bypass activated")
        return await _direct_currency_bypass(q)
    return None


async def _try_weather_bypass(q: str) -> str | None:
    location = _detect_weather_query(q)
    if location:
        logger.info("[AGENT] Weather bypass activated: location=%r", location)
        return await _direct_weather_bypass(location, q)
    return None


async def _try_geocode_bypass(q: str) -> str | None:
    if any(kw in q.lower() for kw in ("סכם", "סיכום", "תמצת", "תקציר")):
        return None
    result = _detect_geocode_query(q)
    if result:
        from_loc, to_loc, query_type = result
        logger.info(
            "[AGENT] Geocode bypass activated: %s from=%r to=%r",
            query_type,
            from_loc,
            to_loc,
        )
        return await _direct_geocode_bypass(from_loc, to_loc, query_type, q)
    return None


async def _try_news_bypass(q: str) -> str | None:
    if "הטקסט שחולץ מהתמונה" in q or "תוכן המסמך:" in q:
        return None
    if not ENABLE_NEWS_BYPASS:
        logger.info("[AGENT] News bypass disabled — routing through LLM tool-calling")
        return None
    topic = _detect_news_topic(q)
    if topic:
        logger.info("[AGENT] News bypass activated: topic=%s", topic)
        return await _direct_news_bypass(topic, q)
    return None


async def _try_intel_bypass(q: str) -> str | None:
    result = _detect_intel_query(q)
    if result:
        command, target = result
        logger.info("[AGENT] Intel bypass activated: %s target=%s", command, target)
        return await _direct_intel_bypass(command, target, q)
    return None


async def _try_crypto_bypass(q: str) -> str | None:
    result = _detect_crypto_query(q)
    if result:
        command, args = result
        logger.info("[AGENT] Crypto bypass activated: %s", command)
        return await _direct_crypto_bypass(command, args, q)
    return None


async def _try_firewall_bypass(q: str) -> str | None:
    result = _detect_firewall_query(q)
    if result:
        command, args = result
        logger.info("[AGENT] Firewall bypass activated: %s", command)
        return await _direct_firewall_bypass(command, args, q)
    return None


# Registry: ordered list of bypass handlers.
# Order matters: CVE → sysreport → intel → firewall → crypto → yara → process → pcap → eml → file_path → stock → elaborate → translation → currency → weather → geocode → news
# CVE before intel: prevents "CVE-2024-3094" from being misrouted
# Intel/firewall before stock: prevents "8.8.8.8" from matching stock ticker regex
# Firewall before crypto: prevents "block" keyword overlap
# YARA before file_path: YARA scans need the file path too but route to a different tool
# pcap/eml before file_path: specific extensions bypass generic file-analyst
_BYPASS_HANDLERS: list[Callable[[str], Awaitable[str | None]]] = [
    _try_cve_bypass,
    _try_sysreport_bypass,
    _try_intel_bypass,
    _try_firewall_bypass,
    _try_crypto_bypass,
    _try_yara_bypass,
    _try_process_bypass,
    _try_pcap_bypass,
    _try_eml_bypass,
    _try_file_path_bypass,
    _try_stock_bypass,
    _try_elaborate_bypass,
    _try_translation_bypass,
    _try_currency_bypass,
    _try_weather_bypass,
    _try_geocode_bypass,
    _try_news_bypass,
]
