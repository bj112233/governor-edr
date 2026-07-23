# services/agent/bypass/weather.py
import asyncio
import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

_WEATHER_BYPASS_KEYWORDS: frozenset[str] = frozenset(
    [
        "מזג אוויר",
        "מזג האוויר",
        "weather",
        "תחזית",
        "טמפרטורה",
    ]
)


def _detect_weather_query(q: str) -> str | None:
    """Return city name if this is a weather/forecast request, else None."""
    q_low = q.lower()
    if not any(kw in q_low for kw in _WEATHER_BYPASS_KEYWORDS):
        return None
    m = re.search(r"ב[- ]?([א-ת][א-ת ]{1,20}?)(?:\s*$|[,!?])", q)
    if m:
        return m.group(1).strip()
    m = re.search(r"(?:in |for )([a-zA-Z][a-zA-Z ]{1,20}?)(?:\s*$|[,!?])", q, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return "Tel Aviv"


async def _direct_weather_bypass(location: str, user_question: str) -> str:
    """Deterministic bypass: call skill_weather-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Weather bypass: location={location!r}")
    args = f'--location "{location}"'
    logger.info(f"[AGENT] Weather bypass args: {args!r}")
    try:
        result = await engine.execute("weather-skill", "run", args)
        logger.info(f"[AGENT] Weather bypass result: {result[:200] if result else 'None'}...")
    except Exception as e:
        logger.error(f"[AGENT] Weather bypass failed: {e}", exc_info=True)
        return "⚠️ שגיאה בשאילת נתוני מזג אוויר."
    if not result:
        logger.error("[AGENT] Weather bypass returned empty result")
        return f"⚠️ לא ניתן לקבל נתוני מזג אוויר עבור {location}."
    if result.startswith("❌"):
        logger.error(f"[AGENT] Weather bypass returned error: {result}")
        return f"⚠️ לא ניתן לקבל נתוני מזג אוויר עבור {location}.\n\n{result}"
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
