# services/agent/bypass/geocode.py
import asyncio
import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

_GEOCODE_BYPASS_KEYWORDS: frozenset[str] = frozenset(
    [
        "מרחק",
        "נסיעה",
        "כתובת",
        "מיקום",
        "מפה",
        "geocode",
        "distance",
        "location",
        "address",
        "route",
        "זמן",
        "שעות",
        "דקות",
        "from",
    ]
)

# Route patterns tried in priority order: (from_loc, to_loc) extraction
_ROUTE_PATTERNS: tuple[str, ...] = (
    # מרחק בין X לY
    r"מרחק\s+בין\s+([א-ת][א-ת\s]{1,20}?)\s+ל([א-ת][א-ת\s]{1,20}?)(?:\s*$|[,!?])",
    # מרחק X לY (without "בין")
    r"מרחק\s*[::]?\s+([א-ת][א-ת\s]{1,20}?)\s+ל([א-ת][א-ת\s]{1,20}?)(?:\s*$|[,!?])",
    # מ-prefix attached to word (מראש, מתל, מחיפה) → לY
    r"(?:^|\s)מ([א-ת][א-ת\s]{1,20}?)\s+ל([א-ת][א-ת\s]{1,20}?)(?:\s*$|[,!?])",
    # "מ X לY" pattern (מ as separate word)
    r"מ(?:\s+(?:מרחק|נסיעה|כתובת|מיקום))?\s+([א-ת][א-ת\s]{1,20}?)\s+ל([א-ת][א-ת\s]{1,20}?)(?:\s*$|[,!?])",
    # from X to Y (English)
    r"from\s+(\w[\w\s]{1,20}?)\s+to\s+(\w[\w\s]{1,20}?)(?:\s*$|[,!?])",
)


def _detect_geocode_query(q: str) -> tuple[str, str, str] | None:
    """Return (from_loc, to_loc, query_type) if this is a geocode/distance request, else None.

    Recognizes patterns like:
    - 'מרחק מX לY'
    - 'כמה זמן נסיעה מX לY'
    - 'כתובת של X'
    """
    q_low = q.lower()
    if not any(kw in q_low for kw in _GEOCODE_BYPASS_KEYWORDS):
        return None

    # Route vs distance: if query mentions time/traffic → use route (HERE traffic)
    is_route = any(kw in q_low for kw in ["זמן", "נסיעה", "שעות", "דקות", "route", "drive", "time"])
    query_type = "route" if is_route else "distance"

    # Try route patterns (from/to) in priority order
    for pattern in _ROUTE_PATTERNS:
        m = re.search(pattern, q, re.IGNORECASE)
        if m:
            return (m.group(1).strip(), m.group(2).strip(), query_type)

    # Pattern: כתובת של X / address of X (forward geocoding)
    m = re.search(
        r"(?:כתובת|address)\s+(?:של\s+)?([א-ת][א-ת\s]{1,20}?|[a-zA-Z][a-zA-Z\s]{1,20}?)(?:\s*$|[,!?])",
        q,
    )
    if m:
        return (m.group(1).strip(), "", "forward")

    return None


async def _direct_geocode_bypass(from_loc: str, to_loc: str, query_type: str, user_question: str) -> str:
    """Deterministic bypass: call skill_geocode-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Geocode bypass: type={query_type} from={from_loc!r} to={to_loc!r}")
    try:
        if query_type == "route":
            result = await engine.execute(
                "geocode-skill",
                "route",
                f'--from "{from_loc}" --to "{to_loc}"',
            )
        elif query_type == "distance":
            result = await engine.execute(
                "geocode-skill",
                "distance",
                f'--from "{from_loc}" --to "{to_loc}"',
            )
        else:  # forward geocoding
            result = await engine.execute("geocode-skill", "forward", f'--address "{from_loc}"')
    except Exception as e:
        logger.error(f"[AGENT] Geocode bypass failed: {e}")
        return "⚠️ שגיאה בשאילת מיקום."
    if not result or result.startswith("❌"):
        return "⚠️ לא ניתן לקבל מידע על המיקום המבוקש."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
