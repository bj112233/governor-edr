# services/agent/bypass/stocks.py
import asyncio
import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

logger = logging.getLogger(__name__)

_KNOWN_TICKERS: frozenset[str] = frozenset(
    [
        "NVDA",
        "AAPL",
        "MSFT",
        "GOOG",
        "GOOGL",
        "AMZN",
        "META",
        "TSLA",
        "AMD",
        "INTC",
        "NFLX",
        "UBER",
        "IBM",
        "ORCL",
        "AVGO",
        "CRM",
        "BABA",
        "SPY",
        "QQQ",
        "VTI",
        "GLD",
        "DIA",
        "ARKK",
        "TEVA",
        "CHKP",
        "NICE",
        "MNDY",
        "WIX",
    ]
)


def _detect_stock_query(q: str) -> str | None:
    """Return ticker symbol if this is a stock/crypto price request, else None."""
    # Don't trigger if user is asking for text/file analysis
    if any(kw in q.lower() for kw in ("נתח", "analyze", "קובץ", "file", "טקסט", "text")):
        return None

    m = re.search(r"\b([A-Z]{2,5})\b", q)
    if not m:
        return None
    ticker = m.group(1)
    has_stock_kw = any(kw in q.lower() for kw in ("מניה", "מחיר", "stock", "quote", "price", "share", "סטוק", "בורסה"))
    if ticker in _KNOWN_TICKERS or has_stock_kw:
        return ticker
    return None


async def _direct_stock_bypass(ticker: str, user_question: str) -> str:
    """Deterministic bypass: call skill_stocks-skill directly, return verbatim."""
    engine = get_skills_engine()
    logger.info(f"[AGENT] Stock bypass: ticker={ticker}")
    try:
        result = await engine.execute("stocks-skill", "quote", f"--symbol {ticker}")
    except Exception as e:
        logger.error(f"[AGENT] Stock bypass failed: {e}")
        return f"⚠️ שגיאה בשאילת נתוני {ticker}."
    if not result or result.startswith("❌"):
        return f"⚠️ לא ניתן לקבל נתונים עבור {ticker}."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
