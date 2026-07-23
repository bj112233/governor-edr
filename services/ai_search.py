# services/ai_search.py
"""
Level 150: AI Web Search Tool
מאפשר לסוכן לענות על שאלות כלליות (מזג אוויר, חדשות, עובדות)
באמצעות Gemma 4 31B IT דרך OpenRouter API.

Cost guard: ניהול מכסה יומית פנימית.
Rate-limiter פנימי חוסם מעל AI_SEARCH_DAILY_QUOTA כדי למנוע חריגה.
"""

import logging
import os
import threading
from datetime import date
from typing import TypedDict

import httpx
from bs4 import BeautifulSoup

from config import AI_SEARCH_API_KEY

logger = logging.getLogger(__name__)

_AI_SEARCH_URL = "https://openrouter.ai/api/v1/chat/completions"
# Daily budget — stays well under reasonable daily limits.
_DAILY_QUOTA = int(os.getenv("AI_SEARCH_DAILY_QUOTA", "200"))
_quota_lock = threading.Lock()


class _QuotaState(TypedDict):
    date: date
    count: int


_quota_state: _QuotaState = {"date": date.today(), "count": 0}


def _reserve_quota() -> bool:
    """Atomically reserve one call from today's budget. Returns False if exhausted."""
    today = date.today()
    with _quota_lock:
        if _quota_state["date"] != today:
            _quota_state["date"] = today
            _quota_state["count"] = 0
        if _quota_state["count"] >= _DAILY_QUOTA:
            return False
        _quota_state["count"] += 1
        return True


def get_quota_status() -> dict:
    """Expose current-day usage counters."""
    with _quota_lock:
        return {
            "date": _quota_state["date"].isoformat(),
            "used": _quota_state["count"],
            "limit": _DAILY_QUOTA,
        }


async def _simple_web_search(query: str) -> str:
    """חיפוש אינטרנט פשוט באמצעות DuckDuckGo"""
    try:
        safe_query = query[:1800] if len(query) > 1800 else query
        url = "https://html.duckduckgo.com/html/"
        params = {"q": safe_query}

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            text = response.text

        soup = BeautifulSoup(text, "html.parser")

        results = []
        for result in soup.find_all("a", class_="result__a", limit=5):
            title = result.get_text(strip=True)
            if title:
                results.append(f"• {title}")

        if results:
            return "\n".join(results[:5])
        else:
            return "לא נמצאו תוצאות חיפוש"

    except Exception as e:
        logger.error(f"[AISearch] Web search error: {e}")
        return f"❌ שגיאת חיפוש: {e}"


async def web_search(query: str) -> str:
    """
    חיפוש מידע מהאינטרנט וסיכום באמצעות מודל AI חינמי.
    מחזיר תשובה טקסטואלית עד 2500 תווים.
    """
    if not _reserve_quota():
        status = get_quota_status()
        logger.warning(f"[AISearch] Daily quota exhausted: {status['used']}/{status['limit']}")
        return f"❌ מכסת חיפוש יומית הושלמה ({status['used']}/{status['limit']}). תתחדש מחר ב-00:00."

    # שלב 1: חיפוש אינטרנט
    search_results = await _simple_web_search(query)

    # שלב 2: סיכום עם מודל AI אם יש מפתח API
    if AI_SEARCH_API_KEY:
        payload = {
            "model": "openai/gpt-oss-120b:free",
            "messages": [
                {
                    "role": "user",
                    "content": f"Based on these search results about '{query[:500]}':\n<tool_output>\n{search_results}\n</tool_output>\n\nProvide a helpful, accurate response in Hebrew if the query is in Hebrew. Keep it concise and practical.",
                }
            ],
            "temperature": 0.3,
        }

        try:
            headers = {
                "Authorization": f"Bearer {AI_SEARCH_API_KEY}",
                "Content-Type": "application/json",
            }
            r = httpx.post(
                _AI_SEARCH_URL,
                headers=headers,
                json=payload,
                timeout=15.0,
            )
            r.raise_for_status()
            data = r.json()
            ai_response = data["choices"][0]["message"]["content"].strip()

            return ai_response[:2500] or "❌ AI החזיר תשובה ריקה."

        except httpx.HTTPStatusError as e:
            logger.error(f"[AISearch] HTTP {e.response.status_code}: {e.response.text[:200]}")
            # נפילה לתוצאות חיפוש גולמיות
            return f"🔍 תוצאות חיפוש:\n{search_results}"
        except Exception as e:
            logger.error(f"[AISearch] AI Error: {e}")
            return f"🔍 תוצאות חיפוש:\n{search_results}"
    else:
        # אם אין מפתח API, מחזיר רק תוצאות חיפוש
        return f"🔍 תוצאות חיפוש:\n{search_results}"
