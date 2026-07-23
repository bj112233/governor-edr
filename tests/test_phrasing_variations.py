"""Test multiple phrasing variations per skill to validate LLM tool calling accuracy."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent import run_agent

TEST_QUERIES = [
    (
        "weather",
        ["מזג אוויר בתל אביב", "weather in tel aviv", "תחזית מזג אוויר ירושלים"],
    ),
    ("currency", ["100 דולר לשקל", "convert 50 eur to ils", "המר 1000 ין לדולר"]),
    ("stocks", ["מחיר NVDA", "stock price AAPL", "טיקר TSLA"]),
    ("news", ["חדשות ארציות", "israel news today", "חדשות כלכלה"]),
    ("geocode", ["כתובת רחביה 1 תל אביב", "geocode haifa", "מרחק תל אביב חיפה"]),
    (
        "translation",
        ["תרגם hello לעברית", "translate shalom to english", "תרגום goodbye"],
    ),
    ("intel", ["dns google.com", "ip 8.8.8.8", "whois example.com"]),
    ("firewall", ["חסימות פיירוול", "firewall drops", "רשימת חסימות"]),
    ("crypto", ["bitcoin price", "מחיר אתריום", "crypto BTC"]),
    ("system", ["דוח יומי על המערכת", "system report", "מצב מערכת"]),
]


async def test_query(query: str) -> dict:
    try:
        response = await run_agent(query)
        return {"query": query, "success": True, "response": str(response)[:200]}
    except Exception as e:
        return {"query": query, "success": False, "error": str(e)[:200]}


async def main():
    results = []
    for skill, queries in TEST_QUERIES:
        print(f"\n=== {skill} ===")
        for q in queries:
            result = await test_query(q)
            results.append(result)
            marker = "✅" if result["success"] else "❌"
            print(f"{marker} {q[:60]}")

    with open("state/phrasing_test_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("\nSaved to state/phrasing_test_results.json")


if __name__ == "__main__":
    asyncio.run(main())
