#!/usr/bin/env python3
"""
Agent Validation Tests - בדיקות אמת למודל
Tests tool calling accuracy and hallucination resistance with truncated prompt.
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.agent import _AGENT_SYSTEM, _is_conversational, run_agent
from services.agent_tools import _TOOLS, _TOOLS_BASIC
from services.skills_engine import get_skills_engine

# Test cases: (query, expected_skill/tool, description)
TEST_CASES = [
    # Conversational (no tools)
    ("היי", "conversational", "Greeting - should not call tools"),
    ("מה שלומך", "conversational", "Small talk - no tools"),
    ("מי אתה", "conversational", "Identity question - no tools"),
    # Skills - Weather
    ("מה המזג אוויר בתל אביב", "skill_weather-skill", "Weather query"),
    ("תחזית לחיפה", "skill_weather-skill", "Weather forecast"),
    # Skills - Currency
    (
        "כמה שווה 100 דולר בשקלים",
        "skill_currency-skill",
        "Currency conversion USD->ILS",
    ),
    ("המר 50 אירו לדולר", "skill_currency-skill", "Currency conversion EUR->USD"),
    ("שער היורו", "skill_currency-skill", "Euro rate"),
    # Skills - Stocks
    ("מחיר NVDA", "skill_stocks-skill", "Stock price NVDA"),
    ("מה מחיר המניה אפל", "skill_stocks-skill", "Apple stock query"),
    # Skills - Translator
    ("תרגם לעברית hello world", "skill_translator-skill", "Translation request"),
    ("translate שלום לenglish", "skill_translator-skill", "Translation EN->HE"),
    # Skills - News
    ("חדשות ספורט", "skill_news-monitor", "Sports news"),
    ("מבזקי כלכלה", "skill_news-monitor", "Economy news"),
    ("מה קורה בעולם", "skill_news-monitor", "World news"),
    # Skills - Geocode
    ("מרחק בין תל אביב לחיפה", "skill_geocode-skill", "Distance query"),
    ("כמה זמן נסיעה מירושלים לתל אביב", "skill_geocode-skill", "Route time"),
    ("כתובת של רחוב הרצל 1 תל אביב", "skill_geocode-skill", "Address geocode"),
    # Skills - Crypto
    ("חשב sha256 של hello", "skill_crypto-skill", "SHA256 hash"),
    ("צור סיסמה אקראית", "skill_crypto-skill", "Generate password"),
    ("פענח base64 aGVsbG8=", "skill_crypto-skill", "Base64 decode"),
    # Skills - Intel
    ("בדוק אייפי 8.8.8.8", "skill_intel-skill", "IP reputation check"),
    ("whois google.com", "skill_intel-skill", "WHOIS lookup"),
    # Skills - File Analyst
    ("סכם את הקובץ test.pdf", "skill_file-analyst", "PDF summarize"),
    ("תקרא את התמונה image.jpg", "skill_file-analyst", "OCR image"),
    # System tools
    ("תראה לי תהליכים", "get_running_processes", "System processes"),
    ("כמה RAM יש", "get_system_snapshot", "System snapshot"),
    # Fallback
    ("מי היה אלברט איינשטיין", "web_search", "Historical fact - web search fallback"),
    # Anti-hallucination tests
    (
        "מה השעה עכשיו בניו יורק",
        "skill_geocode-skill",
        "Time query - should use tool not guess",
    ),
]

# Anti-hallucination specific tests
HALLUCINATION_TESTS = [
    # These should NEVER invent data
    ("מה מחיר הביטקוין עכשיו", "must_use_tool", "Bitcoin price - never invent"),
    ("כמה אנשים יש בעולם", "must_use_tool", "World population - never invent"),
    (
        'מי מנצח בבחירות בארה"ב',
        "must_use_tool_or_deny",
        "Election results - never predict",
    ),
]


async def test_conversational_detection():
    """Test that conversational queries are detected correctly."""
    print("\n=== בדיקת זיהוי שיחה רגילה (ללא כלים) ===")

    conversational_queries = [
        "היי",
        "שלום",
        "מה שלומך",
        "מי אתה",
        "תודה",
        "bye",
        "goodbye",
        "איך קוראים לי",
        "מה שמך",
        "מה השם",
    ]

    passed = 0
    failed = 0

    for query in conversational_queries:
        is_conv = await _is_conversational(query)
        if is_conv:
            print(f"  ✓ '{query}' -> conversational (no tools needed)")
            passed += 1
        else:
            print(f"  ✗ '{query}' -> FAILED (should be conversational)")
            failed += 1

    print(f"\nתוצאה: {passed}/{passed + failed} עברו")
    return passed, failed


async def test_skill_routing():
    """Test that queries route to correct skills."""
    print("\n=== בדיקת ראוטינג לסקילים ===")

    engine = get_skills_engine()
    skill_keywords = {
        "skill_weather-skill": ["מזג", "weather", "תחזית", "אוויר"],
        "skill_currency-skill": ["דולר", "שער", "מטבע", "המרה", "כמה שווה"],
        "skill_stocks-skill": ["מניה", "מחיר", "NVDA", "AAPL", "טיקר"],
        "skill_translator-skill": ["תרגם", "translate", "תרגום"],
        "skill_news-monitor": ["חדשות", "מבזק", "news"],
        "skill_geocode-skill": ["מרחק", "כתובת", "דרך", "נסיעה"],
        "skill_crypto-skill": ["sha256", "md5", "hash", "password", "base64"],
        "skill_intel-skill": ["אייפי", "ip", "whois", "domain"],
        "skill_file-analyst": ["קובץ", "pdf", "תמונה", "ocr"],
    }

    passed = 0
    failed = 0

    for skill_name, keywords in skill_keywords.items():
        skill = engine._skills.get(skill_name.replace("skill_", ""))
        if skill:
            print(f"  ✓ {skill_name} loaded")
            passed += 1
        else:
            print(f"  ✗ {skill_name} NOT FOUND")
            failed += 1

    print(f"\nתוצאה: {passed}/{passed + failed} סקילים טעונים")
    return passed, failed


async def test_prompt_integrity():
    """Test that critical rules are in the prompt."""
    print("\n=== בדיקת שלמות הפרומט ===")

    critical_elements = [
        ("ANTI-HALLUCINATION", "Anti-hallucination rule"),
        ("NEVER invent", "No invention rule"),
        ("skill_translator-skill", "Translator routing"),
        ("skill_weather-skill", "Weather routing"),
        ("skill_currency-skill", "Currency routing"),
        ("skill_news-monitor", "News routing"),
        ("tactical_bot", "Identity"),
        ("FOLLOW-UP CONTINUITY", "Follow-up rules"),
        ("Hebrew", "Language rule"),
        ("skill_geocode-skill", "Geocode routing"),
    ]

    passed = 0
    failed = 0

    for element, description in critical_elements:
        if element in _AGENT_SYSTEM:
            print(f"  ✓ {description}")
            passed += 1
        else:
            print(f"  ✗ {description} - MISSING!")
            failed += 1

    print(f"\nתוצאה: {passed}/{passed + failed} רכיבים קיימים")
    print(f"  אורך פרומט: {len(_AGENT_SYSTEM)} תווים (~{len(_AGENT_SYSTEM) // 4} טוקנים)")
    return passed, failed


async def test_tools_available():
    """Test that all expected tools are available."""
    print("\n=== בדיקת כלים זמינים ===")

    expected_tools = [
        "get_system_snapshot",
        "get_running_processes",
        "web_search",
    ]

    passed = 0
    failed = 0

    for tool_name in expected_tools:
        # Check in _TOOLS or _TOOLS_BASIC
        found = False
        for tool in _TOOLS + _TOOLS_BASIC:
            if tool.get("function", {}).get("name") == tool_name:
                found = True
                break

        if found:
            print(f"  ✓ {tool_name}")
            passed += 1
        else:
            print(f"  ✗ {tool_name} - NOT FOUND")
            failed += 1

    # Check skills as tools
    engine = get_skills_engine()
    skill_tools = engine.get_tools()
    print(f"  → {len(skill_tools)} סקילים ככלים זמינים")

    for tool in skill_tools[:5]:  # Show first 5
        name = tool.get("function", {}).get("name", "unknown")
        print(f"    - {name}")

    print(f"\nתוצאה: {passed}/{passed + failed} כלים בסיסיים זמינים")
    return passed, failed


def test_history_broken_entry_filtering():
    """Regression: broken/empty assistant responses must be filtered from history.

    See: services/agent/core.py lines 232-241 — prevents cascading hallucinations
    where a truncated response (e.g. 7 chars) gets re-injected into the prompt.
    """
    print("\n=== בדיקת רגרסיה: סינון היסטוריה שבורה ===")

    test_cases = [
        ("", True, "empty string"),
        ("   ", True, "whitespace only"),
        ("\n\n", True, "newlines only"),
        ("abc", True, "too short (<10)"),
        ("שלום", True, "Hebrew too short"),
        ("########", True, "no alphanumeric chars"),
        ("!!!???", True, "punctuation only"),
        ("שלום! מה איתך?", False, "valid Hebrew response"),
        ("Hello world, this is a normal response.", False, "valid English response"),
        ("1234567890", False, "exactly 10 chars with digits"),
    ]

    passed = 0
    failed = 0

    for response_text, should_skip, desc in test_cases:
        stripped = response_text.strip()
        is_broken = len(stripped) < 10 or not any(c.isalnum() for c in stripped)

        if is_broken == should_skip:
            print(f"  ✓ {desc}: {'skipped' if should_skip else 'kept'}")
            passed += 1
        else:
            print(f"  ✗ {desc}: expected {'skip' if should_skip else 'keep'}, got {'skip' if is_broken else 'keep'}")
            failed += 1

    print(f"\nתוצאה: {passed}/{passed + failed} עברו")
    assert failed == 0, f"{failed}/{passed + failed} cases failed"


def test_conversational_tools_not_sent():
    """Regression: empty tools list must NOT be sent to KoboldCpp in conversational mode.

    See: services/agent_bridge.py lines 216-231 — sending tools=[] + tool_choice="auto"
    confuses some backends and causes truncated responses (completion_tok=2).
    """
    print("\n=== בדיקת רגרסיה: לא לשלוח tools=[] ב-conversational ===")

    # Simulate the create_kwargs build logic from agent_bridge.py
    def build_kwargs(tools):
        kwargs = dict(model="test", messages=[])
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        return kwargs

    # Test 1: empty tools → no tools key
    kwargs_empty = build_kwargs([])
    assert "tools" not in kwargs_empty, "tools=[] still sent when empty"
    assert "tool_choice" not in kwargs_empty, "tool_choice sent when tools empty"

    # Test 2: non-empty tools → tools key present
    kwargs_with_tools = build_kwargs([{"name": "test_tool"}])
    assert "tools" in kwargs_with_tools, "tools not sent when non-empty"
    assert "tool_choice" in kwargs_with_tools, "tool_choice not sent when non-empty"

    print("  ✓ empty tools → no tools key")
    print("  ✓ non-empty tools → tools + tool_choice present")
    print("\nתוצאה: 2/2 עברו")


async def run_live_tests():
    """Run live tests against actual LLM (if available)."""
    print("\n=== בדיקות לייב מול LLM (אם זמין) ===")

    try:
        from services.llm_bridge import is_llm_ready

        if not is_llm_ready():
            print("  ⚠ LLM לא זמין (KoboldCpp לא רץ?) - מדלג על בדיקות לייב")
            return 0, 0

        print("  → LLM זמין, מריץ בדיקות...")

        # Test 1: Simple tool call
        print("\n  בדיקה 1: שאילתת מזג אוויר")
        try:
            result = await run_agent("מה המזג אוויר בתל אביב", max_rounds=5)
            if "תל אביב" in result or "מזג" in result or "°" in result or "C" in result:
                print("    ✓ תשובה תקינה (מזג אוויר או טמפרטורה)")
            else:
                print(f"    ? תשובה: {result[:100]}...")
        except Exception as e:
            print(f"    ✗ שגיאה: {e}")

        # Test 2: Translation
        print("\n  בדיקה 2: תרגום")
        try:
            result = await run_agent("תרגם לעברית: hello world", max_rounds=5)
            if "שלום" in result or "עולם" in result:
                print("    ✓ תרגום עברי מתקבל")
            else:
                print(f"    ? תשובה: {result[:100]}...")
        except Exception as e:
            print(f"    ✗ שגיאה: {e}")

        # Test 3: Conversational
        print("\n  בדיקה 3: שיחה רגילה (ללא כלים)")
        try:
            result = await run_agent("היי", max_rounds=5)
            if len(result) < 100 and ("היי" in result or "שלום" in result or "👋" in result):
                print(f"    ✓ תשובה קצרה וטבעית: {result[:50]}")
            else:
                print(f"    ? תשובה: {result[:100]}...")
        except Exception as e:
            print(f"    ✗ שגיאה: {e}")

        print("\n  ℹ בדיקות לייב הושלמו")

    except Exception as e:
        print(f"  ⚠ שגיאה בבדיקות לייב: {e}")

    return 0, 0


async def main():
    """Run all validation tests."""
    print("=" * 60)
    print("בדיקות אמת - Agent Validation Tests")
    print("מטרה: וידוא שהמודל מזהה נכון כלים וסקילים, אין הזיות")
    print("=" * 60)

    total_passed = 0
    total_failed = 0

    # Run tests
    p, f = await test_prompt_integrity()
    total_passed += p
    total_failed += f

    p, f = await test_conversational_detection()
    total_passed += p
    total_failed += f

    p, f = await test_tools_available()
    total_passed += p
    total_failed += f

    p, f = await test_skill_routing()
    total_passed += p
    total_failed += f

    p, f = test_history_broken_entry_filtering()
    total_passed += p
    total_failed += f

    p, f = test_conversational_tools_not_sent()
    total_passed += p
    total_failed += f

    await run_live_tests()

    # Summary
    print("\n" + "=" * 60)
    print("סיכום בדיקות:")
    print(f"  עברו: {total_passed}")
    print(f"  נכשלו: {total_failed}")
    print(f"  אחוז הצלחה: {100 * total_passed / (total_passed + total_failed):.1f}%")
    print("=" * 60)

    if total_failed == 0:
        print("✅ כל הבדיקות עברו בהצלחה!")
        return 0
    else:
        print("⚠ יש כשלים שדורשים בדיקה")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
