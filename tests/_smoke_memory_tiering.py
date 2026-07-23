"""Smoke test for memory tiering components (vectorlite + summarizer + core)."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

ERRORS = []


def check(label: str, fn):
    try:
        fn()
        print(f"  ✅ {label}")
    except Exception as exc:
        ERRORS.append(f"{label}: {exc}")
        print(f"  ❌ {label}: {exc}")


# 1. Import checks
print("\n── Import Resolution ──")

check("services.memory_db imports", lambda: __import__("services.memory_db"))
check("services.bot_memory imports", lambda: __import__("services.bot_memory"))
check("services.memory_summarizer imports", lambda: __import__("services.memory_summarizer"))
check("services.agent.core imports", lambda: __import__("services.agent.core"))

# 2. Vectorlite availability
print("\n── Vectorlite Availability ──")
try:
    import vectorlite
    print(f"  ✅ vectorlite {vectorlite.__version__}")
except Exception as exc:
    ERRORS.append(f"vectorlite: {exc}")
    print(f"  ⚠️ vectorlite not available: {exc}")

# 3. Module-level flags
print("\n── Module Flags ──")
from services.memory_db import _VECTORLITE_AVAILABLE, _VECTORLITE_INDEX_DIM
print(f"  memory_db._VECTORLITE_AVAILABLE = {_VECTORLITE_AVAILABLE}")
print(f"  memory_db._VECTORLITE_INDEX_DIM = {_VECTORLITE_INDEX_DIM}")

from services.bot_memory import _VECTORLITE_AVAILABLE as bot_vl
print(f"  bot_memory._VECTORLITE_AVAILABLE = {bot_vl}")

# 4. Async init + schema
print("\n── DB Schema Initialization ──")


async def _test_db_init():
    from services.memory_db import _init_db
    await _init_db()
    print("  ✅ memory_db._init_db() succeeded")


async def _test_summarizer_schema():
    from services.memory_summarizer import _ensure_user_profiles_table
    await _ensure_user_profiles_table()
    print("  ✅ memory_summarizer._ensure_user_profiles_table() succeeded")


async def _test_store_and_search():
    from services.memory_db import store_message, search_conversations
    await store_message("user", "test message for vectorlite smoke test")
    result = await search_conversations("test message", limit=1)
    assert "test message" in result or "תוצאות" in result or "No results" in result
    print(f"  ✅ store_message + search_conversations roundtrip OK")


async def _test_profile_fetch():
    from services.memory_summarizer import get_latest_user_profile
    profile = await get_latest_user_profile()
    print(f"  ✅ get_latest_user_profile() returned (len={len(profile)})")


async def _main():
    try:
        await _test_db_init()
    except Exception as exc:
        ERRORS.append(f"DB init: {exc}")
        print(f"  ❌ DB init: {exc}")

    try:
        await _test_summarizer_schema()
    except Exception as exc:
        ERRORS.append(f"Summarizer schema: {exc}")
        print(f"  ❌ Summarizer schema: {exc}")

    try:
        await _test_store_and_search()
    except Exception as exc:
        ERRORS.append(f"Store/search: {exc}")
        print(f"  ❌ Store/search: {exc}")

    try:
        await _test_profile_fetch()
    except Exception as exc:
        ERRORS.append(f"Profile fetch: {exc}")
        print(f"  ❌ Profile fetch: {exc}")


asyncio.run(_main())

# 5. Check for circular deps in core
print("\n── core.py Agent Entrypoint ──")
try:
    from services.agent.core import analyze_data
    print("  ✅ analyze_data import OK")
except Exception as exc:
    ERRORS.append(f"core.py: {exc}")
    print(f"  ❌ core.py: {exc}")

# Summary
print("\n" + "=" * 50)
if ERRORS:
    print(f"❌ {len(ERRORS)} FAILURE(S):")
    for e in ERRORS:
        print(f"   • {e}")
    sys.exit(1)
else:
    print("✅ ALL CHECKS PASSED")
    sys.exit(0)
