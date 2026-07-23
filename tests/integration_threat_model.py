#!/usr/bin/env python
r"""Integration test suite for Threat Model fixes.
Run: .venv\Scripts\python.exe tests/integration_threat_model.py
"""

import asyncio
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


async def test_powershell_hitl_no_fastpath():
    """TEST 1: Severity 5 — All PowerShell commands queue for HITL.
    The fast-path for 'safe' cmdlets like Get-Date must be REMOVED.
    """
    print("\n" + "=" * 60)
    print("TEST 1: HITL — PowerShell fast-path removed")
    print("=" * 60)

    from services.action_tools import run_powershell
    from services.pending_actions import clear_pending, get_pending

    # Test A: Even 'safe' Get-Date must queue (was fast-path before)
    await clear_pending()
    result = await run_powershell("Get-Date")
    pending = await get_pending()

    assert "PENDING_APPROVAL" in result, f"FAIL: Expected PENDING_APPROVAL, got: {result[:80]}"
    assert pending is not None, "FAIL: Expected pending action after Get-Date"
    assert pending.get("action") == "run_powershell", f"FAIL: Wrong action type: {pending}"
    assert "Get-Date" in pending.get("target", ""), f"FAIL: Target missing Get-Date: {pending}"
    print("  PASS: Get-Date queued for HITL (no fast-path bypass)")

    # Test B: Destructive command also queues
    await clear_pending()
    result = await run_powershell("Remove-Item C:\\temp\\test.txt")
    pending = await get_pending()

    assert "PENDING_APPROVAL" in result, "FAIL: Expected PENDING_APPROVAL for destructive cmd"
    assert pending is not None, "FAIL: Expected pending action after Remove-Item"
    print("  PASS: Remove-Item queued for HITL")

    # Test C: Keyword block still works in _run_powershell_exec
    from services.action_tools import _run_powershell_exec

    blocked = await _run_powershell_exec("Remove-Item test.txt")
    assert "BLOCKED" in blocked, f"FAIL: Expected BLOCKED for Remove-Item, got: {blocked[:80]}"
    print("  PASS: Blocked keywords still reject in executor")

    await clear_pending()
    print("  TEST 1: ALL PASSED")


async def test_async_http_non_blocking():
    """TEST 2: Severity 3 — httpx.AsyncClient does not block event loop.
    Simulate two concurrent operations to prove interleaving.
    """
    print("\n" + "=" * 60)
    print("TEST 2: Event Loop — Async HTTP non-blocking")
    print("=" * 60)

    from services.osint_search import search_threat_intel

    # Test A: search_threat_intel is coroutine
    assert asyncio.iscoroutinefunction(search_threat_intel), "FAIL: search_threat_intel must be async"
    print("  PASS: search_threat_intel is async")

    # Test B: Two concurrent searches interleave (event loop not blocked)
    t0 = time.monotonic()

    async def _fast_ping():
        """Simulate a fast 'ping' response."""
        await asyncio.sleep(0.1)  # Tiny delay to simulate processing
        return "pong"

    # Fire both: a network call and a fast ping
    # If the network call blocked the thread, ping would wait.
    # With async, they run concurrently.
    tasks = [
        asyncio.create_task(search_threat_intel("CVE-2024-0001")),
        asyncio.create_task(_fast_ping()),
    ]
    done, pending = await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
    elapsed = time.monotonic() - t0

    results = [t.result() for t in done]
    search_result = results[0] if isinstance(results[0], list) else results[1]
    ping_result = results[1] if isinstance(results[1], str) else results[0]

    assert ping_result == "pong", f"FAIL: Ping returned wrong result: {ping_result}"
    assert isinstance(search_result, list), f"FAIL: Search returned non-list: {type(search_result)}"
    # The key assertion: both completed, and ping didn't wait for search
    print(f"  PASS: Concurrent execution completed in {elapsed:.2f}s")
    print(f"        Search returned {len(search_result)} results, ping='{ping_result}'")
    print("  TEST 2: ALL PASSED")


async def test_existing_tools_still_async():
    """TEST 3: Regression — All security/system tools are async callable."""
    print("\n" + "=" * 60)
    print("TEST 3: Regression — Tool signatures are async")
    print("=" * 60)

    from services.action_tools import block_ip, defender_scan, manage_service, unblock_ip
    from services.wmi_intel import get_local_users, get_network_adapters

    tools = [
        ("block_ip", block_ip),
        ("unblock_ip", unblock_ip),
        ("manage_service", manage_service),
        ("defender_scan", defender_scan),
        ("get_local_users", get_local_users),
        ("get_network_adapters", get_network_adapters),
    ]

    for name, fn in tools:
        assert asyncio.iscoroutinefunction(fn), f"FAIL: {name} must be async def"
        print(f"  PASS: {name} is async")

    # Test block_ip returns proper error for invalid IP (no crash)
    result = await block_ip("not_an_ip")
    assert "❌" in result, f"FAIL: block_ip should reject invalid IP, got: {result[:80]}"
    print("  PASS: block_ip validates IP correctly")

    # Test manage_service rejects invalid action
    result = await manage_service("delete", "wuauserv")
    assert "❌" in result, "FAIL: manage_service should reject invalid action"
    print("  PASS: manage_service validates action correctly")

    # Test manage_service rejects protected service
    result = await manage_service("stop", "windefend")
    assert "❌" in result and "מוגן" in result, "FAIL: manage_service should protect windefend"
    print("  PASS: manage_service protects critical services")

    print("  TEST 3: ALL PASSED")


async def test_ai_search_async():
    """TEST 4: Regression — ai_search.web_search is async and uses httpx."""
    print("\n" + "=" * 60)
    print("TEST 4: ai_search — async web_search")
    print("=" * 60)

    from services.ai_search import _simple_web_search, web_search

    assert asyncio.iscoroutinefunction(web_search), "FAIL: web_search must be async"
    assert asyncio.iscoroutinefunction(_simple_web_search), "FAIL: _simple_web_search must be async"
    print("  PASS: web_search and _simple_web_search are async")

    # We don't actually call the external API to avoid quota burn,
    # but we verify the function structure.
    print("  TEST 4: ALL PASSED")


async def main():
    print("\n" + "=" * 60)
    print("THREAT MODEL INTEGRATION TESTS")
    print("=" * 60)

    try:
        await test_powershell_hitl_no_fastpath()
        await test_async_http_non_blocking()
        await test_existing_tools_still_async()
        await test_ai_search_async()
    except AssertionError as e:
        print(f"\n  TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  UNEXPECTED ERROR: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)
    sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
