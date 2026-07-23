#!/usr/bin/env python3
"""Diagnostic: test all tools via local MCP server (no LLM)."""

import asyncio

import httpx

from config import MCP_AUTH_ENABLED, MCP_AUTH_TOKEN

MCP_URL = "http://127.0.0.1:11123/mcp"


def _mcp_headers() -> dict:
    """Return auth headers for MCP requests if enabled."""
    if MCP_AUTH_ENABLED and MCP_AUTH_TOKEN:
        return {"Authorization": f"Bearer {MCP_AUTH_TOKEN}"}
    return {}


TOOLS_TO_TEST = [
    ("get_system_snapshot", {}),
    ("get_process_list", {}),
    ("get_disk_details", {}),
    ("get_external_connections", {}),
    ("get_services", {}),
    ("get_event_log", {}),
    ("get_local_users", {}),
    ("get_listening_ports", {}),
    ("get_network_adapters", {}),
    ("get_startup_items", {}),
    ("get_firewall_drops", {}),
    ("get_active_sessions", {}),
    ("get_scheduled_tasks_detail", {}),
    ("query_alert_history", {"limit": 3}),
    ("search_memory", {"query": "test", "limit": 2}),
    ("scan_lan", {}),
    ("get_known_devices", {}),
    ("local_screenshot", {}),
    ("sentinel_get_system_snapshot_full", {}),
    ("sentinel_get_pending_events", {"limit": 3}),
]


async def test_tool(client: httpx.AsyncClient, name: str, args: dict):
    try:
        resp = await client.post(
            f"{MCP_URL}/call",
            json={"tool": name, "arguments": args},
            timeout=30.0,
            headers=_mcp_headers(),
        )
        data = resp.json()
        result = data.get("result", {})
        if "error" in result:
            return {"status": "error", "error": result["error"]}
        content = result.get("content", [])
        text = content[0].get("text", "") if content else ""
        return {"status": "ok", "len": len(text), "preview": text[:200]}
    except Exception as e:
        return {"status": "exception", "error": str(e)}


async def main():
    print("=" * 60)
    print("MCP TOOL DIAGNOSTIC")
    print("=" * 60)

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"{MCP_URL}/health", timeout=5.0, headers=_mcp_headers())
            print(f"MCP Health: {r.status_code} {r.json()}")
        except Exception as e:
            print(f"❌ MCP Server unreachable: {e}")
            print("   The bot must be running (python main.py) for this test.")
            return

        try:
            r = await client.get(f"{MCP_URL}/tools", timeout=5.0, headers=_mcp_headers())
            tools = r.json().get("tools", [])
            print(f"Registered tools: {len(tools)}")
        except Exception as e:
            print(f"❌ Failed to list tools: {e}")
            return

        results = {}
        for name, args in TOOLS_TO_TEST:
            print(f"\nTesting {name}...", end=" ")
            res = await test_tool(client, name, args)
            results[name] = res
            if res["status"] == "ok":
                print(f"✅ ({res['len']} chars)")
            else:
                print(f"❌ {res.get('error', 'unknown')}")

        ok = sum(1 for r in results.values() if r["status"] == "ok")
        fail = len(results) - ok
        print(f"\n{'=' * 60}")
        print(f"RESULTS: {ok}/{len(results)} tools OK, {fail} failed")
        print(f"{'=' * 60}")
        if fail > 0:
            for name, r in results.items():
                if r["status"] != "ok":
                    print(f"  ❌ {name}: {r.get('error', '')}")


if __name__ == "__main__":
    asyncio.run(main())
