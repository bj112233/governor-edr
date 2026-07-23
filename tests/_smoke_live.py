"""Live smoke test of the running Sentinel bot via MCP HTTP."""

from __future__ import annotations

import json
import os
import sys

import httpx


def load_token() -> str:
    env_token = os.getenv("MCP_AUTH_TOKEN", "")
    if env_token:
        return env_token
    try:
        with open(
            os.path.join(os.path.dirname(__file__), "..", ".env"),
            encoding="utf-8",
        ) as fh:
            for line in fh:
                if line.startswith("MCP_AUTH_TOKEN="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return ""


BASE = "http://127.0.0.1:11123"
TOKEN = load_token()
HEADERS = {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}


def step(title: str) -> None:
    print(f"\n=== {title} ===")


# 1. Health
step("1. Health")
r = httpx.get(f"{BASE}/mcp/health", headers=HEADERS, timeout=3.0)
print(f"  status={r.status_code}  body={r.text[:80]}")
if r.status_code != 200:
    sys.exit("ABORT: bot not healthy")

# 2. Tools registry
step("2. Tools registry")
r = httpx.get(f"{BASE}/mcp/tools", headers=HEADERS, timeout=3.0)
tools = r.json()["tools"]
names = sorted(t["name"] for t in tools)
print(f"  MCP exposes {len(tools)} tools")
for t in ("block_ip", "unblock_ip", "get_firewall_drops"):
    mark = "OK" if t in names else "MISSING"
    print(f"  {t:<22}: {mark}")
new_skills = [n for n in names if n.startswith("skill_")]
print(f"  skill_* tools (MCP)     : {new_skills}")

# 3. Call get_system_snapshot — verify TOOL_OUTPUT_MAX_CHARS shape
step("3. Call get_system_snapshot")
r = httpx.post(
    f"{BASE}/mcp/call",
    headers=HEADERS,
    json={"tool": "get_system_snapshot", "arguments": {}},
    timeout=10.0,
)
result = r.json().get("result", {})
text = result.get("content", [{}])[0].get("text", "")
print(f"  status={r.status_code}  payload-len={len(text)}")
print(f"  first 160 chars: {text[:160]}")

# 4. Call firewall-skill via dedicated /mcp/skill/<name>
step("4. firewall-skill stats (new skill, dedicated endpoint)")
try:
    r = httpx.post(
        f"{BASE}/mcp/skill/firewall-skill",
        headers=HEADERS,
        json={"command": "stats", "args": ""},
        timeout=15.0,
    )
    body = r.json()
    text = body.get("result", {}).get("content", [{}])[0].get("text", "")
    print(f"  status={r.status_code}  payload-len={len(text)}")
    print(text[:600])
except Exception as e:
    print(f"  ERR: {e}")

# 5. firewall-skill list
step("5. firewall-skill list")
try:
    r = httpx.post(
        f"{BASE}/mcp/skill/firewall-skill",
        headers=HEADERS,
        json={"command": "list", "args": ""},
        timeout=15.0,
    )
    body = r.json()
    text = body.get("result", {}).get("content", [{}])[0].get("text", "")
    print(f"  status={r.status_code}")
    print(text[:300])
except Exception as e:
    print(f"  ERR: {e}")

# 6. Test legacy block_ip is still callable via MCP (backward compat)
step("6. Legacy get_firewall_drops via MCP (should still work)")
try:
    r = httpx.post(
        f"{BASE}/mcp/call",
        headers=HEADERS,
        json={"tool": "get_firewall_drops", "arguments": {}},
        timeout=15.0,
    )
    text = r.json().get("result", {}).get("content", [{}])[0].get("text", "")
    print(f"  status={r.status_code}  payload-len={len(text)}")
    print(text[:200])
except Exception as e:
    print(f"  ERR: {e}")

print("\n=== smoke test done ===")
