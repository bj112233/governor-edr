# services/telegram/mcp_bridge.py
"""MCP HTTP client for Telegram slash-commands."""

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# Module-level AsyncClient with connection pooling
_default_timeout = httpx.Timeout(60.0)
_client = httpx.AsyncClient(timeout=_default_timeout)


def get_mcp_client() -> httpx.AsyncClient:
    return _client


async def close_mcp_client() -> None:
    await _client.aclose()


async def call_mcp(
    url: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    timeout: float | None = None,
) -> str:
    """POST to local MCP and return the text result (truncated).

    Slash commands deliberately go via HTTP loopback (path #2 in
    local_mcp_server.py header) instead of calling the in-process
    registry directly. The ~1-3 ms cost buys uniform Bearer-token
    auth, per-IP rate-limiting, and a centralized audit log. Free-text
    messages instead go through `run_agent`, which uses the in-process
    path (#1) for zero overhead.
    """
    try:
        from config import MCP_AUTH_ENABLED, MCP_AUTH_TOKEN

        headers = {}
        if MCP_AUTH_ENABLED and MCP_AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {MCP_AUTH_TOKEN}"

        client = get_mcp_client()
        req_timeout = httpx.Timeout(timeout or 60.0)

        resp = await client.post(
            url,
            json={"tool": tool_name, "arguments": arguments or {}},
            headers=headers,
            timeout=req_timeout,
        )
        resp.raise_for_status()
        data = resp.json().get("result", {})
        if "error" in data:
            return f"❌ שגיאת MCP: {data['error']}"
        parts = data.get("content", [])
        return "\n".join(p.get("text", "") for p in parts) or "(ריק)"
    except Exception as e:
        logger.exception("[Telegram] MCP call failed for %s: %r", tool_name, e)
        return f"❌ שגיאה בתקשורת MCP: {e!r}"
