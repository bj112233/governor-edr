# services/local_mcp_server.py
"""
Local MCP Server — FastAPI on port 11123.
Exposes system/filesystem/memory tools via MCP protocol.
Protocol: GET /mcp/health, GET /mcp/tools, POST /mcp/call

============================================================================
TOOL EXECUTION PATHS — when adding callers, choose the right one:
============================================================================

(1) LLM in-process    services.agent.run_agent
                       └→ services.agent_tools.execute_tool
                          └→ tools_registry.LLM_TOOL_MAP[name](args)
                       Direct Python call, ZERO HTTP / JSON overhead.
                       Used for: free-text Telegram messages, conversational AI.
                       Architectural rule: built-in tools MUST stay in-process
                       here (see architecture memory item #4).

(2) /mcp/call         tools_registry handler via HTTP loopback
                       └→ wrapped with audit log + per-IP rate limit
                       Used for: Telegram slash commands (/system, /procs,
                       /scrape, /analyze, etc.) and any external MCP client.
                       The ~1-3 ms loopback cost buys uniform auth + audit.

(3) /mcp/skill/<name> dynamic per-skill endpoint (auto-registered below)
                       └→ skills_engine.execute(skill, command, args)
                       Used for: external HTTP integrations needing flexible
                       sub-command access. Currently NOT consumed by the
                       Telegram client — kept for forward compatibility.

(4) skills_engine direct (BYPASSES this server)
                       services.telegram_channel._process_message uses this
                       on file uploads to skip LLM tool-calling (small-model
                       reliability). NOT routed here.
============================================================================
"""

import asyncio
import hmac
import inspect
import logging
import os
import time
from typing import Any, Optional

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ValidationError

from config import MCP_AUTH_TOKEN, TOOL_OUTPUT_MAX_CHARS
from services.alert_history import async_save_audit_log
from services.security_utils import is_request_from_session_0
from services.skills_engine import get_skills_engine
from services.text_utils import clean_ide_instructions
from services.tools_registry import REGISTRY, to_mcp_handlers, to_mcp_schemas

# Import agent for Telegram message bridge
try:
    from services.agent import run_agent
except ImportError:
    run_agent = None

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

# ── Simple per-IP rate limiter (token bucket style) ─────────────────
_MCP_RATE_LIMIT = int(os.getenv("MCP_RATE_LIMIT", "30"))  # requests per minute per IP
_MCP_RATE_WINDOW = 60.0  # seconds

# M5 fix: Global rate limit bucket — prevents IPv6 rotation bypass.
# Even if attacker rotates through 2^64 addresses, the global cap holds.
_MCP_GLOBAL_RATE_LIMIT = int(os.getenv("MCP_GLOBAL_RATE_LIMIT", "100"))  # total req/min
_mcp_global_timestamps: list[float] = []

_mcp_rate_store: dict[str, list[float]] = {}
_MCP_RATE_EXPIRY = 3600  # 1 hour


def _check_mcp_rate_limit(client_ip: str) -> bool:
    """Return True if request is within rate limit for client IP AND global bucket.

    M5 fix: Two-layer check:
    1. Per-IP limit (30 req/min) — stops single-IP flooding.
    2. Global limit (100 req/min) — stops IPv6 rotation bypass where
       attacker spreads requests across many addresses.
    """
    now = time.time()

    # 1. Global cleanup of extremely stale IPs (memory leak prevention)
    cutoff = now - _MCP_RATE_EXPIRY
    for ip in list(_mcp_rate_store.keys()):
        if _mcp_rate_store[ip] and _mcp_rate_store[ip][-1] < cutoff:
            del _mcp_rate_store[ip]

    # 2. Global bucket check (M5 fix — IPv6 rotation defense)
    window_start = now - _MCP_RATE_WINDOW
    global _mcp_global_timestamps
    _mcp_global_timestamps = [t for t in _mcp_global_timestamps if t > window_start]
    if len(_mcp_global_timestamps) >= _MCP_GLOBAL_RATE_LIMIT:
        return False  # global bucket exhausted — reject even valid IPs

    # 3. Per-IP window filtering and validation
    timestamps = _mcp_rate_store.get(client_ip, [])
    timestamps = [t for t in timestamps if t > window_start]  # filter old

    # 4. Record request in both buckets
    timestamps.append(now)
    _mcp_rate_store[client_ip] = timestamps
    _mcp_global_timestamps.append(now)

    return len(timestamps) <= _MCP_RATE_LIMIT


app = FastAPI(title="Local MCP Server", version="1.0")

skills_engine = get_skills_engine()


class SkillCallRequest(BaseModel):
    command: str = ""
    args: str = ""


async def _verify_mcp_auth(
    request: Request,
    token: HTTPBearer | None = Depends(security),
) -> None:
    """Verify Bearer token for ALL MCP endpoints.

    SECURITY: localhost is NOT a trust boundary. SSRF from any future
    web-scraper or browsing tool can hit 127.0.0.1:11123. Auth is
    mandatory regardless of client IP.
    """
    if not MCP_AUTH_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MCP_AUTH_TOKEN not configured. Set it in .env.",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    provided = auth_header[7:].strip()
    if not provided or not hmac.compare_digest(provided, MCP_AUTH_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid MCP auth token.",
        )


def _make_skill_endpoint(skill_name: str):
    """Factory: closes skill_name by value (not by reference) to avoid late-binding bug."""

    async def _skill_endpoint(req: SkillCallRequest):
        result = await skills_engine.execute(skill_name, req.command, req.args)
        return {"result": {"content": [{"type": "text", "text": str(result)[:TOOL_OUTPUT_MAX_CHARS]}]}}

    return _skill_endpoint


# Dynamically register dedicated skill endpoints (must be after _verify_mcp_auth is defined)
try:
    for _skill_name in skills_engine.list_skill_names():
        _ep = _make_skill_endpoint(_skill_name)
        app.post(
            f"/mcp/skill/{_skill_name}",
            dependencies=[Depends(_verify_mcp_auth)],
        )(_ep)
except Exception as e:
    logger.warning(f"[MCP] Failed to register skill endpoints (SKILLS_DIR missing?): {e}")


@app.middleware("http")
async def _session0_boundary_middleware(request: Request, call_next):
    """Session 0 Zero-Trust boundary — blocks loopback connections from
    Session 1 (user session) processes even if they hold a valid token.

    Prevents privilege escalation: a Session 1 process with a stolen
    MCP_AUTH_TOKEN could otherwise execute tools as LocalSystem (SYSTEM).
    Runs before auth — fail-safe regardless of token validity.
    """
    client = request.client
    if client and client.host in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        if not is_request_from_session_0(client.host, client.port):
            logger.critical(
                "[MCP] SECURITY BREACH: non-Session-0 process on port %d "
                "attempted MCP tool execution (would grant SYSTEM). Denied.",
                client.port,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session 0 Zero-Trust boundary enforced.",
            )
    return await call_next(request)


@app.middleware("http")
async def _audit_mcp_requests(request: Request, call_next):
    """Log all MCP requests for audit trail."""
    response = await call_next(request)
    client = request.client.host if request.client else "unknown"
    logger.info(f"[MCP-Audit] {request.method} {request.url.path} status={response.status_code} client={client}")
    return response


_TOOL_REGISTRY: dict[str, Any] = to_mcp_handlers()
_TOOL_SCHEMAS = to_mcp_schemas()


class CallRequest(BaseModel):
    tool: str
    arguments: dict[str, Any] = {}


@app.get("/mcp/health", dependencies=[Depends(_verify_mcp_auth)])
async def health():
    return {"status": "ok"}


@app.get("/mcp/tools", dependencies=[Depends(_verify_mcp_auth)])
async def list_tools():
    return {"tools": _TOOL_SCHEMAS}


@app.post("/mcp/reload_yara", dependencies=[Depends(_verify_mcp_auth)])
async def reload_yara_rules(request: Request):
    """Hot-reload YARA rules from rules/yara/ without service restart.

    Deterministic endpoint for SOAR/remote workflows: push a .yar file into
    rules/yara/ via any channel, then call this endpoint to trigger an
    immediate recompile. Returns {"files": N, "rules": M} or error dict.
    Zero LLM cost — pure Python compilation in a worker thread.
    """
    client_ip = request.client.host if request.client else "unknown"
    if not _check_mcp_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({_MCP_RATE_LIMIT} req/min). Try again later.",
        )
    from services.yara_engine import reload_rules

    result = await reload_rules()
    logger.info("[MCP] /mcp/reload_yara by %s → %s", client_ip, result)
    return {"result": result}


@app.post("/mcp/call", dependencies=[Depends(_verify_mcp_auth)])
async def call_tool(req: CallRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_mcp_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({_MCP_RATE_LIMIT} req/min). Try again later.",
        )

    start = time.perf_counter()
    audit_result = ""
    response_payload: dict[str, Any] | None = None
    try:
        if req.tool not in _TOOL_REGISTRY:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tool not found: {req.tool}",
            )
        fn = _TOOL_REGISTRY[req.tool]
        tool_spec = REGISTRY.get(req.tool)
        if tool_spec is None or tool_spec.pydantic_model is None:
            logger.warning(f"[LocalMCP] Tool '{req.tool}' missing schema. Rejected.")
            audit_result = "REJECTED: Missing validation schema"
            response_payload = {
                "result": {"error": f"Tool '{req.tool}' lacks a registered validation schema. Execution rejected."}
            }
        else:
            arguments = req.arguments
            try:
                validated = tool_spec.pydantic_model(**req.arguments)
                arguments = validated.model_dump()
            except ValidationError as ve:
                logger.warning(f"[LocalMCP] Validation error in '{req.tool}': {ve}")
                audit_result = f"VALIDATION_FAILED: {ve}"
                response_payload = {
                    "result": {"error": f"Validation failed: {ve}. Please correct your arguments and try again."}
                }
        if response_payload is None:
            if asyncio.iscoroutinefunction(fn):
                result = await fn(**arguments)
            else:
                result = await asyncio.to_thread(fn, **arguments)
            if inspect.isawaitable(result):
                result = await result
            result_text = str(result)[:1000]
            audit_result = result_text
            response_payload = {"result": {"content": [{"type": "text", "text": str(result)[:TOOL_OUTPUT_MAX_CHARS]}]}}
    except (TypeError, ValueError) as val_err:
        logger.warning(f"[LocalMCP] Schema mismatch in '{req.tool}': {val_err}")
        audit_result = f"SCHEMA_ERROR: {val_err}"
        response_payload = {
            "result": {
                "error": f"Schema Validation Error: {val_err}. Please ensure your arguments exactly match the required schema."
            }
        }
    except Exception as e:
        audit_result = f"ERROR: {str(e)[:500]}"
        response_payload = {"result": {"error": str(e)}}
        logger.error(f"[LocalMCP] Tool '{req.tool}' error: {e}", exc_info=True)
    finally:
        duration_ms = int((time.perf_counter() - start) * 1000)
        await async_save_audit_log(
            tool=req.tool,
            args=str(req.arguments)[:500],
            result=audit_result,
            client_ip=client_ip,
            duration_ms=duration_ms,
        )

    return response_payload


async def start_local_mcp_server() -> None:
    """Start the local MCP FastAPI server on port 11123."""
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=11123,
        log_level="warning",
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    logger.info("[LocalMCP] Starting on http://127.0.0.1:11123")
    await server.serve()


# Register telegram message route (import side-effect registers @app.post)
from services.local_mcp_telegram_route import telegram_message  # noqa: E402,F401
