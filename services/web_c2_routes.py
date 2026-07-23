"""Web C2 routes — HTTP endpoints with clean separation from business logic."""

import json
import logging
import time
from pathlib import Path

import aiohttp.web

from services.alert_history import async_save_audit_log
from services.sentinel_events import event_bus
from services.web_c2_commands import dispatch_command
from services.web_c2_data import get_health, get_metrics, get_threats

logger = logging.getLogger(__name__)

# RouteTableDef: avoids circular imports by not requiring app instance
routes = aiohttp.web.RouteTableDef()

# ── Rate limiter for /api/command (token-bucket, per-IP) ─────────────
_C2_RATE_LIMIT = 10  # req/min per IP (lower than MCP — fewer legitimate calls)
_C2_RATE_WINDOW = 60.0
_C2_RATE_EXPIRY = 3600
_c2_rate_store: dict[str, list[float]] = {}

# M8 fix: Dedicated rate limit for hunt trigger (resource exhaustion DoS)
_HUNT_RATE_LIMIT = 5  # max 5 hunt triggers per minute per IP
_HUNT_RATE_WINDOW = 60.0
_hunt_rate_store: dict[str, list[float]] = {}


def _check_c2_rate_limit(client_ip: str) -> bool:
    """Return True if request is within rate limit for client IP."""
    now = time.time()
    cutoff = now - _C2_RATE_EXPIRY
    for ip in list(_c2_rate_store.keys()):
        if _c2_rate_store[ip] and _c2_rate_store[ip][-1] < cutoff:
            del _c2_rate_store[ip]
    window_start = now - _C2_RATE_WINDOW
    timestamps = _c2_rate_store.get(client_ip, [])
    timestamps = [t for t in timestamps if t > window_start]
    timestamps.append(now)
    _c2_rate_store[client_ip] = timestamps
    return len(timestamps) <= _C2_RATE_LIMIT


def _check_hunt_rate_limit(client_ip: str) -> bool:
    """M8 fix: Rate limit for /api/threat_hunter/trigger (5 req/min per IP).

    Prevents resource exhaustion DoS — each hunt triggers LLM calls,
    YARA scans, and network enrichment. Unrestricted triggers can
    saturate the event loop and starve legitimate monitoring.
    """
    now = time.time()
    window_start = now - _HUNT_RATE_WINDOW
    timestamps = _hunt_rate_store.get(client_ip, [])
    timestamps = [t for t in timestamps if t > window_start]
    timestamps.append(now)
    _hunt_rate_store[client_ip] = timestamps
    # Cleanup stale entries
    if len(_hunt_rate_store) > 100:
        for ip in list(_hunt_rate_store.keys()):
            if _hunt_rate_store[ip] and _hunt_rate_store[ip][-1] < window_start:
                del _hunt_rate_store[ip]
    return len(timestamps) <= _HUNT_RATE_LIMIT


@routes.get("/api/metrics")
async def api_metrics(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Return latest metrics with z-score computed from baseline."""
    rows = await get_metrics(limit=50)
    return aiohttp.web.Response(text=json.dumps(rows), content_type="application/json")


@routes.get("/api/threats")
async def api_threats(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Return alerts ordered by timestamp DESC.

    Query params:
        since (optional): epoch seconds (float/int). If provided, returns
            up to 100 alerts whose timestamp > since. Otherwise returns
            last 24h, capped at 50 rows.
    """
    since_param = request.query.get("since")
    since_ts: float | None = None
    if since_param is not None:
        try:
            since_ts = float(since_param)
        except (TypeError, ValueError):
            return aiohttp.web.Response(
                status=400,
                text=json.dumps({"error": "invalid 'since' parameter"}),
                content_type="application/json",
            )

    limit = 100 if since_ts is not None else 50
    rows = await get_threats(limit=limit, since_ts=since_ts)
    return aiohttp.web.Response(text=json.dumps(rows), content_type="application/json")


@routes.get("/api/health")
async def api_health(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Return current system health (CPU, RAM, Disk, VRAM)."""
    data = await get_health()
    return aiohttp.web.Response(text=json.dumps(data), content_type="application/json")


@routes.get("/api/threat_hunter/status")
async def api_threat_hunter_status(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Return current Threat Hunter state machine status.

    Non-blocking snapshot — never acquires the hunt mutex.
    Fields: state, last_run_ts/iso, last_score, last_dispatched,
    last_skip_reason, next_run_eta/iso, seconds_until_next, hunt_count.
    """
    from services.threat_hunter import get_hunt_status

    data = get_hunt_status()
    return aiohttp.web.Response(text=json.dumps(data), content_type="application/json")


@routes.post("/api/threat_hunter/trigger")
async def api_threat_hunter_trigger(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Trigger a threat hunt immediately (operator override).

    Runs threat_hunt_job() as a background task — returns 202 immediately.
    The hunt result appears in /api/threat_hunter/status and the log.
    Bypasses the scheduler interval but still respects the cooldown guard
    inside _preflight() unless force=true is passed in the JSON body.

    M8 fix: Rate limited to 5 triggers/min per IP (resource exhaustion DoS).
    """
    client_ip = request.remote or "unknown"
    if not _check_hunt_rate_limit(client_ip):
        logger.warning("[WebC2] Hunt trigger rate-limited for %s", client_ip)
        return aiohttp.web.json_response(
            {"error": "rate_limited", "message": "max 5 hunt triggers/min"},
            status=429,
        )

    from services.threat_hunter import threat_hunt_job

    force = False
    try:
        payload = await request.json()
        force = bool(payload.get("force", False))
    except Exception:
        pass  # empty body is fine

    if force:
        # Reset cooldown so _preflight() won't skip with "cooldown".
        import services.threat_hunter as _th

        _th._LAST_HUNT_TS = 0.0
        _th._FORCE_HUNT = True

    from services.agent._helpers import _fire_and_forget

    _fire_and_forget(threat_hunt_job())
    logger.info("[WebC2] Threat hunt triggered by operator (force=%s)", force)
    return aiohttp.web.json_response(
        {"status": "accepted", "message": "threat hunt started — check /api/threat_hunter/status"},
        status=202,
    )


@routes.post("/api/command")
async def api_command(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Active Remediation: Execute C2 commands from the dashboard.

    Rate-limited (10 req/min per IP) and audit-logged (including rejections).
    """
    import time as _time

    client_ip = request.remote or "unknown"
    start = _time.perf_counter()

    # Rate limit check
    if not _check_c2_rate_limit(client_ip):
        duration_ms = int((_time.perf_counter() - start) * 1000)
        logger.warning("[WebC2] Rate limit hit for %s on /api/command", client_ip)
        await async_save_audit_log(
            tool="c2_command",
            args="RATE_LIMITED",
            result="REJECTED: rate limit exceeded",
            client_ip=client_ip,
            duration_ms=duration_ms,
        )
        return aiohttp.web.json_response({"status": "error", "error": "rate limit exceeded"}, status=429)

    try:
        payload = await request.json()
        cmd = payload.get("command")
        target = payload.get("target")
        otp_code = payload.get("otp_code")
        challenge_id = payload.get("challenge_id")

        result = await dispatch_command(cmd, target, otp_code=otp_code, challenge_id=challenge_id)
        status_code = result.pop("code", 200)
        duration_ms = int((_time.perf_counter() - start) * 1000)
        await async_save_audit_log(
            tool="c2_command",
            args=str(payload)[:500],
            result=str(result)[:500],
            client_ip=client_ip,
            duration_ms=duration_ms,
        )
        return aiohttp.web.json_response(result, status=status_code)
    except json.JSONDecodeError:
        duration_ms = int((_time.perf_counter() - start) * 1000)
        logger.warning("[WebC2] Malformed JSON payload from %s", client_ip)
        await async_save_audit_log(
            tool="c2_command",
            args="PARSE_ERROR",
            result="REJECTED: malformed JSON",
            client_ip=client_ip,
            duration_ms=duration_ms,
        )
        return aiohttp.web.json_response({"status": "error", "error": "malformed JSON"}, status=400)
    except Exception:
        duration_ms = int((_time.perf_counter() - start) * 1000)
        logger.exception("[WebC2] Command execution crashed")  # log full traceback server-side
        await async_save_audit_log(
            tool="c2_command",
            args=str(payload)[:500] if "payload" in locals() else "PARSE_ERROR",
            result="ERROR: internal error"[:500],
            client_ip=client_ip,
            duration_ms=duration_ms,
        )
        return aiohttp.web.json_response({"status": "error", "error": "internal error", "code": 500}, status=500)


@routes.get("/api/events")
async def api_events(
    request: aiohttp.web.Request,
) -> aiohttp.web.StreamResponse:
    """Server-Sent Events: push live alerts from the Sentinel event bus.

    Token is accepted from query string (?token=xxx) as well as the
    standard Authorization header, because EventSource cannot set
    custom headers. The middleware already validated the token before
    reaching this handler, so we only need to check the query param
    fallback for SSE clients.
    """
    import asyncio

    from services.web_c2_sessions import validate_session

    # SSE token: prefer query param (EventSource can't set headers),
    # fall back to Authorization header (already validated by middleware
    # if present, but SSE clients won't have it).
    token = request.query.get("token")
    if token:
        if not validate_session(token):
            return aiohttp.web.Response(status=401, text="401 Unauthorized — invalid SSE token")
    else:
        # If no query token, the middleware already checked the Bearer header
        pass

    resp = aiohttp.web.StreamResponse(
        status=200,
        reason="OK",
        headers={
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
    await resp.prepare(request)
    queue = await event_bus.subscribe()
    peer = request.remote
    logger.info("[WebC2] SSE client subscribed: %s", peer)
    try:
        await resp.write(b": connected\n\n")
        last_telemetry = 0.0
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=2.0)
            except TimeoutError:
                # Push live telemetry every 2s (real-time gauges + charts)
                now = time.time()
                if now - last_telemetry >= 2.0:
                    last_telemetry = now
                    telemetry = await get_health()
                    payload = json.dumps(telemetry, ensure_ascii=False, default=str)
                    await resp.write(f"event: telemetry\ndata: {payload}\n\n".encode())
                else:
                    await resp.write(b": ping\n\n")
                continue
            try:
                payload = json.dumps(event.to_dict(), ensure_ascii=False, default=str)
            except Exception as exc:
                logger.debug("[WebC2] SSE serialize failed: %s", exc)
                continue
            await resp.write(f"event: {event.event_type}\ndata: {payload}\n\n".encode())
    except (asyncio.CancelledError, ConnectionResetError):
        pass
    except Exception as exc:
        logger.warning("[WebC2] SSE stream error (%s): %s", peer, exc)
    finally:
        await event_bus.unsubscribe(queue)
        logger.info("[WebC2] SSE client disconnected: %s", peer)
    return resp


@routes.get("/")
async def index(request: aiohttp.web.Request) -> aiohttp.web.Response:
    """Serve dashboard HTML from static file."""
    html_path = Path(__file__).parent.parent / "static" / "index.html"
    try:
        body = html_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        body = "<html><body><h1>Dashboard HTML not found.</h1></body></html>"
    return aiohttp.web.Response(text=body, content_type="text/html")


__all__ = ["routes"]
