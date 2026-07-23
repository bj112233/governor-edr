"""Zero-Bloat Web C2 Dashboard — LAN-only with token-based auth.

Binds to 127.0.0.1 by default; set WEB_C2_HOST=0.0.0.0 for LAN access.
The IP whitelist middleware blocks all non-RFC1918 traffic regardless.
Three-layer defense:
  Layer 3: IP whitelist rejects any source outside loopback / RFC 1918.
  Layer 7: Token exchange auth (M6 fix) — Basic Auth ONLY at /api/auth/login,
           all other endpoints require Bearer token with 8h TTL.
  Layer 8: Security headers (CSP, X-Frame-Options, X-Content-Type-Options,
           Referrer-Policy, Permissions-Policy) on every response.
External (public-IP) requests are returned 403 before the handler runs.
"""

import json
import logging
import os

import aiohttp.web

from services.security_utils import is_request_from_session_0
from services.web_c2_auth import check_basic_auth, client_ip_allowed
from services.web_c2_routes import routes
from services.web_c2_sessions import (
    create_session,
    is_ip_locked_out,
    record_failed_auth,
    record_successful_auth,
    revoke_session,
    validate_session,
)

logger = logging.getLogger(__name__)

# Path that accepts Basic Auth for token exchange (M6 fix)
_LOGIN_PATH = "/api/auth/login"
# Path that revokes a session token (logout)
_LOGOUT_PATH = "/api/auth/logout"
# Static root — serves HTML shell with no sensitive data (auth happens client-side)
_PUBLIC_PATHS = frozenset({"/"})

# Security headers applied to every response (including 401/403/500).
# CSP allows the three CDN origins the dashboard loads (Chart.js,
# vis-network, Tailwind) plus 'unsafe-inline' for the inline <style>/
# <script> blocks in index.html. Nonce-based CSP is the long-term upgrade.
_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
}


@aiohttp.web.middleware
async def security_headers_middleware(request: aiohttp.web.Request, handler):
    """Inject security headers on every response (CSP, anti-clickjacking, etc.).

    Runs as the outermost middleware so headers cover 401/403/500 from the
    auth/IP gate as well as successful handler responses.
    """
    response = await handler(request)
    for key, value in _SECURITY_HEADERS.items():
        response.headers[key] = value
    return response


_LOOPBACK_IPS = ("127.0.0.1", "::1", "::ffff:127.0.0.1")


def _check_session0_boundary(request: aiohttp.web.Request) -> aiohttp.web.Response | None:
    """Session 0 Zero-Trust boundary for loopback connections.

    Returns a 403 response if the loopback connection originates from a
    non-Session-0 process (blocks privilege escalation via stolen token).
    Returns None if the connection is allowed (or non-loopback).
    """
    remote = request.remote
    if remote not in _LOOPBACK_IPS:
        return None
    peername = request.transport.get_extra_info("peername") if request.transport else None
    client_port = peername[1] if peername and len(peername) >= 2 else 0
    if not client_port:
        return None
    if is_request_from_session_0(remote, client_port):
        return None
    logger.critical(
        "[WebC2] SECURITY BREACH: non-Session-0 process on port %d "
        "attempted C2 access (token would grant SYSTEM). Denied.",
        client_port,
    )
    return aiohttp.web.Response(
        status=403,
        text="403 Forbidden: Cross-Session Zero-Trust boundary enforced.",
    )


def _handle_auth_routes(request: aiohttp.web.Request, remote: str) -> aiohttp.web.Response | None:
    """Handle login, logout, and public static routes.

    Returns a Response if the route was handled (login/logout/static),
    or None if the request should proceed to Bearer token validation.
    """
    # M6: Token exchange — Basic Auth only at login endpoint
    if request.path == _LOGIN_PATH and request.method == "POST":
        if not check_basic_auth(request.headers.get("Authorization")):
            record_failed_auth(remote or "unknown")
            return aiohttp.web.Response(
                status=401,
                text="401 Unauthorized",
                headers={"WWW-Authenticate": 'Basic realm="Sentinel C2 Login", charset="UTF-8"'},
            )
        record_successful_auth(remote or "unknown")
        token = create_session()
        return aiohttp.web.Response(
            text=json.dumps({"token": token, "expires_in": 28800}),
            content_type="application/json",
        )

    # Logout: revoke the Bearer token
    if request.path == _LOGOUT_PATH and request.method == "POST":
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            revoke_session(auth_header[7:])
        return aiohttp.web.Response(
            text=json.dumps({"status": "revoked"}),
            content_type="application/json",
        )

    # Static root: HTML shell with no sensitive data (auth is client-side)
    if request.path in _PUBLIC_PATHS and request.method == "GET":
        return None  # Let handler serve the HTML

    return None  # Not an auth route — proceed to Bearer check


@aiohttp.web.middleware
async def security_middleware(request: aiohttp.web.Request, handler):
    """Layer 3 (LAN-only) + Layer 7 (token exchange auth) gate.

    M6 fix: Basic Auth is accepted ONLY at /api/auth/login. All other
    endpoints require a valid Bearer token (8h TTL). This ensures stolen
    Basic Auth headers cannot provide ongoing access.

    M7 fix: Brute-force protection — 10 failed attempts per IP in 15 min
    triggers a 15-min lockout. Prevents LAN-based credential stuffing.
    """
    remote = request.remote
    if not client_ip_allowed(remote):
        logger.warning("[WebC2] BLOCK external IP %s -> %s", remote, request.path)
        return aiohttp.web.Response(status=403, text="403 Forbidden")

    # Session 0 Zero-Trust boundary (extracted to _check_session0_boundary)
    breach_response = _check_session0_boundary(request)
    if breach_response is not None:
        return breach_response

    # M7: Check lockout first
    if is_ip_locked_out(remote or "unknown"):
        logger.warning("[WebC2] IP %s is locked out (brute-force)", remote)
        return aiohttp.web.Response(status=429, text="429 Too Many Requests — locked out")

    # Auth routes (login, logout, static root)
    auth_response = _handle_auth_routes(request, remote)
    if auth_response is not None:
        return auth_response
    # Static root returns None from _handle_auth_routes → serve HTML
    if request.path in _PUBLIC_PATHS and request.method == "GET":
        return await handler(request)

    # SSE exception: EventSource cannot set custom headers, so /api/events
    # accepts token via query string (?token=xxx) validated in the handler.
    if request.path == "/api/events" and request.query.get("token"):
        return await handler(request)

    # M6: All other endpoints require Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if validate_session(token):
            return await handler(request)
        record_failed_auth(remote or "unknown")
        return aiohttp.web.Response(
            status=401,
            text="401 Unauthorized — token invalid or expired",
            headers={"WWW-Authenticate": 'Bearer realm="Sentinel C2"'},
        )

    # No valid auth at all
    record_failed_auth(remote or "unknown")
    return aiohttp.web.Response(
        status=401,
        text="401 Unauthorized — Bearer token required (obtain from /api/auth/login)",
        headers={"WWW-Authenticate": 'Bearer realm="Sentinel C2"'},
    )


class C2DashboardServer:
    """Web C2 dashboard server with security enforcement."""

    def __init__(self, host: str | None = None, port: int = 8765) -> None:
        # SECURITY: default to loopback. Set WEB_C2_HOST=0.0.0.0 for LAN access.
        # The IP whitelist middleware (client_ip_allowed) blocks all non-RFC1918
        # traffic, and the Session 0 boundary blocks non-Session-0 loopback.
        # S-11: 0.0.0.0 requires explicit opt-in (WEB_C2_LAN_ALLOWED=true) to
        # prevent accidental LAN exposure (guest WiFi, IoT lateral movement).
        effective_host = host or os.getenv("WEB_C2_HOST", "127.0.0.1")
        if effective_host == "0.0.0.0":
            if os.getenv("WEB_C2_LAN_ALLOWED", "").lower() != "true":
                raise ValueError(
                    "WEB_C2_HOST=0.0.0.0 requires explicit opt-in: set WEB_C2_LAN_ALLOWED=true to enable LAN binding."
                )
            logger.warning(
                "[WebC2] LAN binding enabled (0.0.0.0) — IP whitelist + "
                "Session 0 boundary are the only barriers. Verify network isolation."
            )

        from config import WEB_C2_AUTH_PASSWORD

        if not WEB_C2_AUTH_PASSWORD:
            logger.error(
                "[WebC2] WEB_C2_AUTH_PASSWORD is empty — dashboard will reject "
                "all requests until a password is configured."
            )
        self.host = effective_host
        self.port = port
        self._runner: aiohttp.web.AppRunner | None = None

    async def start(self) -> None:
        """Create app, register routes, bind to host:port."""
        app = aiohttp.web.Application(middlewares=[security_headers_middleware, security_middleware])
        app.add_routes(routes)
        self._runner = aiohttp.web.AppRunner(app)
        await self._runner.setup()
        site = aiohttp.web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info("[WebC2] Dashboard running at http://%s:%d", self.host, self.port)

    async def stop(self) -> None:
        """Cleanup runner."""
        if self._runner:
            await self._runner.cleanup()
            logger.info("[WebC2] Server stopped.")
