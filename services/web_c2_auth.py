"""Web C2 authentication and network security — Layer 3 + Layer 7."""

import base64
import ipaddress
import logging
import secrets

from config import WEB_C2_AUTH_PASSWORD, WEB_C2_AUTH_USER

logger = logging.getLogger(__name__)

# M4 fix: Separate loopback from RFC1918 LAN.
# Loopback = the host itself (127.0.0.0/8, ::1) — fully trusted.
# RFC1918 = LAN devices (10/8, 172.16/12, 192.168/16, fe80::/10) —
# Zero Trust: the smart fridge or guest phone on the same network
# is NOT automatically trusted.

LOOPBACK_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
)

# Backward compat: combined set for client_ip_allowed
ALLOWED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    *LOOPBACK_NETWORKS,
    *PRIVATE_NETWORKS,
)


def _normalize_ip(remote: str | None) -> str | None:
    """Strip IPv6-mapped IPv4 prefix and return clean IP string."""
    if not remote:
        return None
    if remote.startswith("::ffff:"):
        remote = remote.split("::ffff:", 1)[1]
    return remote


def is_loopback_ip(remote: str | None) -> bool:
    """M4: Return True iff `remote` is loopback (127.0.0.0/8 or ::1)."""
    ip_str = _normalize_ip(remote)
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in LOOPBACK_NETWORKS)


def is_private_ip(remote: str | None) -> bool:
    """M4: Return True iff `remote` is RFC1918 private LAN (not loopback).

    Includes 10/8, 172.16/12, 192.168/16, and IPv6 link-local fe80::/10.
    Does NOT include loopback — use is_loopback_ip() for that.
    """
    ip_str = _normalize_ip(remote)
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in PRIVATE_NETWORKS)


def client_ip_allowed(remote: str | None) -> bool:
    """Return True iff `remote` is loopback or RFC 1918 private LAN.

    Handles IPv6-mapped IPv4 addresses (::ffff:192.168.1.5).
    """
    ip_str = _normalize_ip(remote)
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in ALLOWED_NETWORKS)


def check_basic_auth(header: str | None) -> bool:
    """Constant-time validation of HTTP Basic Authorization header.

    Returns False if:
    - Header is missing or malformed
    - Password is not configured (fail-closed)
    - Credentials don't match (constant-time comparison)
    """
    if not header or not header.startswith("Basic "):
        return False
    if not WEB_C2_AUTH_PASSWORD:
        # Fail closed: no password configured -> deny everything.
        return False
    try:
        decoded = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return False
    if ":" not in decoded:
        return False
    user, _, pw = decoded.partition(":")
    return secrets.compare_digest(user, WEB_C2_AUTH_USER) and secrets.compare_digest(pw, WEB_C2_AUTH_PASSWORD)


__all__ = [
    "ALLOWED_NETWORKS",
    "LOOPBACK_NETWORKS",
    "PRIVATE_NETWORKS",
    "client_ip_allowed",
    "is_loopback_ip",
    "is_private_ip",
    "check_basic_auth",
]
