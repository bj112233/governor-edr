"""Fetch safety guards — SSRF blocking, per-domain throttle, robots.txt checks."""

from __future__ import annotations

import ipaddress
import os
import time
from urllib import robotparser
from urllib.parse import urlparse, urlunparse

# Minimum seconds between requests to the same hostname. Default 1.0s.
DOMAIN_MIN_INTERVAL = float(os.getenv("SENTINEL_SCRAPER_DOMAIN_INTERVAL", "1.0"))

_BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
_BLOCKED_NETS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]

_robots_cache: dict = {}
_last_hit: dict[str, float] = {}


def _is_blocked(url: str) -> bool:
    """Block internal IPs to prevent SSRF against local services."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in _BLOCKED_HOSTS:
        return True
    try:
        addr = ipaddress.ip_address(host)
        for net in _BLOCKED_NETS:
            if addr in ipaddress.ip_network(net):
                return True
    except ValueError:
        pass
    return False


def _throttle_domain(url: str) -> None:
    """Block until DOMAIN_MIN_INTERVAL has elapsed since last request to the same host."""
    if DOMAIN_MIN_INTERVAL <= 0:
        return
    host = urlparse(url).netloc.lower()
    if not host:
        return
    last = _last_hit.get(host, 0.0)
    delta = time.monotonic() - last
    if delta < DOMAIN_MIN_INTERVAL:
        time.sleep(DOMAIN_MIN_INTERVAL - delta)
    _last_hit[host] = time.monotonic()


def _robots_allowed(url: str, user_agent: str) -> bool:
    """Check robots.txt with caching. Fail-open on parse/network errors."""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return True
    base = f"{parsed.scheme}://{parsed.netloc}"
    rp = _robots_cache.get(base)
    if rp is None:
        rp = robotparser.RobotFileParser()
        rp.set_url(
            urlunparse((parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
        )
        try:
            rp.read()
        except Exception:
            rp = None
        _robots_cache[base] = rp
    if rp is None:
        return True
    try:
        return rp.can_fetch(user_agent, url)
    except Exception:
        return True
