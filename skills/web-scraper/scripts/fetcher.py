"""HTTP fetcher — GET with retries, backoff, size cap, Hebrew-aware decoding."""

from __future__ import annotations

import os
import random
import time

import requests

from _fetch_safety import _is_blocked, _robots_allowed, _throttle_domain
from _hebrew import _normalize_hebrew_encoding

DEFAULT_UA = os.getenv("SENTINEL_USER_AGENT", "SentinelBot/1.0 (+https://github.com/)")
# Hard cap on response body size (bytes). Default 10MB. Override via env.
MAX_RESPONSE_BYTES = int(os.getenv("SENTINEL_SCRAPER_MAX_BYTES", str(10 * 1024 * 1024)))


_RETRY_STATUS_CODES = (429, 500, 502, 503, 504)


def _check_fetch_safety(url: str, user_agent: str, respect_robots: bool) -> None:
    """SSRF + robots.txt guards — raise PermissionError if blocked."""
    if _is_blocked(url):
        raise PermissionError(f"SSRF: internal address blocked for {url}")
    if respect_robots and not _robots_allowed(url, user_agent):
        raise PermissionError(f"robots.txt disallows {url} for UA={user_agent}")


def _check_content_length(r: requests.Response) -> None:
    """Pre-flight: reject if Content-Length declares oversized body."""
    cl = r.headers.get("Content-Length")
    if cl and cl.isdigit() and int(cl) > MAX_RESPONSE_BYTES:
        r.close()
        raise ValueError(
            f"Response too large: {int(cl):,} bytes > cap {MAX_RESPONSE_BYTES:,}"
        )


def _stream_response_body(r: requests.Response) -> bytes:
    """Stream response into buffer with hard cap. Raises ValueError on overflow."""
    buf = bytearray()
    for chunk in r.iter_content(chunk_size=65536):
        if not chunk:
            continue
        buf.extend(chunk)
        if len(buf) > MAX_RESPONSE_BYTES:
            r.close()
            raise ValueError(
                f"Response exceeded cap of {MAX_RESPONSE_BYTES:,} bytes"
            )
    return bytes(buf)


def _decode_response(r: requests.Response, body: bytes) -> str:
    """Hebrew-aware decoding: try declared encoding, fall back to UTF-8/cp1255."""
    declared = (
        r.encoding
        if r.encoding and r.encoding.lower() != "iso-8859-1"
        else None
    )
    return _normalize_hebrew_encoding(body, declared)


def _attempt_fetch(
    sess: requests.Session | type[requests],
    url: str,
    headers: dict[str, str],
    timeout: float,
) -> str:
    """Single fetch attempt — returns decoded body or raises retryable error."""
    r = sess.get(url, timeout=timeout, headers=headers, stream=True)
    if r.status_code in _RETRY_STATUS_CODES:
        r.close()
        raise requests.HTTPError(f"HTTP {r.status_code}")
    r.raise_for_status()
    _check_content_length(r)
    body = _stream_response_body(r)
    r.close()
    return _decode_response(r, body)


def fetch(
    url: str,
    user_agent: str = DEFAULT_UA,
    retries: int = 3,
    backoff: float = 1.5,
    timeout: float = 20.0,
    respect_robots: bool = True,
    session: requests.Session | None = None,
) -> str:
    """GET with exponential backoff on 5xx/429/network errors. Hebrew-aware decoding."""
    _check_fetch_safety(url, user_agent, respect_robots)
    headers = {"User-Agent": user_agent, "Accept-Language": "he,en;q=0.8"}
    sess = session or requests
    last_err: Exception | None = None
    for attempt in range(max(1, retries)):
        _throttle_domain(url)
        try:
            return _attempt_fetch(sess, url, headers, timeout)
        except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as e:
            last_err = e
        except ValueError:
            raise
        sleep_for = (backoff**attempt) + random.uniform(0, 0.5)
        time.sleep(sleep_for)
    raise last_err if last_err else RuntimeError(f"fetch failed: {url}")
