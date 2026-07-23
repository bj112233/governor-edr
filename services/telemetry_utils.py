"""Telemetry utility functions — error classification + percentile.

Extracted from telemetry.py (SRP).
"""

import asyncio
from typing import Optional


def _classify_openai_error(exc: BaseException, openai) -> str | None:
    """Classify openai-specific exceptions. Returns class string or None."""
    if isinstance(exc, openai.BadRequestError):
        return "bad_request"
    if isinstance(exc, openai.RateLimitError):
        return "rate_limit"
    if isinstance(exc, openai.APITimeoutError):
        return "timeout"
    if isinstance(exc, openai.APIConnectionError):
        return "connection"
    if isinstance(exc, openai.APIStatusError):
        status = getattr(exc, "status_code", 0) or 0
        if status >= 500:
            return "http_5xx"
        if status == 429:
            return "rate_limit"
        return "http_4xx"
    return None


def _classify_httpx_error(exc: BaseException, httpx) -> str | None:
    """Classify httpx-specific exceptions. Returns class string or None."""
    if isinstance(exc, (httpx.ConnectError,)):
        return "connection"
    if isinstance(exc, (httpx.ReadTimeout, httpx.TimeoutException)):
        return "timeout"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "connection"
    return None


def _load_error_modules() -> tuple[object | None, object | None, object | None]:
    """Lazily load optional error classification modules.

    Returns (ContextOverflowError, openai, httpx) — any may be None if import fails.
    """
    try:
        from services.llm_bridge import ContextOverflowError
    except Exception:
        ContextOverflowError = None  # type: ignore
    try:
        import openai
    except Exception:  # pragma: no cover
        openai = None
    try:
        import httpx
    except Exception:  # pragma: no cover
        httpx = None
    return ContextOverflowError, openai, httpx


def _classify_llm_error(exc: BaseException) -> str:
    """Bucket an exception into a coarse error class for /stats.

    Order matters: more-specific subclasses must be checked before bases.
    Imports are local to avoid a hard dependency on agent_bridge at module load.
    """
    ContextOverflowError, openai, httpx = _load_error_modules()

    if ContextOverflowError is not None and isinstance(exc, ContextOverflowError):  # type: ignore[arg-type]
        return "context_overflow"
    if openai is not None:
        result = _classify_openai_error(exc, openai)
        if result is not None:
            return result
    if isinstance(exc, asyncio.TimeoutError):
        return "timeout"
    if httpx is not None:
        result = _classify_httpx_error(exc, httpx)
        if result is not None:
            return result
    return "other"


def _percentile(values: list[float], pct: float) -> float:
    """Linear-interpolation percentile. Empty list -> 0.0."""
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)
