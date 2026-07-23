"""VirusTotal rate limiter — disk-persisted token bucket (4 req/min).

VT free tier: 4 requests per minute. The intel-skill runs as a subprocess,
so an in-process semaphore would not survive across invocations. This module
persists window state to disk so multiple skill invocations share one bucket.

Thread-safe (skill uses ThreadPoolExecutor for parallel enrichment).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# VT free tier: 4 requests / 60 seconds
_MAX_CALLS = 4
_WINDOW_SECONDS = 60.0

_STATE_DIR = (
    Path(
        __import__("os").getenv("SENTINEL_STATE_DIR")
        or Path(__file__).resolve().parents[3] / "state"
    )
    / "skills"
    / "intel_cache"
)
_STATE_DIR.mkdir(parents=True, exist_ok=True)
_STATE_FILE = _STATE_DIR / "vt_bucket.json"

_lock = threading.Lock()


def _read_state() -> dict:
    """Return {"window_start": float, "count": int}. Defaults to fresh window."""
    if not _STATE_FILE.exists():
        return {"window_start": 0.0, "count": 0}
    try:
        data = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        return {
            "window_start": float(data.get("window_start", 0.0)),
            "count": int(data.get("count", 0)),
        }
    except Exception:
        return {"window_start": 0.0, "count": 0}


def _write_state(window_start: float, count: int) -> None:
    try:
        _STATE_FILE.write_text(
            json.dumps({"window_start": window_start, "count": count}),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("[VTRateLimit] Failed to persist bucket state: %s", exc)


def acquire(timeout: float = 65.0) -> bool:
    """Block until a VT request slot is available. Returns True if acquired.

    If the current 60s window has < _MAX_CALLS calls, increment and return.
    Otherwise sleep until the window resets, then start a fresh window.

    Returns False if `timeout` exceeded (should not happen for 4/min tier).
    """
    deadline = time.monotonic() + timeout
    with _lock:
        state = _read_state()
        now = time.time()
        window_age = now - state["window_start"]

        if state["window_start"] == 0.0 or window_age >= _WINDOW_SECONDS:
            # Fresh window
            _write_state(now, 1)
            logger.debug("[VTRateLimit] Fresh window, count=1")
            return True

        if state["count"] < _MAX_CALLS:
            _write_state(state["window_start"], state["count"] + 1)
            logger.debug(
                "[VTRateLimit] Window count=%d/%d",
                state["count"] + 1,
                _MAX_CALLS,
            )
            return True

        # Window full — sleep until reset
        sleep_for = _WINDOW_SECONDS - window_age
        if time.monotonic() + sleep_for > deadline:
            logger.warning(
                "[VTRateLimit] Would sleep %.1fs exceeds timeout %.1fs — aborting",
                sleep_for,
                timeout,
            )
            return False

    # Release lock during sleep so other threads can queue
    logger.info(
        "[VTRateLimit] Window full (%d/%d), sleeping %.1fs until reset",
        _MAX_CALLS,
        _MAX_CALLS,
        sleep_for,
    )
    time.sleep(sleep_for + 0.1)  # small buffer past the boundary
    with _lock:
        now = time.time()
        _write_state(now, 1)
        return True
