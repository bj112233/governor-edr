# services/agent/_noreact_tracker.py
"""No-ReAct frequency tracker — auto-inject aggressive format directive.

The 4B model stochastically collapses to free-form text (no ReAct structure)
under context degradation / long sessions. The Interceptor salvages the output,
but repeated collapses indicate systemic format drift — the model needs a
stronger reminder in the system prompt, not just the tail-anchor micro-reminder.

This module counts "No ReAct structure found" events in a sliding time window.
When the count exceeds a threshold, subsequent agent runs get an aggressive
ReAct format directive injected into the system prompt.

Design:
  - Process-level singleton (survives across agent runs in the same process).
  - Sliding window: events older than WINDOW_SECONDS are evicted.
  - Threshold: THRESHOLD events within the window → directive activated.
  - Auto-recovery: when the window empties (model behaves), directive deactivates.
  - Thread-safe via a simple lock (parser runs in async, initializer runs in async).
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Tuning ──
_WINDOW_SECONDS = 900  # 15 min — fresh directive, auto-expires when model recovers
_THRESHOLD = 3  # 3 collapses in 1h → inject aggressive directive

# The aggressive directive — stronger than the tail-anchor micro-reminder.
# Injected at system-prompt level so it persists across all turns in the run.
_AGGRESSIVE_DIRECTIVE = (
    "\n\n[CRITICAL FORMAT DIRECTIVE — ACTIVATED BY REPEATED FORMAT COLLAPSE]\n"
    "The model has repeatedly failed to maintain ReAct structure in this session.\n"
    "You MUST respond strictly using the ReAct format. No exceptions.\n"
    "Format:\n"
    "Thought: <one line reasoning>\n"
    "Action: <tool_name>\n"
    'Action Input: {"key": "value"}\n\n'
    "If you have enough data to answer, use:\n"
    "Thought: <one line reasoning>\n"
    "Action: final_answer\n"
    'Action Input: {"text": "<your answer>"}\n\n'
    "Do NOT output free-form text. Do NOT output markdown. Do NOT output prose.\n"
    "Every response MUST contain 'Thought:' and 'Action:' lines.\n"
    "[END FORMAT DIRECTIVE]"
)


@dataclass
class _TrackerState:
    """Mutable state for the No-ReAct tracker."""

    events: deque[float]
    lock: threading.Lock


# Singleton state — module-level, survives across agent runs
_state: _TrackerState = _TrackerState(events=deque(), lock=threading.Lock())


def record_no_react() -> int:
    """Record a 'No ReAct structure found' event. Returns current window count.

    Called from _react_parser.py when the parser salvages free-form text.
    """
    now = time.monotonic()
    with _state.lock:
        _evict_expired(now)
        _state.events.append(now)
        count = len(_state.events)
    logger.warning(
        "[NO-REACT-TRACKER] Event recorded. Window count=%d (threshold=%d).",
        count,
        _THRESHOLD,
    )
    return count


def is_directive_active() -> bool:
    """True if the aggressive ReAct directive should be injected.

    Checks current window count against threshold. Evicts expired events.
    """
    now = time.monotonic()
    with _state.lock:
        _evict_expired(now)
        active = len(_state.events) >= _THRESHOLD
    if active:
        logger.info(
            "[NO-REACT-TRACKER] Directive ACTIVE (%d events in window).",
            len(_state.events),
        )
    return active


def get_directive() -> str | None:
    """Return the aggressive directive string if active, else None.

    Called from _initializer.py when building the system prompt.
    """
    if is_directive_active():
        return _AGGRESSIVE_DIRECTIVE
    return None


def get_window_count() -> int:
    """Return current number of events in the sliding window (for diagnostics)."""
    now = time.monotonic()
    with _state.lock:
        _evict_expired(now)
        return len(_state.events)


def reset() -> None:
    """Reset the tracker — for testing only."""
    with _state.lock:
        _state.events.clear()


def _evict_expired(now: float) -> None:
    """Remove events older than WINDOW_SECONDS. Caller must hold lock."""
    cutoff = now - _WINDOW_SECONDS
    while _state.events and _state.events[0] < cutoff:
        _state.events.popleft()
