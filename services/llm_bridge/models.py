# services/llm_bridge/models.py
"""Constants, enums, exceptions — pure data, no logic."""

from typing import Final

_STATE_CLOSED: Final = "closed"
_STATE_DEGRADED: Final = "degraded"
_STATE_OPEN: Final = "open"
_STATE_HALF_OPEN: Final = "half_open"

# Substrings that identify a context-overflow 400 across providers
_CONTEXT_OVERFLOW_MARKERS = (
    "context_length",
    "maximum context",
    "context window",
    "too many tokens",
    "tokens exceed",
    "exceeds the max",
    "n_ctx",
)


class ContextOverflowError(RuntimeError):
    """Raised when LLM rejects request due to context_length_exceeded.

    Payload-level error (not transport): retrying the same payload will
    fail identically. Caller MUST trim messages before retrying.
    Does NOT count toward the circuit breaker.
    """


def _is_context_overflow(exc: BaseException) -> bool:
    """Heuristic match for context_length_exceeded across LLM backends."""
    msg = str(exc).lower()
    return any(marker in msg for marker in _CONTEXT_OVERFLOW_MARKERS)
