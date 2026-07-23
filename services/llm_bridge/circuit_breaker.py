# services/llm_bridge/circuit_breaker.py
"""Stateful Circuit Breaker + TPOT EMA. Instantiated once per LLMBridge."""

import logging
import time
from typing import Final

from config import (
    LLM_BASELINE_SAMPLES,
    LLM_CB_THRESHOLD,
    LLM_DEGRADED_CLEAR_MULTIPLIER,
    LLM_DEGRADED_MULTIPLIER,
    LLM_EMA_ALPHA,
    LLM_MIN_TOKENS_FOR_TPOT,
    LLM_OPEN_COOLDOWN,
)

from .models import _STATE_CLOSED, _STATE_DEGRADED, _STATE_HALF_OPEN, _STATE_OPEN

logger = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker with TPOT-based degradation detection."""

    def __init__(self, name: str = "main") -> None:
        self.name = name
        self.state: str = _STATE_CLOSED
        self.consecutive_failures: int = 0
        self.tpot_ema_ms: float | None = None
        self.tpot_baseline_ms: float | None = None
        self.tpot_samples: list[float] = []
        self.opened_at: float = 0.0
        self._force_cooldown: float | None = None  # set by force_open()

    def on_success(self) -> None:
        self.consecutive_failures = 0
        self._force_cooldown = None
        if self.state in (_STATE_OPEN, _STATE_HALF_OPEN):
            logger.info("[Bridge] Circuit %s/%s -> CLOSED — recovered.", self.name, self.state.upper())
            self.state = _STATE_CLOSED

    def on_failure(self) -> bool:
        self.consecutive_failures += 1
        should_open = (
            self.state in (_STATE_CLOSED, _STATE_DEGRADED) and self.consecutive_failures >= LLM_CB_THRESHOLD
        ) or self.state == _STATE_HALF_OPEN
        if should_open and self.state != _STATE_OPEN:
            prev = self.state
            self.state = _STATE_OPEN
            self.opened_at = time.monotonic()
            logger.warning(
                "[Bridge] Circuit %s/%s -> OPEN after %d failures.",
                self.name,
                prev.upper(),
                self.consecutive_failures,
            )
        return should_open

    def force_open(self, reason: str, timeout_seconds: int = 30) -> None:
        """Actively force the circuit breaker OPEN from an external monitor.

        Unlike on_failure() (which requires N consecutive exceptions), this
        method trips the breaker immediately — used by the NetMonitor when a
        connection storm to KoboldCpp is detected.  The cooldown is set to
        timeout_seconds so can_probe() will not promote to HALF_OPEN early.
        """
        prev = self.state
        self.state = _STATE_OPEN
        self.consecutive_failures = max(self.consecutive_failures, LLM_CB_THRESHOLD)
        self.opened_at = time.monotonic()
        self._force_cooldown = float(timeout_seconds)
        logger.critical(
            "[Bridge] Circuit %s/%s -> FORCED OPEN: %s (cooldown=%ds)",
            self.name,
            prev.upper(),
            reason,
            timeout_seconds,
        )

    def record_latency(self, seconds: float, generated_tokens: int, decode_time: float | None = None) -> None:
        if generated_tokens < LLM_MIN_TOKENS_FOR_TPOT or seconds <= 0:
            return
        # Use decode-only time when available (from KoboldCpp /api/extra/perf).
        # Falls back to total latency (prefill + decode) when perf endpoint
        # is unavailable — same behavior as before, but now the common path
        # excludes prefill, preventing False DEGRADED on large prompts.
        effective_time = decode_time if decode_time and decode_time > 0 else seconds
        tpot_ms = (effective_time / generated_tokens) * 1000.0
        if self.tpot_ema_ms is None:
            self.tpot_ema_ms = tpot_ms
        else:
            self.tpot_ema_ms = LLM_EMA_ALPHA * tpot_ms + (1.0 - LLM_EMA_ALPHA) * self.tpot_ema_ms

        if self.tpot_baseline_ms is None:
            self.tpot_samples.append(tpot_ms)
            if len(self.tpot_samples) >= LLM_BASELINE_SAMPLES:
                self.tpot_baseline_ms = sum(self.tpot_samples) / len(self.tpot_samples)
                self.tpot_samples.clear()
                logger.info(
                    "[Bridge] TPOT baseline locked: %.1f ms/token (degraded > %.1f)",
                    self.tpot_baseline_ms,
                    self.tpot_baseline_ms * LLM_DEGRADED_MULTIPLIER,
                )
            return

        if self.state not in (_STATE_CLOSED, _STATE_DEGRADED):
            return
        degraded_threshold = self.tpot_baseline_ms * LLM_DEGRADED_MULTIPLIER
        clear_threshold = self.tpot_baseline_ms * LLM_DEGRADED_CLEAR_MULTIPLIER
        if self.state == _STATE_CLOSED and self.tpot_ema_ms > degraded_threshold:
            self.state = _STATE_DEGRADED
            logger.warning(
                "[Bridge] Circuit DEGRADED — TPOT %.1fms > %.1fms",
                self.tpot_ema_ms,
                degraded_threshold,
            )
        elif self.state == _STATE_DEGRADED and self.tpot_ema_ms < clear_threshold:
            self.state = _STATE_CLOSED
            logger.info(
                "[Bridge] Circuit CLOSED — TPOT recovered (%.1fms < %.1fms)",
                self.tpot_ema_ms,
                clear_threshold,
            )

    def reset_baseline(self) -> None:
        self.tpot_baseline_ms = None
        self.tpot_samples.clear()
        self.tpot_ema_ms = None
        logger.info("[Bridge] TPOT baseline reset")

    def should_accept(self) -> bool:
        return self.state in (_STATE_CLOSED, _STATE_DEGRADED)

    def can_probe(self) -> bool:
        """True if cooldown elapsed and circuit can transition to HALF_OPEN."""
        if self.state != _STATE_OPEN:
            return False
        cooldown = self._force_cooldown if self._force_cooldown is not None else LLM_OPEN_COOLDOWN
        return time.monotonic() - self.opened_at >= cooldown

    def promote_half_open(self) -> None:
        if self.can_probe():
            logger.info("[Bridge] Circuit %s/OPEN -> HALF_OPEN — probing.", self.name)
            self.state = _STATE_HALF_OPEN
