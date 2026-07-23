# tests/test_tpot_decode_separation.py
"""Tests for TPOT prefill/decode separation in circuit breaker.

Verifies that record_latency uses decode_time when available (from
KoboldCpp /api/extra/perf) instead of total latency (prefill + decode).
This prevents False DEGRADED on large prompts where prefill dominates.
"""

from services.llm_bridge.circuit_breaker import CircuitBreaker
from services.llm_bridge.models import _STATE_CLOSED, _STATE_DEGRADED


def _prime_baseline(cb: CircuitBreaker, tpot_ms: float, samples: int = 10) -> None:
    """Prime the circuit breaker baseline with N samples at given TPOT (ms/token)."""
    # tpot_ms = (effective_time / generated_tokens) * 1000
    # → effective_time = tpot_ms * generated_tokens / 1000
    eff_time = tpot_ms * 100 / 1000.0  # 100 tokens
    for _ in range(samples):
        cb.record_latency(seconds=eff_time, generated_tokens=100, decode_time=eff_time)


def test_decode_time_used_when_available():
    """When decode_time is provided, TPOT should be calculated from it, not total."""
    cb = CircuitBreaker("test")
    # Total latency = 5s (includes 4s prefill + 1s decode), 100 tokens
    # Without decode_time: tpot = 50ms/tok (would trigger DEGRADED)
    # With decode_time=1s: tpot = 10ms/tok (normal)
    _prime_baseline(cb, tpot_ms=10.0)  # baseline = 10ms/tok
    cb.record_latency(seconds=5.0, generated_tokens=100, decode_time=1.0)
    assert cb.state == _STATE_CLOSED  # Not degraded — decode-only TPOT is normal


def test_falls_back_to_total_without_decode_time():
    """Without decode_time, TPOT uses total latency (legacy behavior)."""
    cb = CircuitBreaker("test")
    _prime_baseline(cb, tpot_ms=10.0)  # baseline = 10ms/tok
    # Total latency = 5s, 100 tokens → tpot = 50ms/tok = 5x baseline
    # EMA alpha=0.2 → need multiple samples to cross 3x threshold
    for _ in range(10):
        cb.record_latency(seconds=5.0, generated_tokens=100, decode_time=None)
    assert cb.state == _STATE_DEGRADED


def test_decode_time_zero_falls_back_to_total():
    """decode_time=0 should fall back to total latency."""
    cb = CircuitBreaker("test")
    _prime_baseline(cb, tpot_ms=10.0)
    for _ in range(10):
        cb.record_latency(seconds=5.0, generated_tokens=100, decode_time=0.0)
    assert cb.state == _STATE_DEGRADED


def test_large_prompt_no_false_degraded():
    """Simulate large prompt (8K tokens) with normal decode — must NOT trigger DEGRADED."""
    cb = CircuitBreaker("test")
    _prime_baseline(cb, tpot_ms=15.0)  # baseline = 15ms/tok
    # 8K prompt → prefill = 8s, decode = 1.5s for 100 tokens
    # Without fix: tpot = 95ms/tok → 6.3x baseline → DEGRADED (false!)
    # With fix: tpot = 15ms/tok → 1.0x baseline → CLOSED (correct)
    cb.record_latency(seconds=9.5, generated_tokens=100, decode_time=1.5)
    assert cb.state == _STATE_CLOSED


def test_real_degraded_still_detected():
    """When decode is genuinely slow, DEGRADED should still trigger."""
    cb = CircuitBreaker("test")
    _prime_baseline(cb, tpot_ms=15.0)  # baseline = 15ms/tok
    # Decode genuinely slow: 6s for 100 tokens → 60ms/tok = 4x baseline
    # EMA alpha=0.2 → need multiple samples to cross 3x threshold
    for _ in range(10):
        cb.record_latency(seconds=7.0, generated_tokens=100, decode_time=6.0)
    assert cb.state == _STATE_DEGRADED
