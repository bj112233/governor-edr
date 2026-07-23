"""Unit tests for the Smart Circuit Breaker.

Covers the 4-state machine (CLOSED/DEGRADED/OPEN/HALF_OPEN), TPOT-based
degradation, hysteresis, baseline warmup, and HALF_OPEN recovery probe.

Sprint 4 moved all CB state out of LLMBridge into the standalone
``CircuitBreaker`` class (services/llm_bridge/circuit_breaker.py). These
tests target CircuitBreaker directly for the state machine, and verify
LLMBridge delegation (should_accept_traffic / is_degraded / reset_baseline)
plus the embed HALF_OPEN recovery path.
"""

from __future__ import annotations

import asyncio

import pytest

from config import (
    LLM_BASELINE_SAMPLES,
    LLM_CB_THRESHOLD,
    LLM_DEGRADED_CLEAR_MULTIPLIER,
    LLM_DEGRADED_MULTIPLIER,
    LLM_MIN_TOKENS_FOR_TPOT,
    LLM_OPEN_COOLDOWN,
)
from services.llm_bridge.circuit_breaker import CircuitBreaker
from services.llm_bridge.models import (
    _STATE_CLOSED,
    _STATE_DEGRADED,
    _STATE_HALF_OPEN,
    _STATE_OPEN,
)


@pytest.fixture
def cb() -> CircuitBreaker:
    """Fresh CircuitBreaker — isolated per test."""
    return CircuitBreaker("test")


# --- Failure / OPEN transitions ---------------------------------------------


def test_closed_to_open_after_threshold(cb: CircuitBreaker) -> None:
    for _ in range(LLM_CB_THRESHOLD):
        cb.on_failure()
    assert cb.state == _STATE_OPEN
    assert cb.opened_at > 0


def test_below_threshold_stays_closed(cb: CircuitBreaker) -> None:
    for _ in range(LLM_CB_THRESHOLD - 1):
        cb.on_failure()
    assert cb.state == _STATE_CLOSED


def test_success_resets_failure_count(cb: CircuitBreaker) -> None:
    for _ in range(LLM_CB_THRESHOLD - 1):
        cb.on_failure()
    cb.on_success()
    assert cb.consecutive_failures == 0
    assert cb.state == _STATE_CLOSED


def test_half_open_to_open_on_failure(cb: CircuitBreaker) -> None:
    cb.state = _STATE_HALF_OPEN
    cb.consecutive_failures = 0
    cb.on_failure()
    # HALF_OPEN must trip OPEN on the very first failure
    assert cb.state == _STATE_OPEN


def test_half_open_to_closed_on_success(cb: CircuitBreaker) -> None:
    cb.state = _STATE_HALF_OPEN
    cb.on_success()
    assert cb.state == _STATE_CLOSED


def test_open_to_half_open_after_cooldown(cb: CircuitBreaker) -> None:
    import time as _time

    cb.state = _STATE_OPEN
    cb.opened_at = _time.monotonic() - (LLM_OPEN_COOLDOWN + 1)
    assert cb.can_probe() is True
    cb.promote_half_open()
    assert cb.state == _STATE_HALF_OPEN


def test_open_rejects_probe_before_cooldown(cb: CircuitBreaker) -> None:
    import time as _time

    cb.state = _STATE_OPEN
    cb.opened_at = _time.monotonic()
    assert cb.can_probe() is False


# --- TPOT baseline + DEGRADED transitions -----------------------------------


def _warmup_baseline(cb: CircuitBreaker, tpot_ms: float = 50.0) -> None:
    """Feed N samples at a healthy TPOT to lock the baseline."""
    seconds = (tpot_ms / 1000.0) * LLM_MIN_TOKENS_FOR_TPOT
    for _ in range(LLM_BASELINE_SAMPLES):
        cb.record_latency(seconds, LLM_MIN_TOKENS_FOR_TPOT)


def test_baseline_locks_after_warmup(cb: CircuitBreaker) -> None:
    _warmup_baseline(cb, tpot_ms=50.0)
    assert cb.tpot_baseline_ms is not None
    assert 49.0 < cb.tpot_baseline_ms < 51.0


def test_short_completions_are_dropped(cb: CircuitBreaker) -> None:
    # Below MIN_TOKENS_FOR_TPOT → ignored entirely
    for _ in range(LLM_BASELINE_SAMPLES):
        cb.record_latency(5.0, LLM_MIN_TOKENS_FOR_TPOT - 1)
    assert cb.tpot_baseline_ms is None
    assert cb.tpot_ema_ms is None


def test_zero_tokens_does_not_crash(cb: CircuitBreaker) -> None:
    cb.record_latency(2.0, 0)
    assert cb.tpot_ema_ms is None


def test_long_slow_call_triggers_degraded(cb: CircuitBreaker) -> None:
    _warmup_baseline(cb, tpot_ms=50.0)
    # Inject many slow samples → EMA must climb above 3× baseline
    bad_tpot = 50.0 * LLM_DEGRADED_MULTIPLIER * 2.0
    seconds = (bad_tpot / 1000.0) * LLM_MIN_TOKENS_FOR_TPOT
    for _ in range(20):
        cb.record_latency(seconds, LLM_MIN_TOKENS_FOR_TPOT)
    assert cb.state == _STATE_DEGRADED


def test_long_fast_call_stays_closed(cb: CircuitBreaker) -> None:
    """Long generation but healthy per-token rate → must remain CLOSED."""
    _warmup_baseline(cb, tpot_ms=50.0)
    # 500 tokens at 50ms/token = 25s wall-clock — healthy
    cb.record_latency(25.0, 500)
    assert cb.state == _STATE_CLOSED


def test_degraded_clears_with_hysteresis(cb: CircuitBreaker) -> None:
    _warmup_baseline(cb, tpot_ms=50.0)
    # Trip to DEGRADED
    bad_tpot = 50.0 * LLM_DEGRADED_MULTIPLIER * 2.0
    seconds_bad = (bad_tpot / 1000.0) * LLM_MIN_TOKENS_FOR_TPOT
    for _ in range(20):
        cb.record_latency(seconds_bad, LLM_MIN_TOKENS_FOR_TPOT)
    assert cb.state == _STATE_DEGRADED

    # Recovery: drop well below clear threshold
    good_tpot = 50.0 * (LLM_DEGRADED_CLEAR_MULTIPLIER * 0.5)
    seconds_good = (good_tpot / 1000.0) * LLM_MIN_TOKENS_FOR_TPOT
    for _ in range(50):
        cb.record_latency(seconds_good, LLM_MIN_TOKENS_FOR_TPOT)
    assert cb.state == _STATE_CLOSED


def test_degraded_does_not_block_traffic(cb: CircuitBreaker) -> None:
    cb.state = _STATE_DEGRADED
    assert cb.should_accept() is True


def test_open_blocks_traffic(cb: CircuitBreaker) -> None:
    cb.state = _STATE_OPEN
    assert cb.should_accept() is False


def test_half_open_blocks_traffic(cb: CircuitBreaker) -> None:
    cb.state = _STATE_HALF_OPEN
    assert cb.should_accept() is False


# --- reset_baseline ---------------------------------------------------------


def test_reset_baseline_clears_state(cb: CircuitBreaker) -> None:
    _warmup_baseline(cb, tpot_ms=50.0)
    assert cb.tpot_baseline_ms is not None
    cb.reset_baseline()
    assert cb.tpot_baseline_ms is None
    assert cb.tpot_ema_ms is None
    assert cb.tpot_samples == []


# --- LLMBridge delegation (bridge wraps two CircuitBreaker instances) -------


def _make_bridge():
    """Build a minimal LLMBridge without hitting the network singleton.

    Uses __new__ to skip __init__ (which constructs openai clients), then
    attaches fresh CircuitBreaker instances + a ready Event.
    """
    from services.llm_bridge.bridge import LLMBridge

    b = LLMBridge.__new__(LLMBridge)
    b.cb = CircuitBreaker("main")
    b.embed_cb = CircuitBreaker("embed")
    b._ready_event = asyncio.Event()
    return b


def test_bridge_should_accept_traffic_delegates_to_cb() -> None:
    b = _make_bridge()
    assert b.should_accept_traffic() is True
    for _ in range(LLM_CB_THRESHOLD):
        b.cb.on_failure()
    assert b.should_accept_traffic() is False


def test_bridge_is_degraded_reflects_cb_state() -> None:
    b = _make_bridge()
    assert b.is_degraded() is False
    b.cb.state = _STATE_DEGRADED
    assert b.is_degraded() is True


def test_bridge_reset_baseline_delegates_to_cb() -> None:
    b = _make_bridge()
    _warmup_baseline(b.cb, tpot_ms=50.0)
    assert b.cb.tpot_baseline_ms is not None
    b.reset_baseline()
    assert b.cb.tpot_baseline_ms is None


# --- Embedding circuit breaker (regression: stuck-OPEN deadlock) ------------


def test_embed_closed_to_open_after_threshold() -> None:
    ecb = CircuitBreaker("embed")
    for _ in range(LLM_CB_THRESHOLD):
        ecb.on_failure()
    assert ecb.state == _STATE_OPEN
    assert ecb.opened_at > 0


def test_embed_half_open_to_closed_on_success() -> None:
    ecb = CircuitBreaker("embed")
    ecb.state = _STATE_HALF_OPEN
    ecb.on_success()
    assert ecb.state == _STATE_CLOSED
    assert ecb.consecutive_failures == 0


def test_embed_half_open_to_open_on_failure() -> None:
    ecb = CircuitBreaker("embed")
    ecb.state = _STATE_HALF_OPEN
    ecb.consecutive_failures = 0
    ecb.on_failure()
    # HALF_OPEN must trip OPEN on the very first probe failure
    assert ecb.state == _STATE_OPEN


def test_embed_open_promotes_to_half_open_after_cooldown() -> None:
    """Regression: pre-fix, OPEN was a permanent terminal state.

    After fix, embed() must promote OPEN -> HALF_OPEN once cooldown elapses,
    letting the next call act as a probe.
    """
    import time as _time

    ecb = CircuitBreaker("embed")
    # Trip to OPEN
    for _ in range(LLM_CB_THRESHOLD):
        ecb.on_failure()
    assert ecb.state == _STATE_OPEN

    # Simulate cooldown elapsed by rewinding opened_at
    ecb.opened_at = _time.monotonic() - (LLM_OPEN_COOLDOWN + 1)
    assert ecb.can_probe() is True
    ecb.promote_half_open()
    assert ecb.state == _STATE_HALF_OPEN


def test_embed_open_rejects_before_cooldown() -> None:
    """Within cooldown window, OPEN must still reject calls fast."""
    import openai

    from services.llm_bridge.embeddings import embed

    ecb = CircuitBreaker("embed")
    for _ in range(LLM_CB_THRESHOLD):
        ecb.on_failure()
    assert ecb.state == _STATE_OPEN

    # A dummy client whose create() would succeed — but must never be reached
    # because embed() raises before calling it.
    class _Embeddings:
        async def create(self, **_kw):
            raise AssertionError("create() must not be called while OPEN")

    class _Client:
        embeddings = _Embeddings()

    sem = asyncio.Semaphore(1)
    with pytest.raises(openai.APIConnectionError):
        asyncio.run(embed(_Client(), ["hello"], ecb, sem))


# --- force_open (external trip) --------------------------------------------


def test_force_open_trips_immediately(cb: CircuitBreaker) -> None:
    """force_open() trips the breaker to OPEN without needing N failures."""
    assert cb.state == _STATE_CLOSED
    cb.force_open("Storm: 32 KoboldCpp connections", timeout_seconds=30)
    assert cb.state == _STATE_OPEN
    assert cb.consecutive_failures >= LLM_CB_THRESHOLD
    assert cb._force_cooldown == 30.0


def test_force_open_respects_custom_cooldown(cb: CircuitBreaker) -> None:
    """can_probe() must use the force_open cooldown, not LLM_OPEN_COOLDOWN."""
    cb.force_open("test", timeout_seconds=60)
    # Immediately after — should not probe (60s not elapsed)
    assert not cb.can_probe()
    # Simulate 31s elapsed (default LLM_OPEN_COOLDOWN might be < 60)
    cb.opened_at -= 31.0
    # Still within 60s force_cooldown → must not probe
    assert not cb.can_probe()
    # Simulate 61s elapsed
    cb.opened_at -= 30.0
    assert cb.can_probe()


def test_force_open_cleared_on_success(cb: CircuitBreaker) -> None:
    """on_success() clears _force_cooldown so normal cooldown resumes."""
    cb.force_open("test", timeout_seconds=99)
    assert cb._force_cooldown == 99.0
    cb.on_success()
    assert cb._force_cooldown is None
    assert cb.state == _STATE_CLOSED


# --- Connection storm IoC (REMOVED) ----------------------------------------
# The connection-storm detector counted self-whitelisted (benign) Sentinel→
# KoboldCpp connections as an anomaly — a category error that caused a self-DoS
# (circuit breaker oscillated OPEN/CLOSED every ~60s). The shared httpx pool
# (max_connections=5) is the sole, sufficient defense against connection leaks.
# See commit history for the removal rationale.


if __name__ == "__main__":
    asyncio.run(test_embed_open_promotes_to_half_open_after_cooldown())
    print("OK")
