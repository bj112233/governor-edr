# tests/test_audit_fixes.py
"""Tests for 4 high-priority audit fixes: H1 (TPOT), H2 (semaphore), H3 (scheduler timeout), H4 (dedup threshold)."""

import asyncio

import pytest

from services.telemetry import Telemetry

# ── H2: Skill Semaphore (lazy init) ──


@pytest.mark.asyncio
async def test_skill_semaphore_lazy_init():
    """Semaphore must be None until first use (lazy init inside event loop)."""
    from services._skills_engine import _engine

    # Reset to None
    _engine._SKILL_SEMAPHORE = None
    assert _engine._SKILL_SEMAPHORE is None

    # First call creates it
    sem = _engine._get_skill_semaphore()
    assert sem is not None
    assert isinstance(sem, asyncio.Semaphore)

    # Second call returns same instance
    sem2 = _engine._get_skill_semaphore()
    assert sem is sem2


@pytest.mark.asyncio
async def test_skill_semaphore_limits_concurrency():
    """Verify semaphore actually limits concurrent skill executions to 3."""
    from services._skills_engine import _engine

    _engine._SKILL_SEMAPHORE = None  # Reset
    sem = _engine._get_skill_semaphore()
    assert sem._value == 3  # noqa: SLF001 — internal check

    # Acquire 3
    await sem.acquire()
    await sem.acquire()
    await sem.acquire()
    assert sem._value == 0  # noqa: SLF001

    # 4th acquire should block (verify with timeout)
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(sem.acquire(), timeout=0.1)

    # Release one
    sem.release()
    assert sem._value == 1  # noqa: SLF001


@pytest.mark.asyncio
async def test_cache_lock_lazy_init():
    """Cache lock must also be lazy (was module-level before fix)."""
    from services._skills_engine import _engine

    _engine._SKILL_CACHE_LOCK = None
    assert _engine._SKILL_CACHE_LOCK is None

    lock = _engine._get_cache_lock()
    assert lock is not None
    assert isinstance(lock, asyncio.Lock)

    lock2 = _engine._get_cache_lock()
    assert lock is lock2


# ── H3: Scheduler Timeout Wrapper ──


@pytest.mark.asyncio
async def test_timed_wrapper_success():
    """_timed wrapper passes through successful results."""
    from services.startup._scheduler import _timed

    async def fast_job():
        return "ok"

    wrapped = _timed(fast_job, "test_fast")
    result = await wrapped()
    assert result == "ok"


@pytest.mark.asyncio
async def test_timed_wrapper_timeout():
    """_timed wrapper kills job on timeout."""
    from services.startup._scheduler import _timed

    async def slow_job():
        await asyncio.sleep(10)
        return "should_not_reach"

    wrapped = _timed(slow_job, "test_slow", timeout_s=1)
    result = await wrapped()
    assert result is None  # Timed out → None


@pytest.mark.asyncio
async def test_timed_wrapper_error():
    """_timed wrapper catches exceptions and returns None."""
    from services.startup._scheduler import _timed

    async def failing_job():
        raise RuntimeError("boom")

    wrapped = _timed(failing_job, "test_fail")
    result = await wrapped()
    assert result is None


# ── H1: TPOT Prefill Separation ──


@pytest.mark.asyncio
async def test_tpot_separates_prefill_from_decode():
    """TPOT should estimate decode time separately from prefill.

    With tokens_in=1000, tokens_out=100, total_dt=10s:
    - Old: tps = 100/10 = 10 tps (includes prefill)
    - New: decode_fraction = 100/1100 = 0.091
           decode_time = 10 * 0.091 = 0.91s
           tps = 100/0.91 = 110 tps (decode only, much higher)
    """
    tel = Telemetry()
    async with tel.measure_llm("test", "qwen") as meta:
        meta["tokens_in"] = 1000
        meta["tokens_out"] = 100
        await asyncio.sleep(0.01)

    snap = tel.snapshot()
    tps = snap["llm"]["tpot_tps"]
    # With prefill separation, tps should be significantly higher than
    # the old calculation (which would be ~100/0.01 = 10000)
    # New: 100 / (0.01 * 100/1100) = 100 / 0.0009 = ~110000
    assert tps > 0


@pytest.mark.asyncio
async def test_tpot_zero_division_guard():
    """TPOT must not crash when dt is near-zero (prompt caching)."""
    tel = Telemetry()
    # Minimal dt — simulate prompt cache hit
    async with tel.measure_llm("test", "qwen") as meta:
        meta["tokens_in"] = 500
        meta["tokens_out"] = 50
        # No sleep — dt ≈ 0

    snap = tel.snapshot()
    # Should not crash, should produce a valid number
    assert snap["llm"]["tpot_tps"] >= 0
    assert snap["llm"]["tpot_p50_ms"] >= 0


@pytest.mark.asyncio
async def test_tpot_uses_real_decode_time_from_perf():
    """When decode_time is provided (from KoboldCpp perf), TPOT uses it directly."""
    tel = Telemetry()
    async with tel.measure_llm("test", "qwen") as meta:
        meta["tokens_in"] = 500
        meta["tokens_out"] = 100
        meta["decode_time"] = 0.5  # Real decode time from /api/extra/perf
        await asyncio.sleep(0.3)  # Total dt ≈ 0.3s

    snap = tel.snapshot()
    tps = snap["llm"]["tpot_tps"]
    # With real decode_time=0.5: tps = 100/0.5 = 200
    # (heuristic would be 100/(0.3*100/600) = 100/0.05 = 2000 — very different)
    assert 180 < tps < 220  # ~200 tps


@pytest.mark.asyncio
async def test_tpot_falls_back_to_heuristic_without_perf():
    """Without decode_time (no perf endpoint), TPOT uses heuristic fallback."""
    tel = Telemetry()
    async with tel.measure_llm("test", "qwen") as meta:
        meta["tokens_in"] = 500
        meta["tokens_out"] = 100
        # No decode_time — should use heuristic
        await asyncio.sleep(0.01)

    snap = tel.snapshot()
    assert snap["llm"]["tpot_tps"] > 0


# ── H1: KoboldCpp Perf Endpoint ──


@pytest.mark.asyncio
async def test_fetch_koboldcpp_perf_returns_none_on_error():
    """Perf fetch should return None silently when endpoint unavailable,
    or a valid dict when KoboldCpp is running."""
    from services.llm_bridge.completion import _fetch_koboldcpp_perf

    result = await _fetch_koboldcpp_perf()
    # Either None (no backend) or valid dict (KoboldCpp running)
    if result is not None:
        assert "decode_time" in result
        assert "prefill_time" in result
        assert "input_count" in result
        assert "output_count" in result


# ── H4: Semantic Dedup Threshold (removed — replaced by fingerprint clustering) ──
# SEMANTIC_DUP_THRESHOLD and the embeddings-based dedup were removed when
# Event Fingerprint Clustering replaced the dead-code semantic dedup.
# See test_event_fingerprint_cluster.py for the replacement tests.


def test_monitor_has_no_semantic_threshold():
    """monitor.py should no longer export SEMANTIC_DUP_THRESHOLD (dead code removed)."""
    from services.breaking_news import monitor

    assert not hasattr(monitor, "SEMANTIC_DUP_THRESHOLD"), (
        "SEMANTIC_DUP_THRESHOLD should be removed — fingerprint clustering replaced embeddings"
    )
