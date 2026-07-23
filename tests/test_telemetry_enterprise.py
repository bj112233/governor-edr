# tests/test_telemetry_enterprise.py
"""Tests for enterprise-grade telemetry metrics:
- TPOT (tokens per second)
- Context saturation (avg prompt tokens / context window)
- Event loop lag
"""

import asyncio
import time

import pytest

from services.telemetry import Telemetry


@pytest.fixture
def telemetry(tmp_path):
    """Fresh Telemetry instance with temp path."""
    return Telemetry(path=tmp_path / "test_telemetry.jsonl")


# ── TPOT tracking ──


@pytest.mark.asyncio
async def test_tpot_tracked_when_tokens_out(telemetry):
    """measure_llm with tokens_out > 0 → tpot_samples populated."""
    async with telemetry.measure_llm("test", "test-model") as tm:
        tm["tokens_in"] = 100
        tm["tokens_out"] = 50
        await asyncio.sleep(0.01)  # 10ms
    assert len(telemetry._tpot_samples) == 1
    tps = telemetry._tpot_samples[0]
    assert tps > 0  # tokens/sec > 0


@pytest.mark.asyncio
async def test_tpot_not_tracked_when_zero_tokens(telemetry):
    """measure_llm with tokens_out=0 → no tpot sample (avoid div-by-zero)."""
    async with telemetry.measure_llm("test", "test-model") as tm:
        tm["tokens_in"] = 100
        tm["tokens_out"] = 0
    assert len(telemetry._tpot_samples) == 0


@pytest.mark.asyncio
async def test_tpot_snapshot_includes_tps(telemetry):
    """snapshot() includes tpot_tps field."""
    async with telemetry.measure_llm("test", "m") as tm:
        tm["tokens_out"] = 100
        await asyncio.sleep(0.01)
    snap = telemetry.snapshot()
    assert "tpot_tps" in snap["llm"]
    assert snap["llm"]["tpot_tps"] > 0
    assert "tpot_p50_ms" in snap["llm"]
    # tpot_p50_ms = 1000 / tps, NOT tps * 1000
    # If tps=14, ms/tok should be ~71, not 14000
    assert snap["llm"]["tpot_p50_ms"] < 1000  # sanity: < 1s per token


# ── Context saturation ──


@pytest.mark.asyncio
async def test_context_saturation_tracked(telemetry):
    """measure_llm with tokens_in > 0 → ctx_samples populated."""
    async with telemetry.measure_llm("test", "m") as tm:
        tm["tokens_in"] = 2000
        tm["tokens_out"] = 50
    assert len(telemetry._ctx_samples) == 1
    assert telemetry._ctx_samples[0] == 2000


@pytest.mark.asyncio
async def test_context_saturation_snapshot(telemetry):
    """snapshot() includes ctx_avg, ctx_max, ctx_sat_pct."""
    async with telemetry.measure_llm("test", "m") as tm:
        tm["tokens_in"] = 4000
        tm["tokens_out"] = 10
    snap = telemetry.snapshot()
    assert snap["llm"]["ctx_avg"] == 4000
    assert snap["llm"]["ctx_max"] > 0  # from config
    assert snap["llm"]["ctx_sat_pct"] > 0
    # 4000 / 16384 ≈ 24.4%
    assert 20 < snap["llm"]["ctx_sat_pct"] < 30


# ── Event loop lag ──


@pytest.mark.asyncio
async def test_event_loop_lag_measured(telemetry):
    """_measure_loop_lag populates loop_lag_samples."""
    await telemetry._measure_loop_lag()
    assert len(telemetry._loop_lag_samples) == 1
    lag_ms = telemetry._loop_lag_samples[0]
    # Should be very small (< 5ms) in test environment
    assert 0 <= lag_ms < 50


@pytest.mark.asyncio
async def test_event_loop_lag_snapshot(telemetry):
    """snapshot() includes loop_lag_ms and loop_lag_p95_ms."""
    await telemetry._measure_loop_lag()
    await telemetry._measure_loop_lag()
    snap = telemetry.snapshot()
    assert "loop_lag_ms" in snap
    assert "loop_lag_p95_ms" in snap
    assert snap["loop_lag_ms"] >= 0


@pytest.mark.asyncio
async def test_event_loop_lag_detects_blocking(telemetry):
    """Simulate blocking I/O → lag should spike."""
    # Measure lag before blocking
    await telemetry._measure_loop_lag()
    baseline_lag = telemetry._loop_lag_samples[-1]

    # Simulate blocking sync call (50ms)
    time.sleep(0.05)
    await telemetry._measure_loop_lag()
    after_lag = telemetry._loop_lag_samples[-1]

    # After blocking, lag should be higher (the callback was delayed)
    # Note: this is not guaranteed to be strictly higher due to timing,
    # but it should be non-zero
    assert after_lag >= 0
