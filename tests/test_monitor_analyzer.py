# tests/test_monitor_analyzer.py
"""Unit tests for monitor_analyzer components."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from services.monitor_analyzer import (
    IDLE_CPU_THRESHOLD,
    RAM_DROP_Z_THRESHOLD,
    BaselineStore,
    SnapshotDiffer,
    SustainedZScoreDetector,
)

# ── SnapshotDiffer ──


@pytest.mark.asyncio
async def test_diff_no_previous_snapshot():
    differ = SnapshotDiffer()
    assert await differ.diff(None, {"cpu": 50.0}) == []


@pytest.mark.asyncio
async def test_diff_new_external_ip():
    differ = SnapshotDiffer()
    prev = {"suspicious_net": ["10.0.0.1:443 (chrome:1234)"]}
    curr = {
        "suspicious_net": [
            "10.0.0.1:443 (chrome:1234)",
            "192.168.1.1:80 (unknown:5678)",
        ]
    }
    events = await differ.diff(prev, curr)
    assert len(events) == 1
    assert events[0].category == "net"
    assert "192.168.1.1" in events[0].reason


@pytest.mark.asyncio
async def test_diff_new_heavy_process():
    differ = SnapshotDiffer()
    prev = {"top_procs": [{"pid": 1, "name": "idle", "cpu_percent": 1.0}]}
    curr = {
        "top_procs": [
            {"pid": 1, "name": "idle", "cpu_percent": 1.0},
            {"pid": 2, "name": "heavy", "cpu_percent": 20.0},
        ]
    }
    events = await differ.diff(prev, curr)
    assert len(events) == 1
    assert events[0].category == "proc"
    assert "heavy" in events[0].reason


@pytest.mark.asyncio
async def test_diff_cpu_spike_existing_process():
    differ = SnapshotDiffer()
    prev = {"top_procs": [{"pid": 1, "name": "app", "cpu_percent": 5.0}]}
    curr = {"top_procs": [{"pid": 1, "name": "app", "cpu_percent": 25.0}]}
    events = await differ.diff(prev, curr)
    assert len(events) == 1
    assert events[0].metric == "process_cpu_spike"


@pytest.mark.asyncio
async def test_diff_learned_baseline_suppresses_known_combo():
    """Known (process, ip, port) combos should be suppressed."""
    differ = SnapshotDiffer()
    prev = {"suspicious_net": []}
    curr = {
        "suspicious_net": [
            "192.168.1.1:443 (chrome:5678)",
        ]
    }
    with patch(
        "services.net_noise_filter.is_known_combo",
        new_callable=AsyncMock,
        return_value=True,
    ):
        events = await differ.diff(prev, curr)
    assert events == []


@pytest.mark.asyncio
async def test_diff_self_process_pid_suppressed():
    """python.exe with Sentinel's PID must be suppressed via is_self_process.

    Regression: _extract_conns stripped PID, so suppression_reason never
    called is_self_process(pid, ...) — only name-only check (which excludes
    python.exe). Every new IP the bot connected to fired an alert.
    """
    differ = SnapshotDiffer()
    prev = {"suspicious_net": []}
    curr = {
        "suspicious_net": [
            "[23.95.31.126]:443 (DigitalOcean / AS14061) (python.exe:99999)",
        ]
    }
    with patch(
        "services.self_whitelist.is_self_process",
        return_value=True,
    ):
        events = await differ.diff(prev, curr)
    assert events == [], "Self-process (python.exe:SentinelPID) must be suppressed"


@pytest.mark.asyncio
async def test_diff_learned_baseline_fail_open():
    """If is_known_combo raises, emit the alert (fail-open)."""
    differ = SnapshotDiffer()
    prev = {"suspicious_net": []}
    curr = {
        "suspicious_net": [
            "192.168.1.1:443 (chrome:5678)",
        ]
    }
    with patch(
        "services.net_noise_filter.is_known_combo",
        new_callable=AsyncMock,
        side_effect=Exception("db down"),
    ):
        events = await differ.diff(prev, curr)
    assert len(events) == 1
    assert events[0].category == "net"


# ── SustainedZScoreDetector ──


class _FixedBaseline:
    """Mock BaselineStore that returns constant mean/std."""

    def __init__(self, mean: float = 50.0, std: float = 10.0):
        self.mean = mean
        self.std = std

    def get_stats(self, metric, window_days=7):
        return (self.mean, self.std)


def _run(coro):
    return asyncio.run(coro)


def test_zscore_skips_without_baseline():
    detector = SustainedZScoreDetector(threshold_z=3.0, required_cycles=3)
    events = _run(detector.detect({"cpu": 90.0}, _FixedBaseline(mean=None, std=None)))
    assert events == []


def test_zscore_requires_sustained_cycles():
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=2)
    store = _FixedBaseline(mean=50.0, std=10.0)

    # Cycle 1: z=3.0, not enough cycles
    events = _run(detector.detect({"cpu": 80.0}, store))
    assert len(events) == 0

    # Cycle 2: z=3.0, now fires
    events = _run(detector.detect({"cpu": 80.0}, store))
    assert len(events) == 1
    assert events[0].category == "cpu"

    # Cycle 3: reset after fire, count=0
    events = _run(detector.detect({"cpu": 80.0}, store))
    assert len(events) == 0


def test_zscore_24h_reset_clears_cycles():
    import time

    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=2)
    store = _FixedBaseline(mean=50.0, std=10.0)

    # Build up and fire
    _run(detector.detect({"cpu": 80.0}, store))
    _run(detector.detect({"cpu": 80.0}, store))

    # Fake that 25 hours passed
    detector._last_reset["cpu"] = time.time() - 90000

    # Next detect should reset cycle count
    _run(detector.detect({"cpu": 80.0}, store))
    assert detector._cycle_counts["cpu"] == 1  # reset happened, building again


# ── BaselineStore (real temp SQLite) ──


def test_zscore_moderate_ram_drop_is_suppressed():
    """RAM drop < 40% (e.g. GC) must be suppressed — not a system crash."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=49.3, std=3.14)

    # 49.3 → 32.3 is a 34.5% drop — below 40% threshold, should be silent
    _run(detector.detect({"mem": 32.3}, store))
    events = _run(detector.detect({"mem": 32.3}, store))
    assert events == []


def test_zscore_ram_massive_drop_is_warn():
    """RAM drop >= 40% + extreme Z is a real crash — must alert warn."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=50.0, std=2.0)

    # 50 → 5 is a 90% drop, z = -22.5 — passes all gates
    _run(detector.detect({"mem": 5.0}, store))
    events = _run(detector.detect({"mem": 5.0}, store))
    assert len(events) == 1
    ev = events[0]
    assert ev.metric == "ram_drop"
    assert ev.severity == "warn"
    assert ev.details["z_score"] < -RAM_DROP_Z_THRESHOLD


def test_zscore_cpu_idle_is_suppressed():
    """CPU <= 2% means bot is sleeping — never alert, even with high Z."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=11.1, std=2.5)

    events = _run(detector.detect({"cpu": 0.6}, store))
    assert events == []


def test_zscore_cpu_drop_is_suppressed():
    """Any CPU drop (even with extreme Z) is idle/GC — never alert."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=50.0, std=10.0)

    # 50 → 10 is z=-4.0, but it's a drop — suppressed
    events = _run(detector.detect({"cpu": 10.0}, store))
    assert events == []


def test_zscore_positive_spike_warn_below_absolute_threshold():
    """CPU spike with high Z but below 75% absolute → WARN, not critical.

    Regression: CPU=50% with μ=10 σ=2 → z=20 → was CRITICAL.
    But 50% CPU is not a crash scenario. Only > 75% is critical.
    """
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=10.0, std=2.0)

    # value=50 → delta=40 → 20σ → but 50% < 75% absolute → WARN
    events = _run(detector.detect({"cpu": 50.0}, store))
    assert len(events) == 1
    ev = events[0]
    assert ev.metric == "cpu_spike"
    assert ev.severity == "warn"  # NOT critical — 50% < 75%
    assert ev.details["z_score"] > 0


def test_zscore_cpu_above_75_is_critical():
    """CPU > 75% absolute → CRITICAL (physical danger zone)."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=10.0, std=2.0)

    events = _run(detector.detect({"cpu": 80.0}, store))
    assert len(events) == 1
    assert events[0].severity == "critical"  # 80% > 75%


def test_zscore_ram_above_90_is_critical():
    """RAM > 90% absolute → CRITICAL (OOM danger)."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=50.0, std=2.0)

    events = _run(detector.detect({"mem": 92.0}, store))
    assert len(events) == 1
    assert events[0].severity == "critical"  # 92% > 90%


def test_zscore_cpu_spike_attributes_top_procs():
    """CPU spike must attach top-3 CPU consumers from snapshot['top_procs'].

    Deterministic attribution — the analyst/LLM gets the process name
    instead of guessing ("isolate the network") on a raw Z-score.
    """
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=3.3, std=2.0)
    snapshot = {
        "cpu": 60.0,
        "top_procs": [
            {"name": "chrome.exe", "pid": 111, "cpu_percent": 6.0},
            {"name": "MsMpEng.exe", "pid": 222, "cpu_percent": 18.2},
            {"name": "python.exe", "pid": 333, "cpu_percent": 12.5},
            {"name": "svchost.exe", "pid": 444, "cpu_percent": 5.1},
        ],
    }

    events = _run(detector.detect(snapshot, store))
    assert len(events) == 1
    top_procs = events[0].details["top_procs"]
    assert [p["name"] for p in top_procs] == ["MsMpEng.exe", "python.exe", "chrome.exe"]  # sorted desc, top 3
    assert "MsMpEng.exe" in events[0].reason
    assert "Top CPU:" in events[0].reason


def test_zscore_ram_spike_has_no_top_procs():
    """RAM spikes are not attributed via top_procs (that dict tracks CPU%, not RSS)."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=50.0, std=2.0)
    snapshot = {"mem": 92.0, "top_procs": [{"name": "chrome.exe", "pid": 1, "cpu_percent": 50.0}]}

    events = _run(detector.detect(snapshot, store))
    assert len(events) == 1
    assert "top_procs" not in events[0].details


def test_zscore_cpu_spike_missing_top_procs_is_safe():
    """No top_procs in snapshot (e.g. unit test / degraded sampler) must not error."""
    detector = SustainedZScoreDetector(threshold_z=2.0, required_cycles=1)
    store = _FixedBaseline(mean=3.3, std=2.0)

    events = _run(detector.detect({"cpu": 60.0}, store))
    assert len(events) == 1
    assert "top_procs" not in events[0].details


def test_baseline_store_roundtrip():
    # Isolate from real ema_baselines.json on disk
    from services.ema_baseline import _EMA_PATH

    if _EMA_PATH.exists():
        _EMA_PATH.unlink()
    store = BaselineStore()
    _run(store.record({"cpu": 45.0, "mem": 60.0}))

    mean_cpu, std_cpu = store.get_stats("cpu", window_days=7)
    assert mean_cpu == 45.0
    assert std_cpu > 0

    mean_mem, std_mem = store.get_stats("ram", window_days=7)
    assert mean_mem == 60.0
    assert std_mem > 0
