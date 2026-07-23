"""Tests for services/ema_baseline.py — Gated EMA + EMV + Median/MAD."""

import json
import math
from pathlib import Path

import pytest

from services.ema_baseline import (
    _EMA_PATH,
    GatedEMABaseline,
    _mad,
    _median,
)


class TestRobustStats:
    def test_median_odd(self):
        assert _median([1, 3, 5]) == 3.0

    def test_median_even(self):
        assert _median([1, 3, 5, 7]) == 4.0

    def test_median_empty(self):
        assert _median([]) == 0.0

    def test_mad_basic(self):
        vals = [1, 2, 3, 4, 5]
        # median=3, abs_devs=[2,1,0,1,2], median of devs = 1
        assert _mad(vals) == 1.0


class TestGatedEMA:
    @pytest.fixture(autouse=True)
    def _patch_ema_path(self, tmp_path, monkeypatch):
        """Isolate every test from the real ema_baselines.json on disk."""
        monkeypatch.setattr("services.ema_baseline._EMA_PATH", tmp_path / "ema_test.json")

    def test_first_observation_seeds(self):
        ema = GatedEMABaseline(alpha=0.5, gate_z=2.0)
        ema.record("cpu", 50.0)
        mu, std = ema.get_stats("cpu")
        assert mu == 50.0
        assert std > 0

    def test_normal_sample_updates(self):
        ema = GatedEMABaseline(alpha=0.5, gate_z=2.0)
        ema.record("cpu", 50.0)
        ema.record("cpu", 52.0)  # close to baseline, should update
        mu, std = ema.get_stats("cpu")
        assert mu != 50.0  # moved toward 52

    def test_anomalous_sample_gated(self):
        ema = GatedEMABaseline(alpha=0.5, gate_z=2.0)
        ema.record("cpu", 50.0)
        # Warm-up: first 20 samples bypass gate
        for _ in range(19):
            ema.record("cpu", 52.0)
        # Now count=20, gate is active
        # z = (150 - ~52) / σ >> 2.0 → gated
        ema.record("cpu", 150.0)
        mu, std = ema.get_stats("cpu")
        assert mu < 150.0  # 150 was gated, mean stayed low

    def test_warmup_bypasses_gate(self):
        """During warm-up, even extreme samples update the baseline."""
        ema = GatedEMABaseline(alpha=0.05, gate_z=1.0)
        ema.record("cpu", 50.0)
        # count=1 (<20) → gate off + α=0.5 → 150 updates baseline rapidly
        ema.record("cpu", 150.0)
        mu, _ = ema.get_stats("cpu")
        assert mu > 50.0  # moved toward 150

    def test_warmup_fast_convergence(self):
        """During warm-up α=0.5, EMA converges rapidly even from bad seed."""
        ema = GatedEMABaseline(alpha=0.05, gate_z=1.0)
        ema.record("cpu", 80.0)  # bad seed
        for _ in range(19):
            ema.record("cpu", 10.0)
        mu, _ = ema.get_stats("cpu")
        # α=0.5 × 20 samples → should be close to 10
        assert abs(mu - 10.0) < 5.0

    def test_convergence(self):
        """EMA should converge to the true mean of a stable process."""
        ema = GatedEMABaseline(alpha=0.1, gate_z=5.0)
        # Seed with a reasonable starting point
        ema.record("ram", 40.0)
        for _ in range(100):
            ema.record("ram", 50.0)
        mu, _ = ema.get_stats("ram")
        assert abs(mu - 50.0) < 2.0

    def test_variance_non_negative(self):
        ema = GatedEMABaseline(alpha=0.5, gate_z=2.0)
        ema.record("cpu", 50.0)
        for v in [48.0, 52.0, 49.0, 51.0]:
            ema.record("cpu", v)
        _, std = ema.get_stats("cpu")
        assert std > 0

    def test_persistence_roundtrip(self, tmp_path, monkeypatch):
        """Save to JSON and reload — state must be identical."""
        fake_path = tmp_path / "ema_test.json"
        monkeypatch.setattr("services.ema_baseline._EMA_PATH", fake_path)

        ema = GatedEMABaseline(alpha=0.2, gate_z=2.0)
        ema.record("cpu", 30.0)
        ema.record("cpu", 32.0)
        ema._persist()

        ema2 = GatedEMABaseline(alpha=0.2, gate_z=2.0)
        ema2.load()
        mu, std = ema2.get_stats("cpu")
        assert mu > 30.0  # updated toward 32

    def test_min_std_floor(self):
        """Even with zero variance, std must stay above _MIN_STD."""
        ema = GatedEMABaseline(alpha=0.0, gate_z=2.0)
        ema.record("cpu", 50.0)
        # alpha=0 → mean never changes, variance decays
        for _ in range(10):
            ema.record("cpu", 50.0)
        _, std = ema.get_stats("cpu")
        assert std >= 2.0  # _MIN_STD was raised from 0.5→1.0→2.0

    def test_rebootstrap_after_consecutive_gates(self, tmp_path, monkeypatch):
        """After N consecutive gated samples, baseline re-bootstraps to current value."""
        fake_path = tmp_path / "ema_reboot.json"
        monkeypatch.setattr("services.ema_baseline._EMA_PATH", fake_path)

        ema = GatedEMABaseline(alpha=0.05, gate_z=1.5)
        # Seed baseline at 50% RAM
        for v in [50.0] * 25:  # past warmup
            ema.record("ram", v)
        mu_before, _ = ema.get_stats("ram")
        assert mu_before == pytest.approx(50.0, abs=1.0)

        # Now feed 10 samples at 25% — all should be gated (z << -1.5)
        for _ in range(10):
            ema.record("ram", 25.0)

        # After 10 consecutive gates, re-bootstrap should fire
        mu_after, std_after = ema.get_stats("ram")
        assert mu_after == pytest.approx(25.0, abs=1.0), f"Expected re-bootstrap to 25, got {mu_after}"
        assert std_after >= 1.0
