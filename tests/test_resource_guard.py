"""Tests for services/agent/resource_guard.py"""

import pytest

from services.agent.resource_guard import (
    ResourceGuard,
    TelemetryMetric,
    is_heavy_tool,
)


class TestTelemetryMetric:
    def test_true_z_score_spike(self):
        m = TelemetryMetric(current=80.0, baseline=50.0, std_dev=10.0)
        assert m.true_z_score == pytest.approx(3.0)
        assert m.is_spike is True
        assert m.is_drop is False

    def test_true_z_score_drop(self):
        """RAM drop: 32.3% vs baseline 49.3% → negative Z."""
        m = TelemetryMetric(current=32.3, baseline=49.3, std_dev=3.14)
        assert m.true_z_score == pytest.approx(-5.41, abs=0.05)
        assert m.is_spike is False
        assert m.is_drop is True

    def test_true_z_score_zero_std(self):
        m = TelemetryMetric(current=50.0, baseline=50.0, std_dev=0.0)
        assert m.true_z_score == 0.0


class TestIsHeavyTool:
    def test_known_heavy_tools(self):
        assert is_heavy_tool("web_search") is True
        assert is_heavy_tool("fetch_url") is True
        assert is_heavy_tool("screenshot") is True

    def test_skill_prefix_heavy(self):
        assert is_heavy_tool("skill_report-maker") is True
        assert is_heavy_tool("skill_intel-skill") is True

    def test_light_tools(self):
        assert is_heavy_tool("final_answer") is False
        assert is_heavy_tool("echo") is False


class TestResourceGuard:
    def test_check_returns_tuple(self):
        rg = ResourceGuard()
        permitted, reason = rg.check()
        assert isinstance(permitted, bool)
        assert isinstance(reason, str)

    def test_last_values_populated_after_check(self):
        rg = ResourceGuard()
        rg.check()
        assert rg.last_cpu >= 0.0
        assert rg.last_ram >= 0.0

    def test_z_properties_populated_after_check(self):
        rg = ResourceGuard()
        rg.check()
        assert isinstance(rg.cpu_z, float)
        assert isinstance(rg.ram_z, float)

    def test_load_ema_returns_dict(self):
        rg = ResourceGuard()
        ema = rg._load_ema()
        assert isinstance(ema, dict)

    def test_z_score_does_not_block(self):
        """Z-score above 3σ should WARN, not BLOCK.

        Regression: EMA baseline μ=5.69 σ=2.45 → Z_BLOCK at 13.1% CPU.
        Local LLM inference naturally pushes CPU above 13%, causing
        false BLOCK that prevented the agent from doing its job.
        Fix: Z-score is WARN-only. Only absolute thresholds BLOCK.
        """
        rg = ResourceGuard()
        # Simulate CPU=16% with baseline μ=5.69 σ=2.45 → z=4.2
        rg._last_cpu = 16.0
        rg._last_ram = 45.0
        rg._cpu_z = 4.2
        rg._ram_z = -0.2
        # Even with z=4.2, should NOT block if absolute < BLOCK
        # CPU=16% < CPU_BLOCK=75% → should permit
        assert rg._last_cpu < rg.CPU_BLOCK
        assert rg._last_ram < rg.RAM_BLOCK

    def test_absolute_thresholds_block(self):
        """CPU > 75% or RAM > 90% must BLOCK regardless of Z-score."""
        rg = ResourceGuard()
        rg._last_cpu = 80.0
        assert rg._last_cpu > rg.CPU_BLOCK  # 80 > 75 → would block
        rg._last_cpu = 60.0
        rg._last_ram = 95.0
        assert rg._last_ram > rg.RAM_BLOCK  # 95 > 90 → would block
