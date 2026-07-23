"""Resource guard — First Principles validation before heavy tool calls.

Prevents agent-induced resource exhaustion (CPU spikes + RAM drops / OOM)
by checking system telemetry against gated EMA baselines before executing
external tool calls.
"""

import logging
import math
from dataclasses import dataclass
from typing import Optional

import psutil

logger = logging.getLogger(__name__)


@dataclass
class TelemetryMetric:
    """Signed telemetry metric with mathematically correct Z-score."""

    current: float
    baseline: float
    std_dev: float

    @property
    def true_z_score(self) -> float:
        """Signed Z-score: positive = spike, negative = drop (e.g., OOM)."""
        if self.std_dev <= 0:
            return 0.0
        return (self.current - self.baseline) / self.std_dev

    @property
    def is_spike(self) -> bool:
        return self.true_z_score > 0

    @property
    def is_drop(self) -> bool:
        return self.true_z_score < 0


# Tool categories known to be CPU / memory intensive
_HEAVY_TOOLS: frozenset[str] = frozenset(
    {
        "web_search",
        "fetch_url",
        "screenshot",
        "file_search",
        "skill_intel-skill",
        "skill_report-maker",
        "skill_osquery-skill",
    }
)


def is_heavy_tool(fn_name: str) -> bool:
    """Return True if tool is known to be resource-intensive."""
    return fn_name in _HEAVY_TOOLS or fn_name.startswith(("skill_", "fetch_"))


class ResourceGuard:
    """Lightweight resource gate. Checks CPU/RAM before permitting heavy work.

    When EMA baselines are available, compares current load against the
    learned normal (μ ± σ) rather than using hard thresholds alone.
    """

    CPU_WARN: float = 50.0
    CPU_BLOCK: float = 75.0
    RAM_WARN: float = 80.0
    RAM_BLOCK: float = 90.0
    Z_WARN: float = 3.0  # warn if > 3.0σ above baseline (telemetry only, never BLOCK)

    def __init__(self) -> None:
        self._last_cpu: float = 0.0
        self._last_ram: float = 0.0
        self._cpu_z: float = 0.0
        self._ram_z: float = 0.0

    def _load_ema(self) -> dict[str, tuple[float, float]]:
        """Lazy-load EMA baselines from JSON (no async, fast path)."""
        try:
            from services.ema_baseline import _EMA_PATH

            if not _EMA_PATH.exists():
                return {}
            import json

            raw = json.loads(_EMA_PATH.read_text(encoding="utf-8"))
            out: dict[str, tuple[float, float]] = {}
            for k, v in raw.items():
                mean = float(v.get("ema", 0.0))
                std = max(math.sqrt(float(v.get("var", 1.0))), 0.5)
                out[k] = (mean, std)
            return out
        except Exception:
            return {}

    def check(self) -> tuple[bool, str]:
        """Return (permitted, reason).

        * permitted=True  → execution allowed (may carry a warning).
        * permitted=False → heavy calls must be deferred / skipped.
        """
        self._last_cpu = psutil.cpu_percent(interval=0)
        self._last_ram = psutil.virtual_memory().percent

        # Absolute hard limits (always enforced)
        if self._last_cpu > self.CPU_BLOCK or self._last_ram > self.RAM_BLOCK:
            msg = f"RESOURCE BLOCK: CPU={self._last_cpu:.1f}% RAM={self._last_ram:.1f}% — heavy tool calls suspended"
            logger.warning("[ResourceGuard] %s", msg)
            return False, msg

        # EMA-relative check (when baselines exist)
        # Z-score is WARN-only — it measures "unusual relative to baseline" but
        # for a system running local LLM inference, high CPU IS normal during
        # inference. Only absolute thresholds (checked above) can BLOCK.
        ema = self._load_ema()
        cpu_mean, cpu_std = ema.get("cpu", (0.0, 0.0))
        ram_mean, ram_std = ema.get("ram", (0.0, 0.0))

        self._cpu_z = (self._last_cpu - cpu_mean) / cpu_std if cpu_std > 0 else 0.0
        self._ram_z = (self._last_ram - ram_mean) / ram_std if ram_std > 0 else 0.0

        if (
            self._last_cpu > self.CPU_WARN
            or self._last_ram > self.RAM_WARN
            or self._cpu_z > self.Z_WARN
            or self._ram_z > self.Z_WARN
        ):
            msg = (
                f"RESOURCE WARN: CPU={self._last_cpu:.1f}% (z={self._cpu_z:.1f}) "
                f"RAM={self._last_ram:.1f}% (z={self._ram_z:.1f})"
            )
            logger.warning("[ResourceGuard] %s", msg)
            return True, msg

        return True, "ok"

    @property
    def last_cpu(self) -> float:
        return self._last_cpu

    @property
    def last_ram(self) -> float:
        return self._last_ram

    @property
    def cpu_z(self) -> float:
        return self._cpu_z

    @property
    def ram_z(self) -> float:
        return self._ram_z
