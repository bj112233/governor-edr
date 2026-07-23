"""Gated Exponential Moving Average (EMA) baseline — poisoning-resistant.

Updates μ and σ² only when |Z| <= θ_safe, preventing anomalous samples
(e.g., agent CPU spikes) from corrupting the baseline.

Cold-start bootstraps from SQLite audit log using Median + MAD
(outlier-robust), NOT AVG + STDDEV.
"""

import json
import logging
import math
import os
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_EMA_PATH = Path(__file__).resolve().parent.parent / "memory" / "ema_baselines.json"
_EMA_ALPHA = 0.05  # smoothing factor (~20 samples half-life)
_GATE_Z_SAFE = 1.5  # samples within ±1.5σ update the baseline
_INITIAL_VAR = 9.0  # starting variance (σ≈3)
_MIN_STD = 2.0  # floor to avoid std collapse (was 0.5→1.0, still too tight)
_WARMUP_COUNT = 20  # first N samples update baseline regardless of Z
_REBOOTSTRAP_CONSECUTIVE = 10  # re-bootstrap after N consecutive gated samples
_REBOOTSTRAP_MAGNITUDE = 0.5  # reject reboot if |new_μ - old_μ| / old_μ > this (50%)
_GATED_RING_SIZE = 20  # ring buffer for gated samples (median calculation)


def _median(values: list[float]) -> float:
    """Pure-Python median (no numpy dependency)."""
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def _mad(values: list[float]) -> float:
    """Median Absolute Deviation (robust scale estimator)."""
    med = _median(values)
    abs_devs = [abs(v - med) for v in values]
    return _median(abs_devs)


class GatedEMABaseline:
    """Poisoning-resistant EMA baseline with gated updates."""

    def __init__(self, alpha: float = _EMA_ALPHA, gate_z: float = _GATE_Z_SAFE) -> None:
        self.alpha = alpha
        self.gate_z = gate_z
        self._state: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._loaded = False

    # ── Persistence ──

    def load(self) -> None:
        """Load EMA state from JSON; bootstrap from SQLite if missing."""
        if self._loaded:
            return
        if _EMA_PATH.exists():
            try:
                self._state = json.loads(_EMA_PATH.read_text(encoding="utf-8"))
                logger.info("[EMA] Loaded %d metrics from %s", len(self._state), _EMA_PATH)
            except Exception as exc:
                logger.warning("[EMA] JSON load failed: %s", exc)
                self._state = {}
        else:
            logger.info("[EMA] JSON missing — will bootstrap from SQLite on first use")
        self._loaded = True

    def _persist(self) -> None:
        if not self._dirty:
            return
        try:
            _EMA_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(self._state, ensure_ascii=False, indent=2)
            tmp_path = _EMA_PATH.with_suffix(".json.tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            os.replace(str(tmp_path), str(_EMA_PATH))
            self._dirty = False
        except Exception as exc:
            logger.warning("[EMA] persist failed: %s", exc)

    # ── Cold-start bootstrap (Median + MAD) ──

    async def _bootstrap_metric(self, metric: str, window_days: int = 7) -> None:
        """Fetch raw values from SQLite audit log; initialise with Median + MAD."""
        from services.memory_db import get_baseline_raw_values

        values = await get_baseline_raw_values(metric, window_days=window_days)
        if not values:
            logger.info("[EMA] No SQLite data for %s — cold start deferred", metric)
            return

        med = _median(values)
        mad = _mad(values)
        # MAD → approximate σ for normal distribution (σ ≈ 1.4826 * MAD)
        approx_std = max(mad * 1.4826, _MIN_STD)
        self._state[metric] = {
            "ema": med,
            "var": approx_std**2,
            "count": len(values),
            "last_ts": time.time(),
        }
        self._dirty = True
        logger.info(
            "[EMA] Bootstrapped %s from SQLite (n=%d, median=%.2f, mad=%.2f)",
            metric,
            len(values),
            med,
            approx_std,
        )

    # ── Core update ──

    def _maybe_rebootstrap(
        self,
        metric: str,
        state: dict[str, Any],
        value: float,
        prev_mean: float,
        consecutive: int,
        ring: list[float],
        cotenant_active: bool,
    ) -> bool:
        """Decide whether to re-bootstrap the baseline after consecutive gates.

        Returns True if the caller should return (re-bootstrap or suppression
        handled the sample), False if the caller should continue to log-and-skip.
        """
        if consecutive < _REBOOTSTRAP_CONSECUTIVE:
            return False

        # ── Co-tenant suppression ──
        # A known co-tenant (DEVIN/Windsurf) explains the elevated load.
        # Do NOT re-bootstrap — the baseline must stay at the idle level so
        # that anomalies AFTER the co-tenant leaves are still detectable.
        if cotenant_active:
            logger.info(
                "[EMA-COTENANT] %s elevated (gated %d, val=%.2f) — co-tenant active, baseline preserved μ=%.2f",
                metric,
                consecutive,
                value,
                prev_mean,
            )
            state["consecutive_gated"] = 0
            state["gated_ring"] = []
            self._dirty = True
            return True

        # ── Guard 1: magnitude — reject if jump > 50% of old baseline ──
        magnitude_ratio = abs(value - prev_mean) / max(prev_mean, 0.1)
        if magnitude_ratio > _REBOOTSTRAP_MAGNITUDE:
            logger.warning(
                "[EMA-REBOOT-REJECTED] %s magnitude guard: |%.2f→%.2f|/μ=%.2f > %.0f%% — transient spike, baseline preserved",
                metric,
                prev_mean,
                value,
                prev_mean,
                _REBOOTSTRAP_MAGNITUDE * 100,
            )
            state["consecutive_gated"] = 0
            state["gated_ring"] = []
            self._dirty = True
            return True

        # ── Guard 2: use median of gated samples (robust to outliers) ──
        new_ema = _median(ring) if ring else float(value)
        logger.warning(
            "[EMA-REBOOT] %s baseline stale (gated %d consecutive), re-bootstrapping: μ=%.2f→%.2f (median of %d samples)",
            metric,
            consecutive,
            prev_mean,
            new_ema,
            len(ring),
        )
        self._state[metric] = {
            "ema": new_ema,
            "var": _INITIAL_VAR,
            "count": 1,
            "last_ts": time.time(),
            "consecutive_gated": 0,
            "gated_ring": [],
        }
        self._dirty = True
        return True

    def record(self, metric: str, value: float, cotenant_active: bool = False) -> None:
        """Gated EMA update.  Anomalous samples are logged but NOT absorbed.

        cotenant_active: True when a known co-tenant (DEVIN, Windsurf, etc.) is
        currently consuming significant CPU.  In that case the elevated load is
        explained and the baseline must NOT re-bootstrap to the spiked value.
        """
        self.load()
        state = self._state.get(metric)
        if state is None:
            # First observation for this metric — seed with value + conservative variance
            self._state[metric] = {
                "ema": float(value),
                "var": _INITIAL_VAR,
                "count": 1,
                "last_ts": time.time(),
            }
            self._dirty = True
            return

        prev_mean = state["ema"]
        prev_var = state["var"]
        prev_std = max(math.sqrt(prev_var), _MIN_STD)
        count = state.get("count", 1)

        z_score = (value - prev_mean) / prev_std
        # Warm-up: first _WARMUP_COUNT samples update baseline regardless of Z
        if count >= _WARMUP_COUNT and abs(z_score) > self.gate_z:
            consecutive = state.get("consecutive_gated", 0) + 1
            # Track gated samples in a ring buffer for median-based re-bootstrap
            ring: list[float] = state.get("gated_ring", [])
            ring.append(value)
            if len(ring) > _GATED_RING_SIZE:
                ring = ring[-_GATED_RING_SIZE:]

            if self._maybe_rebootstrap(metric, state, value, prev_mean, consecutive, ring, cotenant_active):
                return

            state["consecutive_gated"] = consecutive
            state["gated_ring"] = ring
            self._dirty = True
            logger.info(
                "[EMA-GATE] Skipped %s=%.2f (z=%.2f |μ=%.2f σ=%.2f gated=%d%s)",
                metric,
                value,
                z_score,
                prev_mean,
                prev_std,
                consecutive,
                " | co-tenant" if cotenant_active else "",
            )
            return

        # Reset consecutive counter on successful update
        state["consecutive_gated"] = 0

        # Adaptive alpha: aggressive during warm-up for fast convergence,
        # conservative after warm-up for stability.
        alpha = 0.5 if count < _WARMUP_COUNT else self.alpha

        # Update EMA
        new_mean = alpha * value + (1.0 - alpha) * prev_mean
        # Update EMV using user's formula:
        # σ²_t = (1 - α) * (σ²_{t-1} + α * (X_t - μ_{t-1})²)
        delta_sq = (value - prev_mean) ** 2
        new_var = (1.0 - alpha) * (prev_var + alpha * delta_sq)
        # Floor variance to avoid collapse
        new_var = max(new_var, _MIN_STD**2)

        state["ema"] = new_mean
        state["var"] = new_var
        state["count"] = count + 1
        state["last_ts"] = time.time()
        self._dirty = True

    def get_stats(self, metric: str) -> tuple[float | None, float | None]:
        """Return (μ, σ) for metric from live EMA state."""
        self.load()
        state = self._state.get(metric)
        if state is None:
            return None, None
        return state["ema"], max(math.sqrt(state["var"]), _MIN_STD)

    async def record_snapshot(self, metrics: dict[str, float], cotenant_active: bool = False) -> None:
        """Batch record + persist.  Called from BaselineStore.record()."""
        for metric, value in metrics.items():
            self.record(metric, value, cotenant_active=cotenant_active)
        self._persist()
