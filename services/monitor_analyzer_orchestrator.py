"""Sustained Z-score detector + MonitorAnalyzer orchestrator.

Extracted from monitor_analyzer.py (SRP). SustainedZScoreDetector gates
Z-score anomalies on consecutive cycles; MonitorAnalyzer is the facade
that orchestrates baseline recording, diffing, Z-score, and threat classification.
"""

import copy
import logging
import time
from typing import Any

from services.monitor_analyzer import (
    _ZSCORE_METRICS,
    ABS_SPIKE_FLOOR,
    IDLE_CPU_THRESHOLD,
    RAM_DROP_ABS_PCT,
    RAM_DROP_Z_THRESHOLD,
    AnomalyEvent,
    BaselineStore,
    SnapshotDiffer,
)
from services.net_parser import parse_ip_port
from services.threat_classifier import ThreatAssessment, ThreatClassifier

logger = logging.getLogger(__name__)


class SustainedZScoreDetector:
    """Z-score anomaly detector with sustained-threshold gate.

    A metric must exceed the Z-score threshold for ``required_cycles``
    consecutive sampling cycles before an anomaly is emitted.
    This filters workstation noise (gaming, compilation, browser tabs).
    """

    def __init__(
        self,
        threshold_z: float = 3.0,
        required_cycles: int = 3,
        metrics: tuple[str, ...] = _ZSCORE_METRICS,
    ) -> None:
        self.threshold_z = threshold_z
        self.required_cycles = required_cycles
        self.metrics = metrics
        self._cycle_counts: dict[str, int] = {}
        self._last_reset: dict[str, float] = {}
        # EMA for KoboldCpp CPU — smooths TOCTOU sampling races.
        # A single misaligned sample (psutil reads total CPU before KoboldCpp)
        # won't cause a false positive because the EMA averages it out.
        self._kobold_ema: float = 0.0
        self._kobold_ema_alpha: float = 0.3  # weight for new sample

    async def detect(
        self,
        snapshot: dict[str, Any],
        baseline_store: BaselineStore,
        window_days: int = 7,
        cotenant_active: bool = False,
    ) -> list[AnomalyEvent]:
        """Analyze snapshot against SQLite baselines; emit only sustained anomalies.

        When cotenant_active is True, spike anomalies are suppressed — the
        elevated load is explained by a known co-tenant (DEVIN/Windsurf/self
        restart), not a threat. Drop anomalies are NOT suppressed (a RAM
        drop during co-tenant activity is still suspicious).
        """
        from services.threat_hunter import is_hunt_active

        events: list[AnomalyEvent] = []
        hunt_active = is_hunt_active()
        kobold_cpu = self._update_kobold_ema(hunt_active)
        for metric in self.metrics:
            self._maybe_daily_reset(metric)
            value = self._extract_value(snapshot, metric)
            if value is None:
                continue
            value = self._adjust_for_kobold(metric, value, kobold_cpu)

            z_result = self._compute_zscore(metric, value, baseline_store, window_days)
            if z_result is None:
                self._cycle_counts[metric] = 0
                continue

            z_score, mean, std = z_result
            self._cycle_counts[metric] = self._cycle_counts.get(metric, 0) + 1
            if self._cycle_counts[metric] < self.required_cycles:
                continue

            if self._is_cotenant_suppressed(cotenant_active, z_score, metric, value, mean):
                self._cycle_counts[metric] = 0
                continue

            event = self._build_anomaly_event(metric, value, mean, std, z_score, snapshot)
            if event is not None:
                events.append(event)
            self._cycle_counts[metric] = 0

        return events

    @staticmethod
    def _top_cpu_procs(snapshot: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
        """Top-N CPU-consuming processes from the snapshot (deterministic attribution).

        `top_procs` is captured by the same 1s sampler tick that produced the
        spiking `cpu` value, so this answers "which process caused it?"
        without the LLM having to guess (e.g. "isolate the network").
        """
        procs = snapshot.get("top_procs") or []
        ranked = sorted(procs, key=lambda p: p.get("cpu_percent", 0.0), reverse=True)
        return [
            {"name": p.get("name", "?"), "pid": p.get("pid", 0), "cpu_percent": round(p.get("cpu_percent", 0.0), 1)}
            for p in ranked[:limit]
        ]

    def _compute_zscore(
        self, metric: str, value: float, baseline_store: BaselineStore, window_days: int
    ) -> tuple[float, float, float] | None:
        """Compute Z-score for a metric, or None if it should be skipped.

        Returns (z_score, mean, std) or None for: missing baseline, zero std,
        idle CPU, or z within threshold.
        """
        mean, std = baseline_store.get_stats(metric, window_days=window_days)
        if mean is None or std is None or std == 0.0:
            return None
        if metric == "cpu" and value <= IDLE_CPU_THRESHOLD:
            return None
        z_score = (value - mean) / std
        if abs(z_score) <= self.threshold_z:
            return None
        return z_score, mean, std

    @staticmethod
    def _is_cotenant_suppressed(cotenant_active: bool, z_score: float, metric: str, value: float, mean: float) -> bool:
        """Suppress spike anomalies when a known co-tenant explains the load.

        Drop anomalies are NOT suppressed — a RAM drop during co-tenant
        activity is still suspicious.
        """
        if not cotenant_active or z_score <= 0:
            return False
        logger.info(
            "[ZScore] %s spike suppressed (co-tenant active): %.1f%% z=%.1f μ=%.1f",
            metric.upper(),
            value,
            z_score,
            mean,
        )
        return True

    def _update_kobold_ema(self, hunt_active: bool) -> float:
        """Update EMA-smoothed KoboldCpp CPU; return current EMA value.

        Use EMA (exponential moving average) to smooth TOCTOU sampling races:
        psutil reads total CPU and KoboldCpp CPU at slightly different times,
        causing transient misalignment. EMA averages this out over cycles.
        """
        from services.self_whitelist import get_koboldcpp_cpu_percent

        raw_kobold = get_koboldcpp_cpu_percent() if hunt_active else 0.0
        # EMA warm-up: first sample initializes the EMA (no smoothing on first read)
        if self._kobold_ema == 0.0 and raw_kobold > 0:
            self._kobold_ema = raw_kobold
        else:
            self._kobold_ema = (self._kobold_ema_alpha * raw_kobold) + ((1 - self._kobold_ema_alpha) * self._kobold_ema)
        if not hunt_active:
            self._kobold_ema = 0.0  # reset when hunt ends
        return self._kobold_ema

    def _maybe_daily_reset(self, metric: str) -> None:
        """Reset cycle count for a metric if 24h elapsed since last reset."""
        current_time = time.time()
        if current_time - self._last_reset.get(metric, 0) > 86400:
            self._cycle_counts[metric] = 0
            self._last_reset[metric] = current_time

    def _adjust_for_kobold(self, metric: str, value: float, kobold_cpu: float) -> float:
        """Subtract EMA-smoothed KoboldCpp CPU from total CPU.

        Combined with required_cycles=3, this defeats TOCTOU:
        a single misaligned sample won't trigger, and EMA prevents
        oscillation between subtracted/unsubtracted states.
        """
        if metric == "cpu" and kobold_cpu > 0:
            original_value = value
            value = max(0.0, value - kobold_cpu)
            logger.debug(
                "[ZScore] CPU subtraction: %.1f%% - %.1f%% (KoboldCpp EMA) = %.1f%% residual",
                original_value,
                kobold_cpu,
                value,
            )
        return value

    def _build_anomaly_event(
        self,
        metric: str,
        value: float,
        mean: float,
        std: float,
        z_score: float,
        snapshot: dict[str, Any],
    ) -> AnomalyEvent | None:
        """Classify spike/drop, apply drop gates, determine severity, emit event.

        Returns None if the anomaly is suppressed (CPU drop, minor RAM drop).
        Resets the cycle count for the metric on suppression.
        """
        is_spike = z_score > 0

        # Drop gates — suppress non-dangerous drops
        if not is_spike and self._is_drop_suppressed(metric, value, mean, z_score):
            self._cycle_counts[metric] = 0
            return None

        # Absolute-floor gate — a monstrous Z-score on a quiet baseline is a
        # statistical curiosity, not a threat, if the metric is nowhere near
        # physically dangerous (e.g. CPU=26% is nothing, regardless of z=11.4).
        if is_spike and value < ABS_SPIKE_FLOOR.get(metric, 0.0):
            logger.debug(
                "[ZScore] %s spike ignored (below physical floor): %.1f%% < %.1f%% (z=%.1f, μ=%.1f)",
                metric.upper(),
                value,
                ABS_SPIKE_FLOOR.get(metric, 0.0),
                z_score,
                mean,
            )
            self._cycle_counts[metric] = 0
            return None

        severity = self._classify_severity(metric, value, is_spike)
        direction = "spike" if is_spike else "drop"
        reason = f"{metric.upper()} sustained {direction}: {value:.1f}% (baseline μ={mean:.1f}, σ={std:.1f}, z={z_score:.1f})"
        details: dict[str, Any] = {"z_score": z_score, "cycles": self._cycle_counts[metric]}

        # Deterministic process attribution — CPU spikes only (RAM isn't
        # attributable via top_procs, which tracks CPU%, not RSS).
        if metric == "cpu" and is_spike:
            top_procs = self._top_cpu_procs(snapshot)
            if top_procs:
                details["top_procs"] = top_procs
                proc_summary = ", ".join(f"{p['name']} ({p['cpu_percent']:.1f}%)" for p in top_procs)
                reason += f" | Top CPU: {proc_summary}"

        return AnomalyEvent(
            category=metric,
            metric=f"{metric}_{direction}",
            current=value,
            baseline=mean,
            std=std,
            reason=reason,
            severity=severity,
            details=details,
        )

    @staticmethod
    def _is_drop_suppressed(metric: str, value: float, mean: float, z_score: float) -> bool:
        """Check if a drop anomaly should be suppressed (not dangerous).

        CPU drops are always suppressed (idle/GC). RAM drops suppressed if
        below absolute % threshold or Z-score not extreme enough.
        """
        if metric == "cpu":
            return True
        if metric == "ram":
            drop_pct = ((mean - value) / mean) * 100 if mean > 0 else 0.0
            if drop_pct < RAM_DROP_ABS_PCT or z_score > -RAM_DROP_Z_THRESHOLD:
                return True
        return False

    @staticmethod
    def _classify_severity(metric: str, value: float, is_spike: bool) -> str:
        """Severity by absolute threshold, NOT Z-score.

        Z-score is statistical curiosity; CRITICAL means physical danger.
        CPU > 75% or RAM > 90% = system approaching crash.
        """
        if is_spike and metric == "cpu" and value > 75.0:
            return "critical"
        if is_spike and metric == "ram" and value > 90.0:
            return "critical"
        return "warn"

    @staticmethod
    def _extract_value(snapshot: dict[str, Any], metric: str) -> float | None:
        if metric == "cpu":
            return float(snapshot["cpu"]) if "cpu" in snapshot else None
        if metric == "ram":
            return float(snapshot["mem"]) if "mem" in snapshot else None
        return None


class MonitorAnalyzer:
    """Facade — orchestrates baseline recording, diffing, sustained Z-score, + threat classification."""

    def __init__(
        self,
        z_threshold: float = 3.0,
        required_cycles: int = 3,
        window_days: int = 7,
    ) -> None:
        self.baseline_store = BaselineStore()
        self.differ = SnapshotDiffer()
        self.z_detector = SustainedZScoreDetector(
            threshold_z=z_threshold,
            required_cycles=required_cycles,
        )
        self.threat_classifier = ThreatClassifier()
        self.window_days = window_days
        self._prev_snapshot: dict[str, Any] | None = None

    @staticmethod
    def _parse_suspicious_net_line(line: str) -> dict[str, Any] | None:
        """Parse '[ip]:port (proc:pid)' or 'ip:port (proc:pid)' into connection dict."""
        if "(" not in line or ")" not in line:
            return None
        ip_part = line.split(" ")[0]
        proc_part = line.split("(")[1].split(")")[0]
        ip, port = parse_ip_port(ip_part)
        if not ip or not port:
            return None
        proc_name = proc_part.split(":")[0] if ":" in proc_part else "unknown"
        pid_str = proc_part.split(":")[1] if ":" in proc_part else "0"
        try:
            pid = int(pid_str)
        except ValueError:
            pid = 0
        return {
            "proc_name": proc_name,
            "pid": pid,
            "raddr_ip": ip,
            "raddr_port": port,
            "laddr_ip": "0.0.0.0",
            "laddr_port": 0,
        }

    async def analyze(self, snapshot: dict[str, Any]) -> tuple[list[AnomalyEvent], list[ThreatAssessment]]:
        """Run full analysis pipeline on a snapshot.

        1. Record metrics for future baseline training.
        2. Diff against previous snapshot (structural changes).
        3. Run sustained Z-score detection.
        4. Classify network threats via behavioral + heuristic profiling.
        5. Update previous-snapshot reference.
        """
        await self.baseline_store.record(snapshot)

        diff_events = await self.differ.diff(self._prev_snapshot, snapshot)
        cotenant = self.baseline_store.is_cotenant_active()
        z_events = await self.z_detector.detect(
            snapshot, self.baseline_store, window_days=self.window_days, cotenant_active=cotenant
        )

        threats: list[ThreatAssessment] = []
        raw_connections: list[dict[str, Any]] = []
        for line in snapshot.get("suspicious_net", []):
            parsed = self._parse_suspicious_net_line(line)
            if parsed:
                raw_connections.append(parsed)
        if raw_connections:
            threats = await self.threat_classifier.classify(connections=raw_connections)
            if any(t.status != "clean" for t in threats):
                summary = "\n".join(
                    f"{c['proc_name']}:{c.get('pid', 0)} -> {c['raddr_ip']}:{c.get('raddr_port', 0)}"
                    for c in raw_connections
                )
                llm_ta = await self.threat_classifier.llm_threat_summary(
                    connection_summary=summary,
                    connections=raw_connections,
                    timeout=10.0,
                )
                if llm_ta.status != "clean":
                    threats.append(llm_ta)

        self._prev_snapshot = copy.deepcopy(snapshot)
        return diff_events + z_events, threats
