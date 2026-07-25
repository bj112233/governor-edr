# services/monitor_analyzer.py
"""Statistical anomaly detection — SQLite baselines, sustained Z-score, snapshot diff.

Implements the Analysis Layer of the Monitoring AI Daemon.
All new files < 300 lines (SRP).
"""

import logging
from dataclasses import dataclass, field
from typing import Any

import psutil

from config import MONITOR_PROCESS_EXCLUSIONS
from services.ema_baseline import GatedEMABaseline
from services.memory_db import store_baseline_metrics
from services.net_noise_filter import is_cdn_whitelisted_ip, parse_conn_line, suppression_reason
from services.net_parser import extract_ip_from_conn_string
from services.threat_classifier import ThreatAssessment, ThreatClassifier

logger = logging.getLogger(__name__)

# Metrics that support sustained Z-score analysis
_ZSCORE_METRICS: tuple[str, ...] = ("cpu", "ram")

# Routine Windows processes that frequently spike CPU during normal operation
# (Defender scans, search indexing, desktop compositor). Suppressed UNLESS the
# CPU usage is extreme (>=80%), which may indicate intrusion / malware activity
# the process is struggling to handle.
SAFE_PROCESSES = {
    "msmpeng.exe",
    "searchindexer.exe",
    "dwm.exe",
    "devin.exe",
    "python.exe",
    "widgets.exe",
    "taskhostw.exe",
    "backgroundtaskhost.exe",
    "searchapp.exe",
}
_SAFE_PROCESS_CPU_CEILING = 80.0
_PYTHON_CPU_CEILING = 70.0

# Co-tenant CPU threshold: if excluded processes collectively use this much CPU,
# the elevated system load is explained and the EMA baseline must not re-bootstrap.
_COTENANT_CPU_THRESHOLD = 5.0

# Sentinel gating: suppress false positives from idle state / GC
IDLE_CPU_THRESHOLD = 2.0  # CPU below this = bot is sleeping, skip metric
RAM_DROP_ABS_PCT = 40.0  # only alert on RAM drops >= this % (massive crash)
RAM_DROP_Z_THRESHOLD = 10.0  # RAM drop Z must be <= -this (extreme statistical outlier)

# Absolute spike floor (physical-danger gate) — a Z-score is a statistical
# curiosity, not a threat signal, when the metric itself is nowhere near
# physically dangerous. On a quiet idle baseline (μ≈3%), a routine background
# scan/scheduled hunt can produce z>10 while CPU is still only ~26% — no
# physical danger, no reason to page Telegram. Spikes below the floor are
# logged at DEBUG only, never built into a dispatched AnomalyEvent.
ABS_SPIKE_FLOOR = {"cpu": 40.0, "ram": 60.0}


@dataclass(frozen=True)
class AnomalyEvent:
    """Single detected anomaly."""

    category: str  # 'cpu', 'ram', 'disk', 'net', 'proc'
    metric: str  # human-readable name
    current: float  # current value
    baseline: float | None = None
    std: float | None = None
    reason: str = ""
    severity: str = "warn"  # 'info' | 'warn' | 'critical'
    details: dict = field(default_factory=dict)


class BaselineStore:
    """Poisoning-resistant baseline: Gated EMA for live stats, SQLite for audit."""

    def __init__(self) -> None:
        self._ema = GatedEMABaseline()
        self._ema.load()
        self._last_cotenant: bool = False

    @staticmethod
    def _cotenant_active() -> bool:
        """Check if a known co-tenant (DEVIN, Windsurf, cascade, LSP) is consuming
        significant CPU.  When True, the EMA baseline must NOT re-bootstrap to the
        elevated system load — the spike is explained by the co-tenant, not a threat.
        """
        try:
            excluded_lower = {ex.lower() for ex in MONITOR_PROCESS_EXCLUSIONS}
            total_cpu = 0.0
            for proc in psutil.process_iter(["name", "cpu_percent"]):
                try:
                    name = (proc.info["name"] or "").lower()
                    if any(ex in name for ex in excluded_lower):
                        total_cpu += proc.info["cpu_percent"] or 0.0
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return total_cpu >= _COTENANT_CPU_THRESHOLD
        except Exception:
            return False

    async def record(self, snapshot: dict[str, Any]) -> None:
        """Store numeric metrics for baseline training (gated EMA + SQLite audit)."""
        metrics: dict[str, float] = {}
        if "cpu" in snapshot:
            metrics["cpu"] = float(snapshot["cpu"])
        if "mem" in snapshot:
            metrics["ram"] = float(snapshot["mem"])
        if snapshot.get("disk_alerts"):
            max_disk = 0.0
            for alert in snapshot["disk_alerts"]:
                try:
                    pct = float(alert.split()[-1].rstrip("%"))
                    max_disk = max(max_disk, pct)
                except (ValueError, IndexError):
                    continue
            if max_disk:
                metrics["disk"] = max_disk
        if metrics:
            # Audit log: raw samples (fire-and-forget, never used for stats directly)
            await store_baseline_metrics(metrics)
            # Co-tenant check: DEVIN/Windsurf active → suppress baseline re-bootstrap
            cotenant = self._cotenant_active()
            self._last_cotenant = cotenant
            # Gated EMA: update only if sample is within safe Z-band
            await self._ema.record_snapshot(metrics, cotenant_active=cotenant)

    def is_cotenant_active(self) -> bool:
        """Return the last co-tenant check result (cached from record())."""
        return self._last_cotenant

    def get_stats(self, metric: str, window_days: int = 7) -> tuple[float | None, float | None]:
        """Return (μ, σ) from gated EMA."""
        return self._ema.get_stats(metric)


class SnapshotDiffer:
    """Compare two system snapshots and flag structural differences."""

    async def diff(
        self,
        prev: dict[str, Any] | None,
        curr: dict[str, Any],
    ) -> list[AnomalyEvent]:
        """Return list of anomaly events describing what changed."""
        if prev is None:
            return []  # First snapshot — no diff possible

        events: list[AnomalyEvent] = []
        events += await self._diff_connections(prev, curr)
        events += self._diff_processes(prev, curr)
        events += await self._diff_suspicious_procs(prev, curr)
        return events

    async def _diff_connections(self, prev: dict[str, Any], curr: dict[str, Any]) -> list[AnomalyEvent]:
        """Detect new external connections, filtered by 3-layer whitelist."""
        prev_conns = self._extract_conns(prev.get("suspicious_net", []))
        curr_conns = self._extract_conns(curr.get("suspicious_net", []))
        new_conns = curr_conns - prev_conns
        seen_ips: set[str] = set()
        events: list[AnomalyEvent] = []
        for ip, proc_name, port, pid in new_conns:
            if ip in seen_ips:
                continue
            # Shared filter chain (net_noise_filter): CDN whitelist, self-whitelist,
            # Phase 7 behavioral allowlist, Phase 8 learned baseline (fail-open),
            # Phase 9 intel whitelist — same chain the threat hunter uses.
            # PID is passed so is_self_process can verify via path+lineage+hash
            # instead of name-only (defense against python.exe spoofing).
            reason = await suppression_reason(proc_name, ip, port, pid)
            if reason:
                logger.debug(
                    "[SnapshotDiffer] Suppressing benign conn (%s): %s -> %s:%d",
                    reason,
                    proc_name,
                    ip,
                    port,
                )
                continue
            seen_ips.add(ip)
            events.append(
                AnomalyEvent(
                    category="net",
                    metric="new_external_ip",
                    current=0.0,
                    reason=f"חיבור חדש לכתובת חיצונית: {ip}",
                    severity="warn",
                    details={"ip": ip, "proc_name": proc_name, "remote_port": port, "pid": pid},
                )
            )
        return events

    @staticmethod
    def _is_safe_noise(name: str, cpu: float) -> bool:
        """True if `name` is a routine Windows/dev process under its CPU ceiling."""
        ceiling = _PYTHON_CPU_CEILING if name == "python.exe" else _SAFE_PROCESS_CPU_CEILING
        return name in SAFE_PROCESSES and cpu < ceiling

    def _diff_processes(self, prev: dict[str, Any], curr: dict[str, Any]) -> list[AnomalyEvent]:
        """Detect new heavy processes and CPU spikes in existing ones."""
        prev_procs = {int(p["pid"]): p for p in prev.get("top_procs", []) if p.get("pid") and str(p["pid"]).isdigit()}
        curr_procs = {int(p["pid"]): p for p in curr.get("top_procs", []) if p.get("pid") and str(p["pid"]).isdigit()}
        events: list[AnomalyEvent] = []
        for pid, info in curr_procs.items():
            if pid not in prev_procs:
                cpu = info.get("cpu_percent", 0.0)
                name = (info.get("name") or "").lower()
                # Suppress routine Windows tasks unless spiking extremely high
                if self._is_safe_noise(name, cpu):
                    logger.debug(
                        "[SnapshotDiffer] Suppressing safe process noise: %s @ %.1f%% CPU",
                        name,
                        cpu,
                    )
                    continue
                if cpu > 15.0:
                    events.append(
                        AnomalyEvent(
                            category="proc",
                            metric="new_heavy_process",
                            current=cpu,
                            reason=f"תהליך חדש עם עומס גבוה: {info.get('name', '?')} (PID {pid}) — {cpu:.1f}% CPU",
                            severity="warn" if cpu < 40.0 else "critical",
                            details={
                                "pid": pid,
                                "name": info.get("name", "?"),
                                "cpu": cpu,
                            },
                        )
                    )
            else:
                # Existing process that jumped significantly
                old_cpu = prev_procs[pid].get("cpu_percent", 0.0)
                new_cpu = info.get("cpu_percent", 0.0)
                name = (info.get("name") or "").lower()
                if self._is_safe_noise(name, new_cpu):
                    logger.debug(
                        "[SnapshotDiffer] Suppressing safe process spike: %s @ %.1f%% CPU",
                        name,
                        new_cpu,
                    )
                    continue
                if old_cpu > 0 and new_cpu / old_cpu >= 3.0 and new_cpu > 20.0:
                    events.append(
                        AnomalyEvent(
                            category="proc",
                            metric="process_cpu_spike",
                            current=new_cpu,
                            reason=f"קפיצת CPU בתהליך {info.get('name', '?')}: {old_cpu:.1f}% → {new_cpu:.1f}%",
                            severity="warn",
                            details={
                                "pid": pid,
                                "name": info.get("name", "?"),
                                "old_cpu": old_cpu,
                                "new_cpu": new_cpu,
                            },
                        )
                    )
        return events

    async def _diff_suspicious_procs(self, prev: dict[str, Any], curr: dict[str, Any]) -> list[AnomalyEvent]:
        """Detect TTPs in suspicious process command lines (PowerShell, WMIC, etc.).

        When TTP score >= 85, auto-queues a kill_process action for FSM approval.

        Feature flag (SYSMON_ENRICHED_ANALYSIS_ENABLED):
          - False (default): uses analyze_cmdline (regex engine, original path)
          - True: uses analyze_process_event (Sysmon-enriched wrapper with 4
            new checks: T1059.005, T1027, T1548.002, T1036). The psutil-derived
            proc dict is converted to a ProcessEvent with source="psutil" so
            Sysmon-only fields are None and the enriched checks skip gracefully.

        Dry-run mode (SYSMON_KILL_QUEUE_DRY_RUN, default True):
          - When True, queue_kill_for_ttp is NOT called. Instead, what would
            have been queued is shadow-logged at WARNING. This lets the new
            checks run against live traffic for false-positive tuning without
            risking auto-kill.
        """
        from config import SYSMON_ENRICHED_ANALYSIS_ENABLED, SYSMON_KILL_QUEUE_DRY_RUN

        if SYSMON_ENRICHED_ANALYSIS_ENABLED:
            from services.process_analyzer import analyze_process_event
            from services.process_event import ProcessEvent
        else:
            from services.cmdline_analyzer import analyze_cmdline

        prev_pids = {p.get("pid") for p in prev.get("suspicious_procs", [])}
        curr_procs = curr.get("suspicious_procs", [])
        events: list[AnomalyEvent] = []

        for proc in curr_procs:
            pid = proc.get("pid", 0)
            cmdline = proc.get("cmdline", "")
            if pid in prev_pids or not cmdline:
                continue

            if SYSMON_ENRICHED_ANALYSIS_ENABLED:
                # Build ProcessEvent from psutil proc dict — Sysmon fields
                # are None (source="psutil"), so enriched checks skip and
                # only analyze_cmdline + parent_anomaly (if parent_image
                # were present) would fire. In the psutil path, parent_image
                # is not available, so effectively only the regex engine
                # runs — same as the non-flagged path, but through the
                # wrapper so the code path is exercised.
                pe = ProcessEvent(
                    pid=pid,
                    name=proc.get("name", ""),
                    cmdline=cmdline,
                    source="psutil",
                )
                matches = analyze_process_event(pe)
            else:
                matches = analyze_cmdline(cmdline)

            for m in matches:
                if m.suggested_score < 50:
                    continue
                severity = "critical" if m.suggested_score >= 85 else "warn"

                kill_queued = await self._maybe_queue_kill(
                    m, pid, proc.get("name", "?"), cmdline, SYSMON_KILL_QUEUE_DRY_RUN
                )

                details = {
                    "pid": pid,
                    "name": proc.get("name", "?"),
                    "cmdline": cmdline[:200],
                    "technique_id": m.technique_id,
                    "ttp_score": m.suggested_score,
                    "signals": m.signals,
                }
                if kill_queued:
                    details["kill_process_queued"] = kill_queued

                events.append(
                    AnomalyEvent(
                        category="proc",
                        metric="ttp_detected",
                        current=float(m.suggested_score),
                        reason=f"MITRE {m.technique_id} ({m.name}): {'; '.join(m.signals[:2])}",
                        severity=severity,
                        details=details,
                    )
                )
        return events

    @staticmethod
    async def _maybe_queue_kill(
        match: Any, pid: int, proc_name: str, cmdline: str, dry_run: bool
    ) -> int:
        """Queue kill_process for score>=85, or shadow-log in dry-run. Returns row ID."""
        if match.suggested_score < 85:
            return 0
        if dry_run:
            logger.warning(
                "[SnapshotDiffer] DRY-RUN: would queue kill for PID %d (TTP %s score=%d)",
                pid, match.technique_id, match.suggested_score,
            )
            return 0
        try:
            from services.pending_actions import queue_kill_for_ttp

            row_id = await queue_kill_for_ttp(
                pid=pid, score=match.suggested_score, technique_id=match.technique_id,
                signals=match.signals, proc_name=proc_name, cmdline=cmdline,
            )
            logger.warning("[SnapshotDiffer] AUTO-QUEUE kill #%d PID %d (score=%d)", row_id, pid, match.suggested_score)
            return row_id
        except Exception as exc:
            logger.error("[SnapshotDiffer] Failed to queue kill for PID %d: %s", pid, exc)
            return 0

    @staticmethod
    def _extract_ips(suspicious_net: list[str]) -> set[str]:
        """Extract IP addresses from suspicious_net strings."""
        ips: set[str] = set()
        for line in suspicious_net:
            ip = extract_ip_from_conn_string(line)
            if ip:
                ips.add(ip)
        return ips

    @staticmethod
    def _extract_conns(suspicious_net: list[str]) -> set[tuple[str, str, int, int | None]]:
        """Extract (ip, proc_name, remote_port, pid) tuples from suspicious_net strings.

        Line format: '[ip]:port (org / AS123) (proc_name:pid)'.
        The proc_name:pid is always the LAST parenthesized group.
        PID is retained for self-process verification in suppression_reason.
        """
        conns: set[tuple[str, str, int, int | None]] = set()
        for line in suspicious_net:
            conn = parse_conn_line(line)
            if conn is not None:
                ip, proc_name, port, pid = conn
                conns.add((ip, proc_name, port, pid))
        return conns

    @staticmethod
    def _is_whitelisted_ip(ip: str) -> bool:
        """Return True if IP belongs to a known CDN / cloud provider."""
        return is_cdn_whitelisted_ip(ip)


# ── Re-exports for backward compatibility (lazy to avoid circular import) ──
def __getattr__(name: str):  # noqa: D401
    if name in ("MonitorAnalyzer", "SustainedZScoreDetector"):
        from services.monitor_analyzer_orchestrator import (
            MonitorAnalyzer as _MA,
        )
        from services.monitor_analyzer_orchestrator import (
            SustainedZScoreDetector as _SZSD,
        )

        return {"MonitorAnalyzer": _MA, "SustainedZScoreDetector": _SZSD}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
