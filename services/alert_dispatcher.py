# services/alert_dispatcher.py
"""Smart alert dispatcher — cooldown, rate limit, severity gate, Hebrew formatting.

Emits enriched alerts to the Sentinel event bus for Telegram delivery.
IP extraction, enrichment, emit/persist logic extracted to
alert_dispatcher_helpers.py (SRP).
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Optional

from services.monitor_analyzer import AnomalyEvent
from services.telegram.headers import SEPARATOR
from services.threat_classifier import ThreatAssessment

logger = logging.getLogger(__name__)

# ── Eager import of intel_enricher (fail-loud, not silent) ──
try:
    from services.intel_enricher import enrich_ip, is_clean_enrichment
except Exception as _exc:
    logger.error("[AlertDispatch] Failed to import intel_enricher: %s", _exc)
    enrich_ip = None
    is_clean_enrichment = None

from services.alert_dispatcher_helpers import (  # noqa: E402
    ACTIVE_ALERTS_CACHE,
    _cache_alert_context,
    _emit_and_persist,
    _enrich_and_escalate,
    _extract_net_context,
)

# Severity levels that pass the gate (ordered)
_PASS_SEVERITIES = {"critical", "warn", "suspicious", "malicious"}


@dataclass
class DispatchResult:
    sent: int = 0
    suppressed_cooldown: int = 0
    suppressed_rate_limit: int = 0
    suppressed_severity: int = 0


class AlertDispatcher:
    """Routes alerts through severity gate, cooldown, and rate-limit filters."""

    def __init__(
        self,
        cooldown_seconds: float = 900.0,
        rate_limit_window: float = 600.0,
        max_alerts_per_window: int = 3,
    ) -> None:
        self.cooldown_seconds = cooldown_seconds
        self.rate_limit_window = rate_limit_window
        self.max_alerts_per_window = max_alerts_per_window
        self._cooldown_map: dict[str, float] = {}
        self._rate_map: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self,
        anomalies: list[AnomalyEvent],
        threats: list[ThreatAssessment] | None = None,
        snapshot: dict[str, Any] | None = None,
    ) -> DispatchResult:
        """Filter and emit alerts. Returns dispatch statistics."""
        result = DispatchResult()
        threats = threats or []
        now = time.time()
        unified = self._unify(algorithms=anomalies, threats=threats)

        for alert in unified:
            if not self._passes_severity_gate(alert, result):
                continue
            key = f"{alert['category']}:{alert['metric']}"
            cat = alert["category"]

            if not self._passes_cooldown(key, now, result):
                continue
            if not self._passes_rate_limit(cat, now, result):
                continue

            # Passed all gates
            self._rate_map[cat].append(now)
            self._cooldown_map[key] = now

            rem, ip = self._build_remediation(alert, cat)
            await _enrich_and_escalate(alert, ip, rem, enrich_ip, is_clean_enrichment)
            text = self._format_alert(alert, snapshot)
            if await _emit_and_persist(alert, text, rem, snapshot, key):
                result.sent += 1

        return result

    def _passes_severity_gate(self, alert: dict, result: DispatchResult) -> bool:
        if alert["severity"] not in _PASS_SEVERITIES:
            result.suppressed_severity += 1
            return False
        return True

    def _passes_cooldown(self, key: str, now: float, result: DispatchResult) -> bool:
        last = self._cooldown_map.get(key)
        if last is not None and (now - last) < self.cooldown_seconds:
            result.suppressed_cooldown += 1
            logger.debug(
                "[AlertDispatch] %s in cooldown (%.0fs left)",
                key,
                self.cooldown_seconds - (now - last),
            )
            return False
        return True

    def _passes_rate_limit(self, cat: str, now: float, result: DispatchResult) -> bool:
        window = self._rate_map[cat]
        while window and (now - window[0]) > self.rate_limit_window:
            window.popleft()
        if len(window) >= self.max_alerts_per_window:
            result.suppressed_rate_limit += 1
            logger.debug(
                "[AlertDispatch] %s rate-limited (%d/%d in %.0fs)",
                cat,
                len(window),
                self.max_alerts_per_window,
                self.rate_limit_window,
            )
            return False
        return True

    def _build_remediation(self, alert: dict, cat: str) -> tuple[dict, str | None]:
        """Build remediation dict with IP/PID/proc context for net alerts."""
        rem: dict = {"category": cat, "metric": alert["metric"]}
        ip: str | None = None

        # Extract details early — needed for auto-kill/auto-block ID caching
        details = alert.get("details") or {}

        if (
            alert.get("severity") in ("critical", "malicious", "suspicious", "warn")
            and cat == "net"
            and alert.get("type") in ("threat", "anomaly")
        ):
            ip, pid, proc, port = _extract_net_context(alert)
            if ip:
                # Pass auto-kill/auto-block IDs to cache so ignore handler can reject them
                auto_kill_id = int(details.get("kill_process_queued", 0)) if details.get("kill_process_queued") else 0
                auto_block_id = int(rem.get("auto_block_queued", 0)) if rem.get("auto_block_queued") else 0
                alert_id = _cache_alert_context(ip, port, proc, auto_kill_id=auto_kill_id, auto_block_id=auto_block_id)
                rem["actions"] = {
                    "alert_id": alert_id,
                    "ip": ip,
                    "pid": pid,
                    "proc_name": proc,
                }

        # Pass through kill_process_queued from TTP detection (proc alerts)
        if details.get("kill_process_queued"):
            rem["kill_process_queued"] = details["kill_process_queued"]
            rem["kill_pid"] = details.get("pid", 0)
            rem["kill_process_name"] = details.get("name", "?")
            rem["kill_ttp_score"] = details.get("ttp_score", 0)
            rem["kill_technique_id"] = details.get("technique_id", "")
            rem["kill_signals"] = details.get("signals", [])
            rem["kill_cmdline"] = details.get("cmdline", "")

        return rem, ip

    @staticmethod
    def _unify(
        algorithms: list[AnomalyEvent],
        threats: list[ThreatAssessment],
    ) -> list[dict[str, Any]]:
        """Normalize anomaly events and threat assessments into uniform dicts."""
        out: list[dict[str, Any]] = []
        for ev in algorithms:
            out.append(
                {
                    "type": "anomaly",
                    "category": ev.category,
                    "metric": ev.metric,
                    "severity": ev.severity,
                    "current": ev.current,
                    "baseline": ev.baseline,
                    "std": ev.std,
                    "reason": ev.reason,
                    "details": ev.details,
                }
            )
        for ta in threats:
            severity = ta.status if ta.status in _PASS_SEVERITIES else "info"
            out.append(
                {
                    "type": "threat",
                    "category": "net",
                    "metric": f"threat_{ta.status}",
                    "severity": severity,
                    "current": 0.0,
                    "baseline": None,
                    "std": None,
                    "reason": ta.reason,
                    "details": ta.details,
                }
            )
        return out

    @staticmethod
    def _format_alert(alert: dict[str, Any], snapshot: dict[str, Any] | None) -> str:
        """Build rich Hebrew alert text with contextual data."""
        from services.telegram.severity import severity_emoji

        severity_icon = severity_emoji(alert.get("severity"))
        lines = [
            f"{severity_icon} התראת Sentinel [{alert['severity'].upper()}]",
            SEPARATOR,
        ]

        if alert["type"] == "anomaly":
            cat = alert["category"]
            is_continuous = cat in ("cpu", "ram", "disk")
            lines.append(f"קטגוריה: {cat.upper()}")
            lines.append(f"מדד: {alert['metric']}")
            if is_continuous and alert.get("current") is not None:
                lines.append(f"ערך נוכחי: {alert['current']:.1f}%")
            if is_continuous and alert.get("baseline") is not None:
                lines.append(f"בסיס: μ={alert['baseline']:.1f}, σ={alert['std']:.1f}")
        else:
            lines.append("קטגוריה: רשת / איומים")
            lines.append(f"סטטוס: {alert['severity']}")

        lines.append("")
        lines.append(alert["reason"])
        return "\n".join(lines)
