"""Threat analyzers — port classification + connection graph analysis.

Extracted from threat_classifier.py (SRP). Heuristic-only analyzers that
don't require LLM calls. ThreatClassifier (facade) stays in threat_classifier.py.
"""

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from services.behavioral_filter import BehavioralFilter
from services.net_baseline import is_intel_whitelisted, is_known_combo

logger = logging.getLogger(__name__)

# ── Known service ports (IANA-registered + common dev/telemetry) ──
_KNOWN_SERVICES: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-Submission",
    853: "DNS-over-TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    4317: "OTLP-gRPC",
    4318: "OTLP-HTTP",
    5228: "FCM-Push",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB",
}

_BROWSER_PROCS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "Code.exe"}
_STANDARD_WEB_PORTS = {80, 443, 8080, 8443}
_FLAGGED_IP_PREFIXES = {"185.220.101.", "199.249.230."}


@dataclass(frozen=True)
class ThreatAssessment:
    status: str  # 'clean' | 'suspicious' | 'malicious'
    reason: str = ""
    details: dict = field(default_factory=dict)


class PortClassifier:
    """Classify listening ports into known services or flag unknowns."""

    def __init__(self, known_services: dict[int, str] | None = None) -> None:
        self.known = known_services or _KNOWN_SERVICES

    def classify(self, port: int) -> tuple[str, str | None]:
        """Return (classification, service_name)."""
        if port in _STANDARD_WEB_PORTS:
            return ("standard", self.known.get(port))
        if port in self.known:
            return ("known", self.known[port])
        if port >= 49152:
            return ("ephemeral", None)
        return ("unknown", None)

    def analyze_listening(self, ports_data: list[dict]) -> list[ThreatAssessment]:
        """Analyze a list of listening port dicts."""
        assessments: list[ThreatAssessment] = []
        for p in ports_data:
            port = int(p.get("port", 0))
            proc = p.get("process", "unknown")
            classification, svc = self.classify(port)
            if classification == "unknown" and port > 1024:
                assessments.append(
                    ThreatAssessment(
                        status="suspicious",
                        reason=f"פורט לא ידוע פתוח: {port} ({proc}, PID {p.get('pid', '?')})",
                        details={"port": port, "process": proc, "pid": p.get("pid")},
                    )
                )
            elif classification == "ephemeral" and proc.lower() not in _BROWSER_PROCS:
                assessments.append(
                    ThreatAssessment(
                        status="info",
                        reason=f"פורט ephemeral פתוח: {port} ({proc})",
                        details={"port": port, "process": proc},
                    )
                )
        return assessments


class ConnectionAnalyzer:
    """Analyze active connections for beaconing, non-standard ports, flagged IPs."""

    def __init__(self) -> None:
        self.behavioral = BehavioralFilter()
        self._port_classifier = PortClassifier()

    async def analyze(self, connections: list[dict]) -> list[ThreatAssessment]:
        """Analyze connection dicts and return threat assessments."""
        assessments: list[ThreatAssessment] = []

        aggregated, behavioral_assessments = self.behavioral.filter_and_classify(connections)
        for ba in behavioral_assessments:
            assessments.append(
                ThreatAssessment(
                    status=ba.status,
                    reason=ba.reason,
                    details=ba.details,
                )
            )

        ip_to_procs: dict[str, set[tuple]] = defaultdict(set)
        for c in aggregated:
            r_ip = c.get("raddr_ip", "")
            if r_ip:
                ip_to_procs[r_ip].add((c.get("pid", 0), c.get("proc_name", "unknown"), c.get("raddr_port", 0)))

        for r_ip, procs in ip_to_procs.items():
            unique_pids = {pid for pid, _, _ in procs}
            if len(unique_pids) >= 3:
                proc_list = ", ".join(sorted({p for _, p, _ in procs}))[:80]
                assessments.append(
                    ThreatAssessment(
                        status="suspicious",
                        reason=f"מספר תהליכים ({len(unique_pids)}) מתחברים לאותה כתובת: {r_ip}",
                        details={"remote_ip": r_ip, "pids": list(unique_pids), "procs": proc_list},
                    )
                )

        for c in connections:
            proc = c.get("proc_name", "unknown")
            r_port = c.get("raddr_port", 0)
            if proc.lower() in _BROWSER_PROCS:
                continue
            classification, _svc = self._port_classifier.classify(r_port)
            if classification in ("standard", "known", "ephemeral"):
                continue
            try:
                if await is_known_combo(proc, c.get("raddr_ip", ""), r_port):
                    logger.debug(
                        "[ConnectionAnalyzer] Suppressing learned combo: %s -> %s:%d",
                        proc,
                        c.get("raddr_ip", ""),
                        r_port,
                    )
                    continue
            except Exception:
                pass
            try:
                if await is_intel_whitelisted(c.get("raddr_ip", "")):
                    logger.debug("[ConnectionAnalyzer] Suppressing intel-whitelisted IP: %s", c.get("raddr_ip", ""))
                    continue
            except Exception:
                pass
            assessments.append(
                ThreatAssessment(
                    status="suspicious",
                    reason=f"תהליך {proc} מתחבר לפורט לא סטנדרטי {r_port} → {c.get('raddr_ip', '?')}",
                    details={"proc": proc, "remote_port": r_port, "remote_ip": c.get("raddr_ip", "")},
                )
            )

        for c in connections:
            r_ip = c.get("raddr_ip", "")
            for prefix in _FLAGGED_IP_PREFIXES:
                if r_ip.startswith(prefix):
                    assessments.append(
                        ThreatAssessment(
                            status="malicious",
                            reason=f"חיבור לכתובת ברשימת חשודים: {r_ip} ({c.get('proc_name', '?')})",
                            details={"remote_ip": r_ip, "proc": c.get("proc_name", "")},
                        )
                    )
                    break

        return assessments
