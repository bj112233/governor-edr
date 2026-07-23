# services/threat_classifier.py
"""Network threat intelligence — port classification, connection graph, LLM summary.

All functions return structured assessments. LLM calls enforce strict JSON
schema; on parse failure, heuristic classification is used as fallback.

Analyzers (PortClassifier, ConnectionAnalyzer) extracted to threat_analyzers.py.
This module keeps the ThreatClassifier facade + LLM summary logic.
"""

import json
import logging
from typing import Optional

from services.intel_enricher import enrich_ip
from services.threat_analyzers import (
    ConnectionAnalyzer,
    PortClassifier,
    ThreatAssessment,
)

logger = logging.getLogger(__name__)


class ThreatClassifier:
    """Facade — orchestrates port + connection analysis + optional LLM summary."""

    def __init__(self) -> None:
        self.port_classifier = PortClassifier()
        self.conn_analyzer = ConnectionAnalyzer()

    async def classify(
        self,
        listening_ports: list[dict] | None = None,
        connections: list[dict] | None = None,
    ) -> list[ThreatAssessment]:
        """Run heuristic classification on network data."""
        results: list[ThreatAssessment] = []
        if listening_ports:
            results.extend(self.port_classifier.analyze_listening(listening_ports))
        if connections:
            results.extend(await self.conn_analyzer.analyze(connections))
        return results

    async def llm_threat_summary(
        self,
        connection_summary: str,
        connections: list[dict] | None = None,
        timeout: float = 10.0,
    ) -> ThreatAssessment:
        """Send connection graph to LLM for structured threat assessment.

        Enforces strict JSON schema. On parse failure, returns heuristic fallback.
        """
        enrich_block = ""
        if connections:
            unique_ips = set()
            for c in connections:
                rip = c.get("raddr_ip", "")
                # M4: Only skip loopback — LAN IPs are included for enrichment
                # (lateral movement detection: svchost.exe → 192.168.1.50:4444)
                if rip and not rip.startswith(("127.", "::1")):
                    unique_ips.add(rip)
            enrich_lines = []
            for ip in sorted(unique_ips)[:20]:
                info = await enrich_ip(ip)
                if info:
                    parts = [f"{k}={v}" for k, v in info.items()]
                    enrich_lines.append(f"{ip}: " + ", ".join(parts))
            enrich_block = "\n".join(enrich_lines) or "No enrichment data available."

        prompt = (
            "You are a network threat analyst. Analyze ONLY the connection data below.\n"
            "Rules:\n"
            "1. Evaluate each connection on its own merits (IP reputation, port, process, ASN).\n"
            "2. CPU or RAM usage on the local host is IRRELEVANT to network threat assessment.\n"
            "3. Known cloud provider IPs (Azure, AWS, Google, Cloudflare) are benign unless paired with suspicious ports.\n"
            "IP enrichment (Geo/ASN):\n"
            f"{enrich_block}\n\n"
            "Return ONLY valid JSON in this exact schema — no markdown, no explanations, "
            "no text outside the JSON object:\n"
            '{"status": "clean|suspicious|malicious", "reason": "short explanation"}\n\n'
            "Connection data:\n"
            f"{connection_summary[:2000]}"
        )
        try:
            from services.llm_bridge import LLMBridge

            bridge = LLMBridge.get_instance()
            raw = await bridge.complete(
                system_prompt=(
                    "You are a terse SOC analyst. Reply with JSON only. "
                    "CRITICAL: CPU or RAM spikes on the local host are NEVER evidence of network threats. "
                    "Evaluate each connection purely on its own IP, port, process, and ASN. "
                    "Do NOT infer network risk from system resource usage."
                ),
                user_input=prompt,
                temperature=0.0,
                max_tokens=120,
                timeout=timeout,
            )
            text = raw.strip()
            if text.startswith("```json"):
                text = text[7:]
            if text.startswith("```"):
                text = text[3:]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
            parsed = json.loads(text)
            status = parsed.get("status", "unknown")
            reason = parsed.get("reason", "")
            if status not in ("clean", "suspicious", "malicious"):
                status = "unknown"
            return ThreatAssessment(status=status, reason=reason)
        except Exception as exc:
            logger.debug("[ThreatClassifier] LLM summary failed, using heuristic: %s", exc)
            return self._heuristic_summary(connection_summary)

    @staticmethod
    def _heuristic_summary(summary: str) -> ThreatAssessment:
        """Fallback when LLM is unreachable or returns garbage."""
        lower = summary.lower()
        suspicious_kws = ["tor", "ransomware", "malware", "exploit", "c2", "beacon"]
        if any(kw in lower for kw in suspicious_kws):
            return ThreatAssessment(status="suspicious", reason="heuristic: keyword match")
        return ThreatAssessment(status="clean", reason="heuristic: no threat indicators")
