# tests/test_threat_classifier.py
"""Unit tests for threat_classifier heuristics."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from services.threat_classifier import (
    ConnectionAnalyzer,
    PortClassifier,
    ThreatClassifier,
)

# ── PortClassifier ──


def test_port_standard_web():
    pc = PortClassifier()
    classification, svc = pc.classify(443)
    assert classification == "standard"
    assert svc == "HTTPS"


def test_port_known_service():
    pc = PortClassifier()
    classification, svc = pc.classify(22)
    assert classification == "known"
    assert svc == "SSH"


def test_port_unknown_suspicious():
    pc = PortClassifier()
    classification, svc = pc.classify(9999)
    assert classification == "unknown"
    assert svc is None


def test_port_ephemeral_browser_ok():
    pc = PortClassifier()
    classification, _ = pc.classify(50000)
    assert classification == "ephemeral"


def test_analyze_listening_flags_unknown_port():
    pc = PortClassifier()
    ports = [{"port": 9999, "process": "mystery.exe", "pid": 1234}]
    assessments = pc.analyze_listening(ports)
    assert len(assessments) == 1
    assert assessments[0].status == "suspicious"


# ── ConnectionAnalyzer ──


def _mock_behavioral(ca, conns):
    """Patch behavioral filter to pass connections through unchanged."""
    return patch.object(ca.behavioral, "filter_and_classify", return_value=(conns, []))


@pytest.mark.asyncio
async def test_beaconing_multiple_pids_same_ip():
    ca = ConnectionAnalyzer()
    conns = [
        {"pid": 1, "proc_name": "a.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
        {"pid": 2, "proc_name": "b.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
        {"pid": 3, "proc_name": "c.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
    ]
    with _mock_behavioral(ca, conns):
        assessments = await ca.analyze(conns)
    assert any(a.status == "suspicious" and "3" in a.reason for a in assessments)


@pytest.mark.asyncio
async def test_nonstandard_port_nonbrowser():
    ca = ConnectionAnalyzer()
    conns = [
        {
            "pid": 1,
            "proc_name": "backdoor.exe",
            "raddr_ip": "5.6.7.8",
            "raddr_port": 1337,
        }
    ]
    with _mock_behavioral(ca, conns):
        assessments = await ca.analyze(conns)
    assert any(a.status == "suspicious" for a in assessments)


@pytest.mark.asyncio
async def test_flagged_ip_prefix():
    ca = ConnectionAnalyzer()
    conns = [
        {
            "pid": 1,
            "proc_name": "tor.exe",
            "raddr_ip": "185.220.101.50",
            "raddr_port": 443,
        }
    ]
    with _mock_behavioral(ca, conns):
        assessments = await ca.analyze(conns)
    assert any(a.status == "malicious" for a in assessments)


@pytest.mark.asyncio
async def test_learned_baseline_suppresses_nonstandard_port():
    """Known (proc, ip, port) should suppress non-standard port alerts."""
    ca = ConnectionAnalyzer()
    conns = [
        {
            "pid": 1,
            "proc_name": "backdoor.exe",
            "raddr_ip": "5.6.7.8",
            "raddr_port": 1337,
        }
    ]
    with (
        _mock_behavioral(ca, conns),
        patch(
            "services.threat_analyzers.is_known_combo",
            new_callable=AsyncMock,
            return_value=True,
        ),
    ):
        assessments = await ca.analyze(conns)
    # Should be suppressed (no non-standard-port alert)
    nonstandard = [a for a in assessments if "פורט לא סטנדרטי" in a.reason]
    assert nonstandard == []


@pytest.mark.asyncio
async def test_flagged_ip_never_suppressed_by_baseline():
    """Flagged IPs are hard IOCs and should never be baseline-suppressed."""
    ca = ConnectionAnalyzer()
    conns = [
        {
            "pid": 1,
            "proc_name": "tor.exe",
            "raddr_ip": "185.220.101.50",
            "raddr_port": 443,
        }
    ]
    with (
        _mock_behavioral(ca, conns),
        patch(
            "services.threat_analyzers.is_known_combo",
            new_callable=AsyncMock,
            return_value=True,
        ),
    ):
        assessments = await ca.analyze(conns)
    assert any(a.status == "malicious" for a in assessments)


# ── ThreatClassifier Facade ──


@pytest.mark.asyncio
async def test_classify_combined_ports_and_connections():
    tc = ThreatClassifier()
    ports = [{"port": 9999, "process": "evil.exe", "pid": 666}]
    conns = [
        {"pid": 1, "proc_name": "a.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
        {"pid": 2, "proc_name": "b.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
        {"pid": 3, "proc_name": "c.exe", "raddr_ip": "1.2.3.4", "raddr_port": 443},
    ]
    with patch(
        "services.threat_analyzers.is_known_combo",
        new_callable=AsyncMock,
        return_value=False,
    ):
        results = await tc.classify(listening_ports=ports, connections=conns)
    statuses = {r.status for r in results}
    assert "suspicious" in statuses


# ── Heuristic Summary ──


def test_heuristic_summary_keyword_match():
    tc = ThreatClassifier()
    result = tc._heuristic_summary("tor beacon c2 malware")
    assert result.status == "suspicious"


def test_heuristic_summary_no_indicators():
    tc = ThreatClassifier()
    result = tc._heuristic_summary("normal traffic http")
    assert result.status == "clean"
