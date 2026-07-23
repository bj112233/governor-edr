# tests/test_monitor_integration.py
"""Integration smoke test for the full MonitorAnalyzer pipeline."""

import asyncio

from services.monitor_analyzer import MonitorAnalyzer


def _run(coro):
    return asyncio.run(coro)


def test_full_pipeline_smoke():
    """Verify the analyzer pipeline runs end-to-end without crashing."""
    analyzer = MonitorAnalyzer()

    snapshot = {
        "cpu": 80.0,
        "mem": 60.0,
        "suspicious_net": ["1.2.3.4:443 (chrome:1234)"],
        "top_procs": [{"pid": 1, "name": "chrome", "cpu_percent": 5.0}],
        "disk_alerts": [],
    }

    events, threats = _run(analyzer.analyze(snapshot))

    assert isinstance(events, list)
    assert isinstance(threats, list)
