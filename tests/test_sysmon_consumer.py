# tests/test_sysmon_consumer.py
"""Tests for SysmonConsumer — the consumer logic (not EvtSubscribe itself).

EvtSubscribe requires admin + running Sysmon, so we test the consumer
loop in isolation by feeding mock XML strings directly into the event
queue. This validates:
  - XML → ProcessEvent → analyze_process_event → alert pipeline
  - Score threshold filtering (only >= 85 alerts)
  - Malformed XML doesn't crash the consumer
  - Graceful shutdown via stop()
  - Stats tracking
"""

from __future__ import annotations

import asyncio

import pytest

from services.sysmon_consumer import _AUTO_BLOCK_SCORE, SysmonConsumer


def _make_event_xml(
    pid: int = 1234,
    cmdline: str = "test.exe",
    image: str = "C:\\test.exe",
    parent_image: str = "",
    integrity_level: str = "",
    sha256: str = "",
) -> str:
    """Build a minimal Sysmon Event 1 XML for testing."""
    parts = [
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>",
        "<System><EventID>1</EventID></System>",
        "<EventData>",
        f"<Data Name='ProcessId'>{pid}</Data>",
        f"<Data Name='Image'>{image}</Data>",
        f"<Data Name='CommandLine'>{cmdline}</Data>",
    ]
    if parent_image:
        parts.append(f"<Data Name='ParentImage'>{parent_image}</Data>")
        parts.append("<Data Name='ParentProcessId'>1000</Data>")
    if integrity_level:
        parts.append(f"<Data Name='IntegrityLevel'>{integrity_level}</Data>")
    if sha256:
        parts.append(f"<Data Name='Hashes'>SHA256={sha256}</Data>")
    parts.append("</EventData></Event>")
    return "".join(parts)


# ── Consumer pipeline tests ──


class TestConsumerPipeline:
    """Feed mock XML into the consumer and verify alert output."""

    async def _run_consumer_until_alerts(self, xmls: list[str], timeout: float = 2.0):
        """Helper: start consumer, feed XMLs, collect alerts, stop."""
        alert_queue: asyncio.Queue[dict] = asyncio.Queue()
        consumer = SysmonConsumer(alert_queue)

        # We can't call start() (it needs EvtSubscribe + admin), so we
        # manually set up the queue and feed it
        consumer._loop = asyncio.get_running_loop()
        consumer._event_queue = asyncio.Queue(maxsize=100)
        consumer._stop_event.clear()

        # Start consumer loop
        consumer._consumer_task = asyncio.create_task(consumer._consumer_loop())

        # Feed XMLs
        for xml in xmls:
            await consumer._event_queue.put((0.0, xml))

        # Wait for processing
        await asyncio.sleep(0.3)

        # Stop
        await consumer.stop()

        # Collect alerts
        alerts = []
        while not alert_queue.empty():
            alerts.append(alert_queue.get_nowait())
        return alerts, consumer

    async def test_clean_process_no_alert(self):
        xml = _make_event_xml(cmdline="notepad.exe", image="C:\\Windows\\notepad.exe")
        alerts, consumer = await self._run_consumer_until_alerts([xml])
        assert len(alerts) == 0
        assert consumer.stats["events_parsed"] == 1
        assert consumer.stats["events_alerted"] == 0

    async def test_high_score_cmdline_triggers_alert(self):
        """PowerShell encoded command (score 90) → alert."""
        xml = _make_event_xml(
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        alerts, consumer = await self._run_consumer_until_alerts([xml])
        assert len(alerts) == 1
        assert alerts[0]["pid"] == 1234
        assert alerts[0]["source"] == "sysmon"
        techniques = [m["technique_id"] for m in alerts[0]["matches"]]
        assert "T1059.001" in techniques

    async def test_parent_anomaly_does_not_alert_below_threshold(self):
        """Parent anomaly scores 75 — below 85 threshold, no alert."""
        xml = _make_event_xml(
            cmdline="cmd /c echo test",
            image="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Program Files\\Microsoft Office\\winword.exe",
        )
        alerts, consumer = await self._run_consumer_until_alerts([xml])
        # T1059.005 scores 75 — below 85, no alert
        assert len(alerts) == 0

    async def test_malformed_xml_does_not_crash_consumer(self):
        """Garbage XML → consumer skips, continues processing next events."""
        garbage = "this is not xml"
        good_xml = _make_event_xml(
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        alerts, consumer = await self._run_consumer_until_alerts([garbage, good_xml])
        # Garbage skipped, good event processed
        assert consumer.stats["events_parsed"] == 1
        assert len(alerts) == 1

    async def test_multiple_events_processed(self):
        """Consumer handles a batch of events."""
        xmls = [
            _make_event_xml(pid=i, cmdline=f"proc_{i}.exe", image=f"C:\\proc_{i}.exe")
            for i in range(10)
        ]
        alerts, consumer = await self._run_consumer_until_alerts(xmls)
        assert consumer.stats["events_parsed"] == 10
        assert len(alerts) == 0  # all clean

    async def test_alert_contains_full_event_context(self):
        """Alert should include parent_image, sha256, integrity_level."""
        xml = _make_event_xml(
            cmdline="powershell -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            parent_image="C:\\Program Files\\Microsoft Office\\winword.exe",
            integrity_level="High",
            sha256="a" * 64,
        )
        alerts, _ = await self._run_consumer_until_alerts([xml])
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert["parent_image"] is not None
        assert "winword.exe" in alert["parent_image"]
        assert alert["integrity_level"] == "High"
        assert alert["sha256"] == "a" * 64


# ── Stats tracking ──


class TestConsumerStats:
    async def test_stats_zero_before_any_events(self):
        alert_queue: asyncio.Queue = asyncio.Queue()
        consumer = SysmonConsumer(alert_queue)
        assert consumer.stats == {
            "events_received": 0,
            "events_parsed": 0,
            "events_alerted": 0,
        }
