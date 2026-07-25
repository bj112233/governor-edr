# services/sysmon_consumer.py
"""Sysmon Event 1 consumer — real-time process creation telemetry.

Architecture (validated in spike — see docs/ARCHITECTURE.md Appendix D):

  EvtSubscribe (push, Windows internal thread)
       ↓ callback
  asyncio.run_coroutine_threadsafe → asyncio.Queue
       ↓ async consumer
  parse_event1_xml → ProcessEvent
       ↓
  analyze_process_event → list[CmdlineMatch]
       ↓ score >= 85
  alert_queue (fed to monitor_analyzer / threat_hunter)

The callback runs on a Windows internal thread (not the asyncio event
loop). The bridge is `run_coroutine_threadsafe` — validated at 100%
delivery rate (0% loss) in the spike.

Robustness:
  - XML parse failures return None (never raise) — see sysmon_xml.py
  - analyze_process_event never throws on missing fields
  - The consumer loop catches all exceptions per-event so one bad event
    doesn't kill the subscription
  - Graceful shutdown via stop() sets the threading.Event

Permissions: requires admin OR Event Log Readers group to read the
Sysmon Event Log channel.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

import win32evtlog

from services.process_analyzer import analyze_process_event
from services.process_event import ProcessEvent
from services.sysmon_xml import parse_event1_xml

logger = logging.getLogger(__name__)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVENT_1_QUERY = "Event/System/EventID=1"
_QUEUE_MAXSIZE = 10000  # bounded — see ARCHITECTURE.md SLA discussion
_AUTO_BLOCK_SCORE = 85  # matches cmdline_analyzer threshold
_EVT_SUBSCRIBE_ACTION_DELIVER = win32evtlog.EvtSubscribeActionDeliver


class SysmonConsumer:
    """EvtSubscribe consumer for Sysmon Event 1 (Process Create).

    Lifecycle:
        consumer = SysmonConsumer(alert_queue)
        await consumer.start()  # starts subscription + async consumer
        ...
        await consumer.stop()   # graceful shutdown

    The alert_queue receives dicts with: pid, name, cmdline, matches,
    source="sysmon" — compatible with monitor_analyzer's AnomalyEvent
    pipeline.
    """

    def __init__(self, alert_queue: asyncio.Queue[dict[str, Any]]):
        self._alert_queue = alert_queue
        self._event_queue: asyncio.Queue[tuple[float, str] | None] | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event = threading.Event()
        self._subscription_handle: Any = None
        self._consumer_task: asyncio.Task[None] | None = None
        self._events_received = 0
        self._events_parsed = 0
        self._events_alerted = 0

    @property
    def stats(self) -> dict[str, int]:
        """Runtime stats for health check / monitoring."""
        return {
            "events_received": self._events_received,
            "events_parsed": self._events_parsed,
            "events_alerted": self._events_alerted,
        }

    def _callback(self, action: int, ctx: Any, event: Any) -> int:
        """EvtSubscribe callback — runs on Windows internal thread.

        Must not raise — exceptions here don't reach the main log handler.
        """
        if action != _EVT_SUBSCRIBE_ACTION_DELIVER:
            return 0
        self._events_received += 1
        try:
            xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            if self._loop and self._loop.is_running() and self._event_queue is not None:
                asyncio.run_coroutine_threadsafe(
                    self._event_queue.put((asyncio.get_event_loop().time(), xml_str)),
                    self._loop,
                )
        except Exception as e:
            # Critical: never let an exception escape the callback —
            # it would kill the subscription silently.
            logger.exception("[sysmon_consumer] callback error: %s", e)
        return 0

    async def _consumer_loop(self) -> None:
        """Async consumer — parse XML → ProcessEvent → analyze → alert."""
        assert self._event_queue is not None
        while not self._stop_event.is_set():
            try:
                item = await asyncio.wait_for(self._event_queue.get(), timeout=0.5)
            except TimeoutError:
                continue
            if item is None:  # poison pill (stop signal)
                break
            _, xml_str = item

            # 1. Parse XML → ProcessEvent (never raises, returns None on failure)
            event = parse_event1_xml(xml_str)
            if event is None:
                continue
            self._events_parsed += 1

            # 2. Analyze (never raises on missing fields)
            try:
                matches = analyze_process_event(event)
            except Exception as e:
                logger.exception("[sysmon_consumer] analyze error on PID %s: %s", event.pid, e)
                continue

            # 3. Alert on high-score matches
            high_score = [m for m in matches if m.suggested_score >= _AUTO_BLOCK_SCORE]
            if high_score:
                self._events_alerted += 1
                alert = {
                    "pid": event.pid,
                    "name": event.name,
                    "cmdline": event.cmdline,
                    "image": event.image,
                    "parent_image": event.parent_image,
                    "sha256": event.sha256,
                    "integrity_level": event.integrity_level,
                    "matches": [
                        {
                            "technique_id": m.technique_id,
                            "name": m.name,
                            "tactic": m.tactic,
                            "score": m.suggested_score,
                            "signals": m.signals,
                        }
                        for m in high_score
                    ],
                    "source": "sysmon",
                }
                try:
                    self._alert_queue.put_nowait(alert)
                except asyncio.QueueFull:
                    logger.warning("[sysmon_consumer] alert queue full — dropping alert for PID %s", event.pid)

    async def start(self) -> None:
        """Start the EvtSubscribe subscription + async consumer loop."""
        self._loop = asyncio.get_running_loop()
        self._event_queue = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._stop_event.clear()

        logger.info("[sysmon_consumer] starting EvtSubscribe on %s", SYSMON_CHANNEL)
        self._subscription_handle = win32evtlog.EvtSubscribe(
            SYSMON_CHANNEL,
            win32evtlog.EvtSubscribeToFutureEvents,
            Query=EVENT_1_QUERY,
            Callback=self._callback,
        )
        logger.info("[sysmon_consumer] subscription active")

        self._consumer_task = asyncio.create_task(self._consumer_loop())

    async def stop(self) -> None:
        """Graceful shutdown — signal stop, wait for consumer to drain."""
        self._stop_event.set()
        if self._event_queue is not None:
            # Poison pill to unblock the consumer if waiting on get()
            await self._event_queue.put(None)
        if self._consumer_task is not None:
            try:
                await asyncio.wait_for(self._consumer_task, timeout=5.0)
            except TimeoutError:
                self._consumer_task.cancel()
                logger.warning("[sysmon_consumer] consumer did not stop in 5s — cancelled")
        # Close the subscription handle to release Windows resources
        if self._subscription_handle is not None:
            try:
                win32evtlog.CloseEventLog(self._subscription_handle)
            except Exception:
                pass
        logger.info(
            "[sysmon_consumer] stopped — stats: %s",
            self.stats,
        )
