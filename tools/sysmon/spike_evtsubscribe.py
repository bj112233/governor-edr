# tools/sysmon/spike_evtsubscribe.py
r"""Spike: EvtSubscribe consumer for Sysmon Event 1 (Process Create).

Measures:
1. Latency: time from process creation to callback fired
2. Burst loss: 100 processes spawned in <1s, count events received
3. asyncio bridge: consumer thread -> run_coroutine_threadsafe

Run as admin (Sysmon Event Log requires admin or Event Log Readers group).

Usage:
    .\.venv\Scripts\python.exe tools\sysmon\spike_evtsubscribe.py
"""

from __future__ import annotations

import asyncio
import os
import statistics
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

# Add project root to path so services._winutil is importable
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Bootstrap pywin32 DLLs (needed in venv)
import services._winutil  # noqa: F401, E402
import win32evtlog  # noqa: E402

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
EVENT_1_QUERY = "Event/System/EventID=1"

# Results storage
_latencies_ms: list[float] = []
_events_received = 0
_events_expected = 0
_stop_event = threading.Event()
_event_queue: asyncio.Queue | None = None


def _parse_event_xml(xml_str: str) -> dict:
    """Parse Sysmon Event 1 XML to extract key fields."""
    # XML namespace handling
    ns = {
        "ns": "http://schemas.microsoft.com/win/2004/08/events/event",
    }
    root = ET.fromstring(xml_str)

    result = {}
    # System fields
    system = root.find("ns:System", ns)
    if system is not None:
        time_created = system.find("ns:TimeCreated", ns)
        if time_created is not None:
            result["timestamp"] = time_created.get("SystemTime", "")
        record_id = system.find("ns:EventRecordID", ns)
        if record_id is not None:
            result["record_id"] = record_id.text

    # EventData fields (Sysmon-specific)
    event_data = root.find("ns:EventData", ns)
    if event_data is not None:
        for data in event_data.findall("ns:Data", ns):
            name = data.get("Name", "")
            result[name] = data.text or ""

    return result


def _callback(action, user_context, event):
    """EvtSubscribe callback — called from Windows internal thread."""
    global _events_received

    if action == win32evtlog.EvtSubscribeActionDeliver:
        _events_received += 1
        try:
            xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            parsed = _parse_event_xml(xml_str)

            # Measure latency: compare event timestamp to now
            # Sysmon timestamp is when the event was generated
            # We can't get exact process creation time from XML easily,
            # so we use callback arrival time as proxy
            callback_time = time.monotonic()

            # Extract process info
            image = parsed.get("Image", "?")
            cmd_line = parsed.get("CommandLine", "")
            record_id = parsed.get("record_id", "?")

            # Put on queue for async processing
            if _event_queue is not None:
                # run_coroutine_threadsafe needs the loop
                loop = user_context
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        _event_queue.put((callback_time, parsed)), loop
                    )

        except Exception as e:
            print(f"[callback] Error: {e}", file=sys.stderr)

    return 0


async def _event_consumer():
    """Async consumer — reads from queue, records latencies."""
    global _latencies_ms

    while not _stop_event.is_set():
        try:
            callback_time, parsed = await asyncio.wait_for(
                _event_queue.get(), timeout=0.5
            )
            # Latency from callback to here (async bridge overhead)
            async_arrival = time.monotonic()
            bridge_latency_ms = (async_arrival - callback_time) * 1000
            _latencies_ms.append(bridge_latency_ms)

            image = parsed.get("Image", "?")
            if "spike" in image.lower() or "cmd.exe" in image.lower():
                print(
                    f"  [async] {parsed.get('record_id', '?'):>6}  "
                    f"bridge={bridge_latency_ms:.1f}ms  {image}"
                )
        except asyncio.TimeoutError:
            continue


def _spawn_processes(count: int, marker: str = "spike_marker") -> float:
    """Spawn N processes rapidly, return spawn start time."""
    global _events_expected
    _events_expected += count

    start = time.monotonic()
    for i in range(count):
        # cmd /c echo — minimal process, exits immediately
        subprocess.Popen(
            ["cmd.exe", "/c", f"echo {marker}_{i}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    spawn_duration = time.monotonic() - start
    return spawn_duration


async def run_spike():
    """Main spike coroutine."""
    global _event_queue

    print("=" * 70)
    print("Sysmon EvtSubscribe Spike — Event 1 (Process Create)")
    print("=" * 70)

    # Setup asyncio queue
    _event_queue = asyncio.Queue(maxsize=10000)

    # Start async consumer
    consumer_task = asyncio.create_task(_event_consumer())

    # Start EvtSubscribe with callback
    loop = asyncio.get_running_loop()
    print("\n[1] Starting EvtSubscribe subscription...")
    try:
        subscription = win32evtlog.EvtSubscribe(
            SYSMON_CHANNEL,
            win32evtlog.EvtSubscribeToFutureEvents,
            Query=EVENT_1_QUERY,
            Callback=_callback,
            Context=loop,
        )
        print("    Subscription active.")
    except Exception as e:
        print(f"    FAILED: {e}")
        print("    (Run as admin — Sysmon Event Log requires admin or Event Log Readers)")
        return

    # Wait for subscription to stabilize
    await asyncio.sleep(1.0)

    # ── Test 1: Single process latency ──
    print("\n[2] Latency test: spawning 1 process...")
    initial_received = _events_received
    t0 = time.monotonic()
    _spawn_processes(1, "latency_test")
    # Wait for event to arrive
    for _ in range(50):  # 5s max
        await asyncio.sleep(0.1)
        if _events_received > initial_received:
            latency_ms = (time.monotonic() - t0) * 1000
            print(f"    Event received in {latency_ms:.0f}ms (spawn→callback→async)")
            break
    else:
        print("    TIMEOUT: no event received in 5s")

    # ── Test 2: Burst loss ──
    print("\n[3] Burst test: spawning 100 processes rapidly...")
    initial_received = _events_received
    initial_expected = _events_expected
    spawn_time = _spawn_processes(100, "burst_test")
    print(f"    Spawned 100 processes in {spawn_time:.2f}s")

    # Wait for events to settle (give Sysmon + Event Log time)
    print("    Waiting 5s for events to arrive...")
    await asyncio.sleep(5.0)

    burst_received = _events_received - initial_received
    burst_expected = _events_expected - initial_expected
    loss_pct = (
        ((burst_expected - burst_received) / burst_expected * 100)
        if burst_expected > 0
        else 0
    )
    print(f"    Received: {burst_received}/{burst_expected}  (loss: {loss_pct:.1f}%)")

    # ── Test 3: Sustained throughput ──
    print("\n[4] Sustained test: 50 processes over 5s (10/sec)...")
    initial_received = _events_received
    initial_expected = _events_expected
    for i in range(5):
        _spawn_processes(10, f"sustained_{i}")
        await asyncio.sleep(1.0)

    await asyncio.sleep(2.0)
    sustained_received = _events_received - initial_received
    sustained_expected = _events_expected - initial_expected
    print(f"    Received: {sustained_received}/{sustained_expected}")

    # ── Summary ──
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total events received: {_events_received}")
    print(f"  Total events expected: {_events_expected}")
    if _latencies_ms:
        print(f"\n  Async bridge latency (callback→async consumer):")
        print(f"    min:    {min(_latencies_ms):.1f}ms")
        print(f"    median: {statistics.median(_latencies_ms):.1f}ms")
        print(f"    mean:   {statistics.mean(_latencies_ms):.1f}ms")
        print(f"    p95:    {statistics.quantiles(_latencies_ms, n=20)[18]:.1f}ms")
        print(f"    max:    {max(_latencies_ms):.1f}ms")
        print(f"    count:  {len(_latencies_ms)}")
    else:
        print("\n  No latency samples collected.")

    # Cleanup
    _stop_event.set()
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    print("\nSpike complete.")


def main():
    # Check admin
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        print("WARNING: Not running as admin. Sysmon Event Log access may fail.")
        print("  (Event Log Readers group membership also works.)")
        print()

    asyncio.run(run_spike())


if __name__ == "__main__":
    main()
