# tools/sysmon/spike_async.py
"""Spike: EvtSubscribe with asyncio bridge.

Consumer thread runs EvtSubscribe with message pump.
Events pushed to asyncio.Queue via run_coroutine_threadsafe.
Measures bridge latency (callback → async consumer).
"""

from __future__ import annotations

import asyncio
import os
import statistics
import subprocess
import sys
import threading
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import win32evtlog  # noqa: E402

import services._winutil  # noqa: F401, E402

# Shared state
_bridge_latencies: list[float] = []
_event_count = 0
_stop = threading.Event()
_queue: asyncio.Queue | None = None
_loop: asyncio.AbstractEventLoop | None = None


def callback(action, ctx, event):
    """Called from EvtSubscribe internal thread."""
    global _event_count
    if action == win32evtlog.EvtSubscribeActionDeliver:
        _event_count += 1
        cb_time = time.monotonic()
        if _loop and _loop.is_running():
            # Schedule async put — run_coroutine_threadsafe returns a Future
            asyncio.run_coroutine_threadsafe(
                _queue.put((cb_time, _event_count)), _loop
            )
    return 0


async def async_consumer():
    """Read from queue, measure bridge latency."""
    while not _stop.is_set():
        try:
            cb_time, num = await asyncio.wait_for(_queue.get(), timeout=0.5)
            arrival = time.monotonic()
            bridge_ms = (arrival - cb_time) * 1000
            _bridge_latencies.append(bridge_ms)
        except TimeoutError:
            continue


def spawn_processes(count: int, marker: str) -> float:
    start = time.monotonic()
    for i in range(count):
        subprocess.Popen(
            ["cmd.exe", "/c", f"echo {marker}_{i}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
    return time.monotonic() - start


async def run_spike():
    global _queue, _loop

    print("=" * 70, flush=True)
    print("Sysmon EvtSubscribe + asyncio Bridge Spike", flush=True)
    print("=" * 70, flush=True)

    _queue = asyncio.Queue(maxsize=10000)
    _loop = asyncio.get_running_loop()

    # Start EvtSubscribe (callback runs in Windows internal thread)
    print("\n[1] Starting EvtSubscribe...", flush=True)
    win32evtlog.EvtSubscribe(
        "Microsoft-Windows-Sysmon/Operational",
        win32evtlog.EvtSubscribeToFutureEvents,
        Query="Event/System/EventID=1",
        Callback=callback,
    )
    print("    Subscription active.", flush=True)

    # Start async consumer
    consumer = asyncio.create_task(async_consumer())

    # Stabilize
    await asyncio.sleep(1.0)
    initial = _event_count

    # ── Test 1: Single ──
    print("\n[2] Latency: 1 process...", flush=True)
    t0 = time.monotonic()
    spawn_processes(1, "latency")
    await asyncio.sleep(2.0)
    received = _event_count - initial
    print(f"    Events: {received}  total: {(time.monotonic()-t0)*1000:.0f}ms", flush=True)

    # ── Test 2: Burst ──
    print("\n[3] Burst: 100 processes...", flush=True)
    initial = _event_count
    initial_bridge = len(_bridge_latencies)
    spawn_time = spawn_processes(100, "burst")
    print(f"    Spawned in {spawn_time:.2f}s. Waiting 5s...", flush=True)
    await asyncio.sleep(5.0)
    burst = _event_count - initial
    bridge_received = len(_bridge_latencies) - initial_bridge
    print(f"    Events: {burst}  Bridge delivered: {bridge_received}", flush=True)

    # ── Test 3: Sustained ──
    print("\n[4] Sustained: 50 over 5s...", flush=True)
    initial = _event_count
    for i in range(5):
        spawn_processes(10, f"sus_{i}")
        await asyncio.sleep(1.0)
    await asyncio.sleep(2.0)
    sustained = _event_count - initial
    print(f"    Events: {sustained}", flush=True)

    # ── Summary ──
    _stop.set()
    consumer.cancel()
    try:
        await consumer
    except asyncio.CancelledError:
        pass

    print("\n" + "=" * 70, flush=True)
    print("SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"  Total events (callback): {_event_count}", flush=True)
    print(f"  Bridge deliveries:       {len(_bridge_latencies)}", flush=True)
    if _bridge_latencies:
        samples = _bridge_latencies[5:]  # skip startup
        if samples:
            print("\n  Bridge latency (callback -> async consumer):", flush=True)
            print(f"    min:    {min(samples):.2f}ms", flush=True)
            print(f"    median: {statistics.median(samples):.2f}ms", flush=True)
            print(f"    mean:   {statistics.mean(samples):.2f}ms", flush=True)
            print(f"    p95:    {sorted(samples)[int(len(samples)*0.95)]:.2f}ms", flush=True)
            print(f"    max:    {max(samples):.2f}ms", flush=True)
            print(f"    count:  {len(samples)}", flush=True)
    print("\nDone.", flush=True)


def main():
    asyncio.run(run_spike())


if __name__ == "__main__":
    main()
