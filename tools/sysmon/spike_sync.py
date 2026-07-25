# tools/sysmon/spike_sync.py
"""Spike: EvtSubscribe latency + burst loss.

Key insight: EvtSubscribe callback needs the main thread to pump messages.
Using a message pump loop instead of time.sleep().
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import statistics
import subprocess
import sys
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import win32evtlog  # noqa: E402

import services._winutil  # noqa: F401, E402

# Results
_event_times: list[float] = []  # callback arrival times (monotonic)
_event_count = 0
_start = 0.0


def callback(action, ctx, event):
    global _event_count
    if action == win32evtlog.EvtSubscribeActionDeliver:
        _event_count += 1
        _event_times.append(time.monotonic())
    return 0


def pump_messages(duration_s: float):
    """Pump Windows messages for duration_s seconds (allows callbacks to fire)."""
    msg = ctypes.wintypes.MSG()
    end = time.monotonic() + duration_s
    while time.monotonic() < end:
        # PeekMessage with PM_REMOVE, non-blocking
        ctypes.windll.user32.PeekMessageW(ctypes.byref(msg), 0, 0, 0, 1)
        time.sleep(0.001)  # yield to callback thread


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


def main():
    global _start

    print("=" * 70, flush=True)
    print("Sysmon EvtSubscribe Spike (Event 1, message pump)", flush=True)
    print("=" * 70, flush=True)

    print("\n[1] Starting EvtSubscribe...", flush=True)
    _start = time.monotonic()
    win32evtlog.EvtSubscribe(
        "Microsoft-Windows-Sysmon/Operational",
        win32evtlog.EvtSubscribeToFutureEvents,
        Query="Event/System/EventID=1",
        Callback=callback,
    )
    print("    Subscription active.", flush=True)
    pump_messages(1.0)
    initial = _event_count

    # ── Test 1: Single process ──
    print("\n[2] Latency: 1 process...", flush=True)
    t0 = time.monotonic()
    spawn_processes(1, "latency")
    pump_messages(3.0)
    received = _event_count - initial
    total_ms = (time.monotonic() - t0) * 1000
    print(f"    Events: {received}  total: {total_ms:.0f}ms", flush=True)

    # ── Test 2: Burst ──
    print("\n[3] Burst: 100 processes...", flush=True)
    initial = _event_count
    spawn_time = spawn_processes(100, "burst")
    print(f"    Spawned in {spawn_time:.2f}s. Pumping 5s...", flush=True)
    pump_messages(5.0)
    burst = _event_count - initial
    print(f"    Received: {burst} events", flush=True)

    # ── Test 3: Sustained ──
    print("\n[4] Sustained: 50 over 5s...", flush=True)
    initial = _event_count
    for i in range(5):
        spawn_processes(10, f"sus_{i}")
        pump_messages(1.0)
    pump_messages(2.0)
    sustained = _event_count - initial
    print(f"    Received: {sustained} events", flush=True)

    # ── Summary ──
    print("\n" + "=" * 70, flush=True)
    print("SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"  Total events: {_event_count}", flush=True)
    if _event_times:
        # Inter-arrival times
        if len(_event_times) > 1:
            intervals = [
                (_event_times[i] - _event_times[i - 1]) * 1000
                for i in range(1, len(_event_times))
            ]
            print("\n  Inter-arrival time (ms):", flush=True)
            print(f"    min:    {min(intervals):.1f}", flush=True)
            print(f"    median: {statistics.median(intervals):.1f}", flush=True)
            print(f"    mean:   {statistics.mean(intervals):.1f}", flush=True)
            print(f"    max:    {max(intervals):.1f}", flush=True)
    print("\nDone.", flush=True)


if __name__ == "__main__":
    main()
