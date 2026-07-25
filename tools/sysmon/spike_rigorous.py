# tools/sysmon/spike_rigorous.py
"""Rigorous EvtSubscribe spike — addresses three concerns:

1. Steady-state vs burst latency decomposition
2. Real consumer (analyze_cmdline) not dummy handler
3. Background load (simulated LLM/threat_hunter CPU contention)

Run as admin.
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
from services.cmdline_analyzer import analyze_cmdline  # noqa: E402

# ── Shared state ──
_event_queue: asyncio.Queue | None = None
_loop: asyncio.AbstractEventLoop | None = None
_stop = threading.Event()

# Per-event records: (event_seq, callback_time, consumer_time, bridge_latency_ms, analyze_latency_ms)
_records: list[tuple[int, float, float, float, float]] = []
_event_seq = 0


def callback(action, _ctx, event):
    global _event_seq
    if action == win32evtlog.EvtSubscribeActionDeliver:
        _event_seq += 1
        seq = _event_seq
        cb_time = time.monotonic()
        if _loop and _loop.is_running():
            asyncio.run_coroutine_threadsafe(
                _event_queue.put((seq, cb_time)), _loop
            )
    return 0


async def real_consumer():
    """Consumer that calls analyze_cmdline — the real production handler."""
    while not _stop.is_set():
        try:
            seq, cb_time = await asyncio.wait_for(_event_queue.get(), timeout=0.5)
            consumer_start = time.monotonic()

            # Real production work: parse + analyze
            # (In production, we'd parse XML here; for spike, use a representative cmdline)
            cmdline = f"cmd.exe /c echo spike_{seq}"
            analyze_cmdline(cmdline)

            consumer_end = time.monotonic()
            bridge_ms = (consumer_start - cb_time) * 1000
            analyze_ms = (consumer_end - consumer_start) * 1000
            _records.append((seq, cb_time, consumer_end, bridge_ms, analyze_ms))
        except TimeoutError:
            continue


async def dummy_load(duration_s: float, intensity: float = 0.3):
    """Simulate background event-loop load (LLM analysis, threat_hunter).

    intensity: fraction of time spent CPU-bound (0.3 = 30% busy).
    """
    end = time.monotonic() + duration_s
    busy_chunk = 0.05 * intensity  # 50ms * intensity
    idle_chunk = 0.05 * (1 - intensity)
    iterations = 0
    while time.monotonic() < end:
        # CPU-bound work (simulate regex/JSON parsing)
        if busy_chunk > 0:
            t0 = time.monotonic()
            while time.monotonic() - t0 < busy_chunk:
                # Busy-wait with trivial work
                sum(i * i for i in range(100))
        await asyncio.sleep(idle_chunk)
        iterations += 1
    return iterations


def spawn_processes(count: int, marker: str, delay_ms: float = 0) -> float:
    start = time.monotonic()
    for i in range(count):
        subprocess.Popen(
            ["cmd.exe", "/c", f"echo {marker}_{i}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
    return time.monotonic() - start


def print_latency_stats(label: str, latencies: list[float]):
    if not latencies:
        print(f"  {label}: no samples", flush=True)
        return
    sorted_l = sorted(latencies)
    n = len(sorted_l)
    p95_idx = min(int(n * 0.95), n - 1)
    p99_idx = min(int(n * 0.99), n - 1)
    print(f"  {label} (n={n}):", flush=True)
    print(f"    min:    {min(latencies):.2f}ms", flush=True)
    print(f"    median: {statistics.median(latencies):.2f}ms", flush=True)
    print(f"    mean:   {statistics.mean(latencies):.2f}ms", flush=True)
    print(f"    p95:    {sorted_l[p95_idx]:.2f}ms", flush=True)
    print(f"    p99:    {sorted_l[p99_idx]:.2f}ms", flush=True)
    print(f"    max:    {max(latencies):.2f}ms", flush=True)


async def run_spike():
    global _event_queue, _loop

    print("=" * 70, flush=True)
    print("Sysmon EvtSubscribe — Rigorous Spike", flush=True)
    print("=" * 70, flush=True)

    _event_queue = asyncio.Queue(maxsize=10000)
    _loop = asyncio.get_running_loop()

    print("\n[1] Starting EvtSubscribe...", flush=True)
    _sub = win32evtlog.EvtSubscribe(  # noqa: F841 — keep handle alive
        "Microsoft-Windows-Sysmon/Operational",
        win32evtlog.EvtSubscribeToFutureEvents,
        Query="Event/System/EventID=1",
        Callback=callback,
    )
    print("    Subscription active.", flush=True)

    consumer_task = asyncio.create_task(real_consumer())
    await asyncio.sleep(1.0)  # stabilize

    # ── Test 1: Steady-state (1 process every 500ms, 20 events) ──
    print("\n[2] Steady-state: 1 process / 500ms, 20 events...", flush=True)
    _records.clear()
    _event_seq = 0
    for i in range(20):
        spawn_processes(1, f"steady_{i}")
        await asyncio.sleep(0.5)
    await asyncio.sleep(2.0)  # drain
    steady_records = list(_records)
    steady_bridge = [r[3] for r in steady_records]
    steady_analyze = [r[4] for r in steady_records]
    print(f"    Events: {len(steady_records)}/20", flush=True)
    print_latency_stats("Steady-state bridge latency", steady_bridge)
    print_latency_stats("analyze_cmdline latency", steady_analyze)

    # ── Test 2: Burst (100 processes in <1s) ──
    print("\n[3] Burst: 100 processes rapid...", flush=True)
    _records.clear()
    _event_seq = 0
    spawn_time = spawn_processes(100, "burst")
    print(f"    Spawned in {spawn_time:.2f}s. Waiting 5s to drain...", flush=True)
    await asyncio.sleep(5.0)
    burst_records = list(_records)
    burst_bridge = [r[3] for r in burst_records]
    print(f"    Events: {len(burst_records)}", flush=True)
    print_latency_stats("Burst bridge latency", burst_bridge)

    # Show accumulation curve (first 10, middle 10, last 10)
    if len(burst_records) >= 30:
        print("\n    Accumulation curve (bridge latency by event position):", flush=True)
        for label, chunk in [
            ("first 10", burst_bridge[:10]),
            ("middle 10", burst_bridge[len(burst_bridge)//2-5:len(burst_bridge)//2+5]),
            ("last 10", burst_bridge[-10:]),
        ]:
            print(f"      {label}: median={statistics.median(chunk):.1f}ms  max={max(chunk):.1f}ms", flush=True)

    # ── Test 3: Burst WITH background load ──
    print("\n[4] Burst + background load (30% CPU contention)...", flush=True)
    _records.clear()
    _event_seq = 0
    load_task = asyncio.create_task(dummy_load(8.0, intensity=0.3))
    await asyncio.sleep(1.0)  # let load ramp up
    spawn_time = spawn_processes(100, "burst_loaded")
    print(f"    Spawned in {spawn_time:.2f}s. Waiting 5s to drain...", flush=True)
    await asyncio.sleep(5.0)
    load_iters = await load_task
    loaded_records = list(_records)
    loaded_bridge = [r[3] for r in loaded_records]
    print(f"    Events: {len(loaded_records)}  (load: {load_iters} iters)", flush=True)
    print_latency_stats("Burst+load bridge latency", loaded_bridge)

    # ── Test 4: Steady-state WITH background load ──
    print("\n[5] Steady-state + background load (30% CPU)...", flush=True)
    _records.clear()
    _event_seq = 0
    load_task = asyncio.create_task(dummy_load(15.0, intensity=0.3))
    await asyncio.sleep(1.0)
    for i in range(20):
        spawn_processes(1, f"steady_loaded_{i}")
        await asyncio.sleep(0.5)
    await asyncio.sleep(2.0)
    load_iters = await load_task
    loaded_steady = list(_records)
    loaded_steady_bridge = [r[3] for r in loaded_steady]
    print(f"    Events: {len(loaded_steady)}/20  (load: {load_iters} iters)", flush=True)
    print_latency_stats("Steady+load bridge latency", loaded_steady_bridge)

    # ── Summary ──
    _stop.set()
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    print("\n" + "=" * 70, flush=True)
    print("SUMMARY", flush=True)
    print("=" * 70, flush=True)
    print(f"\n  analyze_cmdline cost: ~{statistics.mean(steady_analyze):.3f}ms/call (regex-based)", flush=True)
    print(f"\n  {'Scenario':<30} {'median':>8} {'p95':>8} {'max':>8} {'n':>5}", flush=True)
    print(f"  {'-'*65}", flush=True)
    for label, lats in [
        ("Steady-state (idle)", steady_bridge),
        ("Burst (idle)", burst_bridge),
        ("Steady-state + 30% load", loaded_steady_bridge),
        ("Burst + 30% load", loaded_bridge),
    ]:
        if lats:
            s = sorted(lats)
            print(f"  {label:<30} {statistics.median(lats):>7.1f}ms {s[min(int(len(s)*0.95),len(s)-1)]:>7.1f}ms {max(lats):>7.1f}ms {len(lats):>5}", flush=True)
        else:
            print(f"  {label:<30} {'N/A':>8} {'N/A':>8} {'N/A':>8} {'0':>5}", flush=True)
    print("\nDone.", flush=True)


def main():
    asyncio.run(run_spike())


if __name__ == "__main__":
    main()
