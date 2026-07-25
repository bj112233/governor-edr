# tools/sysmon/spike_minimal.py
"""Minimal EvtSubscribe test — spawn processes + verify callback fires."""

from __future__ import annotations

import os
import subprocess
import sys
import time

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import win32evtlog  # noqa: E402

import services._winutil  # noqa: F401, E402

_events = 0
_start = time.monotonic()


def callback(action, ctx, event):
    global _events
    if action == win32evtlog.EvtSubscribeActionDeliver:
        _events += 1
        elapsed = time.monotonic() - _start
        print(f"  [{elapsed:.2f}s] Event #{_events} received", flush=True)
    return 0


def main():
    print("Starting EvtSubscribe...", flush=True)
    win32evtlog.EvtSubscribe(
        "Microsoft-Windows-Sysmon/Operational",
        win32evtlog.EvtSubscribeToFutureEvents,
        Query="Event/System/EventID=1",
        Callback=callback,
    )
    print("Subscription active.", flush=True)

    # Spawn 5 processes to generate events
    print("Spawning 5 processes...", flush=True)
    for i in range(5):
        subprocess.Popen(
            ["cmd.exe", "/c", f"echo spike_{i}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
        )

    print("Waiting 5s for callbacks...", flush=True)
    time.sleep(5)

    print(f"\nTotal events received: {_events} (expected ~5)", flush=True)
    print("Done.", flush=True)


if __name__ == "__main__":
    main()
