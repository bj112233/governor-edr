"""Chaos Engineering / Red Team — live fire test for Threat Hunter.

Simulates an adversarial event:
  1. Opens a suspicious TCP listening port (port 4444 — classic Meterpreter)
  2. Spawns CPU stress workers to drive CPU to ~95%
  3. Triggers the agent with a threat-hunting query (full DAG, no bypass)
  4. Measures end-to-end latency, DAG step count, and tool invocation accuracy

Cleanup: kills stress workers + closes the port when done.

Run:  .\\.venv\\Scripts\\python.exe bin\\chaos_redteam.py
"""

import asyncio
import logging
import multiprocessing as mp
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    stream=sys.stdout,
)

logger = logging.getLogger("chaos_redteam")

# ── CPU Stress Worker ────────────────────────────────────────────────────────


def _cpu_burn(stop_event: mp.Event) -> None:
    """Burn CPU cycles until stop_event is set."""
    while not stop_event.is_set():
        # Tight loop — math operations to peg the core
        x = 0
        for i in range(1_000_000):
            x += i * i


def start_cpu_stress(target_pct: float = 0.70, num_workers: int | None = None) -> tuple[list[mp.Process], mp.Event]:
    """Start CPU stress workers to drive CPU to target_pct.

    Leaves 3 cores free for KoboldCpp HTTP handling + agent + OS.
    """
    if num_workers is None:
        num_workers = max(1, mp.cpu_count() - 3)
    stop_event = mp.Event()
    procs = []
    for i in range(num_workers):
        p = mp.Process(target=_cpu_burn, args=(stop_event,), name=f"chaos_cpu_{i}")
        p.daemon = True
        p.start()
        procs.append(p)
    logger.info("[CHAOS] Started %d CPU stress workers (target: %.0f%%)", num_workers, target_pct * 100)
    return procs, stop_event


def stop_cpu_stress(procs: list[mp.Process], stop_event: mp.Event) -> None:
    stop_event.set()
    for p in procs:
        p.join(timeout=5)
        if p.is_alive():
            p.kill()
    logger.info("[CHAOS] CPU stress workers stopped.")


# ── Suspicious Port Opener ───────────────────────────────────────────────────


def open_suspicious_port(port: int = 4444) -> socket.socket | None:
    """Open a TCP listening socket on the given port (simulates C2 beacon).

    Port 4444 is the classic Meterpreter default — should trigger threat detection.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        s.setblocking(False)
        logger.info("[CHAOS] Suspicious TCP port %d OPEN (simulating C2 beacon)", port)
        return s
    except OSError as e:
        logger.warning("[CHAOS] Could not open port %d: %s", port, e)
        return None


# ── Threat Hunt Query ────────────────────────────────────────────────────────

HUNT_QUERY = (
    "אתה Sentinel Threat Hunter. בצע ציד איומים יזום ומלא. "
    "בדוק: (1) תמונת מצב מערכת עם get_system_snapshot, "
    "(2) חיבורים חיצוניים ופורטים פתוחים עם get_external_connections, "
    "(3) אירועי אבטחה עם get_event_log. "
    "זהה פורטים חשודים, תהליכים חריגים, ועומס CPU לא רגיל. "
    "סיים בשורה נפרדת: THREAT_SCORE: 0.X (0=נקי, 1=קריטי)."
)


async def main():
    from services.agent._agent_loop import run_agent

    print(f"\n{'=' * 70}")
    print("🔴 CHAOS RED TEAM — Live Fire Test")
    print(f"{'=' * 70}")
    print("Simulating: C2 port 4444 + CPU stress + threat hunt query\n")

    # Phase 1: Inject chaos
    print("─" * 70)
    print("PHASE 1: INJECT CHAOS")
    print("─" * 70)

    suspicious_socket = open_suspicious_port(4444)
    cpu_procs, cpu_stop = start_cpu_stress()

    # Let the chaos stabilize (CPU ramps up, port is visible to psutil)
    await asyncio.sleep(3)

    # Verify chaos is active
    import psutil

    cpu_pct = psutil.cpu_percent(interval=1)
    mem_pct = psutil.virtual_memory().percent
    print(f"  CPU: {cpu_pct:.1f}%  RAM: {mem_pct:.1f}%  Port 4444: {'OPEN' if suspicious_socket else 'FAILED'}")

    # Phase 2: Trigger the agent
    print(f"\n{'─' * 70}")
    print("PHASE 2: TRIGGER THREAT HUNTER (full DAG, bypasses DISABLED)")
    print(f"{'─' * 70}")
    print(f"Query: {HUNT_QUERY[:100]}...\n")

    t0 = time.monotonic()
    try:
        result = await run_agent(
            user_question=HUNT_QUERY,
            max_rounds=25,
            allow_bypasses=False,
        )
    except Exception as e:
        result = f"AGENT CRASHED: {e}"
        logger.error("[CHAOS] Agent crashed: %s", e, exc_info=True)
    elapsed = time.monotonic() - t0

    # Phase 3: Analyze results
    print(f"\n{'─' * 70}")
    print("PHASE 3: RESULTS")
    print(f"{'─' * 70}")

    print(f"\n⏱️  End-to-end latency: {elapsed:.1f}s")
    print(f"📝 Result length: {len(result)} chars")
    print("\n--- Agent Output (first 1500 chars) ---")
    print(result[:1500] if result else "(empty)")

    # Check for threat score
    import re

    score_match = re.search(r"THREAT_SCORE:\s*([0-9]\.?[0-9]*)", result or "", re.IGNORECASE)
    if score_match:
        score = float(score_match.group(1))
        print(f"\n🎯 THREAT_SCORE: {score}")
        if score >= 0.5:
            print("✅ DETECTION SUCCESS — agent identified the threat")
        elif score >= 0.2:
            print("⚠️  PARTIAL DETECTION — agent noticed anomalies but scored low")
        else:
            print("❌ DETECTION FAILURE — agent missed the threat")
    else:
        print("\n❌ NO THREAT_SCORE — agent did not follow output format")

    # Check if agent used the right tools
    tools_used = []
    for tool_name in [
        "get_system_snapshot",
        "get_external_connections",
        "get_event_log",
        "skill_firewall-skill",
        "skill_intel-skill",
    ]:
        if tool_name in (result or ""):
            tools_used.append(tool_name)
    print(f"\n🔧 Tools referenced in output: {tools_used or 'none found in text'}")

    # Phase 4: Cleanup
    print(f"\n{'─' * 70}")
    print("PHASE 4: CLEANUP")
    print(f"{'─' * 70}")

    if suspicious_socket:
        suspicious_socket.close()
        print("  Port 4444 closed.")
    stop_cpu_stress(cpu_procs, cpu_stop)

    # Post-cleanup snapshot
    await asyncio.sleep(1)
    cpu_after = psutil.cpu_percent(interval=1)
    print(f"  CPU after cleanup: {cpu_after:.1f}%")

    print(f"\n{'=' * 70}")
    print("CHAOS RED TEAM TEST COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    asyncio.run(main())
