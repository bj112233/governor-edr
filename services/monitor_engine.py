# services/monitor_engine.py
"""
Level 150: Monitor Engine — Snapshot Collection + Alert Dispatch
מופרד מ-main.py כדי לשמור על גבול 300 שורות ועל SRP.

Network analysis + disk check extracted to monitor_engine_helpers.py.
"""

import asyncio
import logging
import threading
import time
from typing import Any

import psutil

from config import (
    CPU_THRESHOLD,
    DISK_THRESHOLD,
    MONITOR_PROCESS_EXCLUSIONS,
    RAM_THRESHOLD,
    SNAPSHOT_TO_THREAD_TIMEOUT,
    SUSPICIOUS_NET_THRESHOLD,
)
from services.gpu_amd import get_cached_gpu_info
from services.monitor_engine_helpers import (
    _check_disks,
    _collect_suspicious_net,
    is_browser_connection,  # noqa: F401 — re-exported
    is_whitelisted,  # noqa: F401 — re-exported
)

logger = logging.getLogger(__name__)

# ── CPU Daemon Sampler ─────────────────────────────────────────────────────
_cpu_cache: dict[str, Any] = {"cpu": 0.0, "top_procs": []}
_cpu_cache_lock = threading.Lock()


def _cpu_sampler_daemon():
    """Background thread: prime psutil then sample CPU + top processes every 1s."""
    psutil.cpu_percent(interval=0)
    for p in psutil.process_iter(["name", "cpu_percent", "exe", "pid"]):
        pass  # prime baseline
    while True:
        time.sleep(1)
        cpu = psutil.cpu_percent(interval=0)
        cpu_cores = psutil.cpu_count(logical=True)
        top_processes = []
        for p in psutil.process_iter(["name", "cpu_percent", "exe", "pid"]):
            try:
                info = p.info
                if info["pid"] in (0, 4):
                    continue
                raw_cpu = info["cpu_percent"] or 0.0
                true_cpu = raw_cpu / cpu_cores if cpu_cores else raw_cpu
                if true_cpu > 5.0 and not any(ex in (info["name"] or "").lower() for ex in MONITOR_PROCESS_EXCLUSIONS):
                    info["cpu_percent"] = true_cpu
                    top_processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        with _cpu_cache_lock:
            _cpu_cache["cpu"] = cpu
            _cpu_cache["top_procs"] = top_processes


threading.Thread(target=_cpu_sampler_daemon, daemon=True, name="cpu-sampler").start()
# ── end CPU Daemon Sampler ────────────────────────────────────────────────


_SUSPICIOUS_PROC_NAMES = {"powershell.exe", "powershell_ise.exe", "wmic.exe", "certutil.exe", "mshta.exe"}


def _scan_suspicious_procs() -> list[dict[str, Any]]:
    """Scan for processes with suspicious names and capture their command lines.

    Lightweight: only iterates processes matching _SUSPICIOUS_PROC_NAMES.
    Self-blindspot: processes whose cmdline contains the Sentinel project path
    (tactical_bot/sentinel) are dropped — the bot must never analyze its own
    sensor/launcher scripts (pytest, hunt poll, coverage gate) as T1059.001.
    Returns list of {pid, name, cmdline} dicts.
    """
    from services.self_whitelist import is_self_cmdline

    results: list[dict[str, Any]] = []
    for p in psutil.process_iter(["name", "pid", "cmdline"]):
        try:
            info = p.info
            name = (info.get("name") or "").lower()
            if name not in _SUSPICIOUS_PROC_NAMES:
                continue
            cmdline_list = info.get("cmdline") or []
            cmdline = " ".join(cmdline_list) if cmdline_list else ""
            if is_self_cmdline(cmdline):
                continue  # own sensor script — never hunt self
            results.append({"pid": info.get("pid", 0), "name": name, "cmdline": cmdline})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return results


async def get_system_snapshot() -> dict[str, Any]:
    """Collect system metrics: CPU, RAM, GPU, network, disk, top processes.

    All asyncio.to_thread OS calls are wrapped with a hard
    SNAPSHOT_TO_THREAD_TIMEOUT (3s default) so monitor_loop never blocks
    indefinitely on a hung psutil/WMI call. On timeout, the field falls
    back to a safe empty value and a warning is logged.
    """
    # 1. Memory + network connections in parallel (no CPU delta dependency)
    try:
        mem = await asyncio.wait_for(
            asyncio.to_thread(lambda: psutil.virtual_memory().percent),
            timeout=SNAPSHOT_TO_THREAD_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("[Monitor] virtual_memory timed out after %.1fs — using 0.0", SNAPSHOT_TO_THREAD_TIMEOUT)
        mem = 0.0
    try:
        connections = await asyncio.wait_for(
            asyncio.to_thread(psutil.net_connections, kind="inet"),
            timeout=SNAPSHOT_TO_THREAD_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("[Monitor] net_connections timed out after %.1fs — using []", SNAPSHOT_TO_THREAD_TIMEOUT)
        connections = []

    # 2. Suspicious network analysis (enrichment + filtering)
    _ip_cache: dict[str, dict] = {}
    suspicious_net, _self_filtered = await _collect_suspicious_net(connections, _ip_cache)

    # 3. CPU from daemon cache (O(1))
    with _cpu_cache_lock:
        cpu = _cpu_cache["cpu"]
        top_procs = _cpu_cache["top_procs"]

    # 4. Disk + GPU (GPU from daemon cache — O(1), no hardware I/O)
    disk_alerts = await _check_disks()
    gpu_info = get_cached_gpu_info()

    # 5. PowerShell TTP scan — catch obfuscated commands regardless of CPU
    try:
        suspicious_procs = await asyncio.wait_for(
            asyncio.to_thread(_scan_suspicious_procs),
            timeout=SNAPSHOT_TO_THREAD_TIMEOUT,
        )
    except TimeoutError:
        logger.warning("[Monitor] suspicious_procs scan timed out after %.1fs — using []", SNAPSHOT_TO_THREAD_TIMEOUT)
        suspicious_procs = []

    return {
        "cpu": cpu,
        "mem": mem,
        "gpu": gpu_info,
        "suspicious_net": suspicious_net,
        "top_procs": top_procs,
        "suspicious_procs": suspicious_procs,
        "disk_alerts": disk_alerts,
        "alert_needed": cpu > CPU_THRESHOLD
        or mem > RAM_THRESHOLD
        or len(suspicious_net) > SUSPICIOUS_NET_THRESHOLD
        or len(disk_alerts) > 0,
    }
