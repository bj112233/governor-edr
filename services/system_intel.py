# services/system_intel.py
"""
Level 150: System Intelligence Data Gatherer
אוסף נתונים גולמיים מהמערכת כטקסט נקי לניתוח AI
"""

import asyncio
import time
from typing import Optional

import psutil

from config import truncate_for_context
from services._winutil import _decode_oem

_PROTECTED_PIDS = {0, 4}
_PROTECTED_NAMES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "lsass.exe",
    "services.exe",
    "svchost.exe",
    "explorer.exe",
    "registry",
    "memory compression",
}


def get_system_snapshot_raw() -> str:
    """מחזיר snapshot של משאבי מערכת — עם פורמט Markdown"""
    cpu = psutil.cpu_percent(interval=0.1)
    ram = psutil.virtual_memory()
    c_icon = "🔴" if cpu > 85 else "🟡" if cpu > 60 else "🟢"
    m_icon = "🔴" if ram.percent > 85 else "🟡" if ram.percent > 70 else "🟢"
    lines = [
        "**💡 עומסי מערכת:**",
        f"{c_icon} CPU: {cpu:.0f}%   {m_icon} RAM: {ram.percent:.0f}%"
        f' ({ram.available / (1024**3):.1f}GB פנוי / {ram.total / (1024**3):.1f}GB סה"כ)',
    ]

    # Add GPU info
    try:
        from services.gpu_amd import get_cached_gpu_info

        gpu_info = get_cached_gpu_info()
        if gpu_info and "name" in gpu_info:
            gpu_name = gpu_info["name"]
            util = gpu_info.get("utilization_percent") or 0
            ram_gb = gpu_info.get("adapter_ram_gb", 0)
            parts = [f"🎮 GPU: {gpu_name}"]
            if util is not None:
                parts.append(f"📊 Load: {util}%")
            if ram_gb:
                used_vram = round(ram_gb * util / 100, 1) if util else 0
                parts.append(f"💾 VRAM: {used_vram}GB used / {ram_gb}GB total")
            lines.append(" | ".join(parts))
        elif gpu_info and "error" in gpu_info:
            lines.append(f"🎮 GPU: {gpu_info['error']}")
    except Exception:
        pass

    lines.extend(
        [
            "",
            "**💾 כוננים:**",
        ]
    )
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            d_icon = "🔴" if u.percent > 85 else "🟡" if u.percent > 70 else "🟢"
            lines.append(
                f"- {d_icon} {part.device}  {u.percent:.0f}% בשימוש"
                f' | פנוי: {u.free / (1024**3):.1f}GB / {u.total / (1024**3):.1f}GB סה"כ'
            )
        except (PermissionError, OSError):
            pass
    return "\n".join(lines)


def get_process_list_raw() -> str:
    """מחזיר עד 40 תהליכים מסודרים לפי CPU עם פורמט Markdown"""
    # 1. Prime — יצירת baseline למוני CPU
    list(psutil.process_iter(["cpu_percent"]))
    # 2. Delta — השהיה ליצירת מדידה אמיתית
    time.sleep(1)

    # 3. Collect + Normalize
    cpu_cores = psutil.cpu_count(logical=True)
    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "username"]):
        try:
            info = proc.info
            # סינון תהליכי ליבה
            if info["pid"] in (0, 4):
                continue
            raw_cpu = info.get("cpu_percent") or 0.0
            true_cpu = raw_cpu / cpu_cores
            # דו"ח תצוגה — סינון רק תהליכים מתים (0.0 מוחלט)
            if true_cpu > 0.01:
                info["cpu_percent"] = true_cpu
                procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Top 15 — מיון מהעומס הגבוה לנמוך, חיתוך לתצוגה
    procs.sort(key=lambda p: p.get("cpu_percent") or 0, reverse=True)
    lines = ["**⚙️ תהליכים (לפי CPU):**"]
    for info in procs[:15]:
        cpu = info.get("cpu_percent") or 0
        mem = info.get("memory_percent") or 0
        icon = "🔴" if cpu > 50 else "🟡" if cpu > 20 else "🟢"
        lines.append(f"- {icon} {info['name']:<28} CPU:{cpu:.1f}%  MEM:{mem:.1f}%  PID:{info['pid']}")
    return truncate_for_context("\n".join(lines) if lines else "No processes found.", max_chars=8000)


def get_services_raw() -> str:
    """מחזיר שירותי Windows עם פורמט Markdown"""
    try:
        running, stopped = [], []
        for svc in psutil.win_service_iter():
            try:
                info = svc.as_dict()
                status = info.get("status", "")
                entry = f"- {info['name']} ({info['display_name']})"
                if status == "running":
                    running.append(entry)
                else:
                    stopped.append(f"{entry} [{status}]")
            except Exception:
                pass
        lines = [
            f"**🛠️ שירותים פעילים ({len(running)}):**",
            *running[:30],
            "",
            f"**⏹️ שירותים עצורים ({len(stopped)}):**",
            *stopped[:20],
        ]
        return "\n".join(lines) if (running or stopped) else "No services found."
    except Exception as e:
        return f"Error gathering services: {e}"


async def get_event_log_raw(count: int = 20) -> str:
    """מחזיר אירועי Security Event Log האחרונים"""
    try:
        proc = await asyncio.create_subprocess_exec(
            "wevtutil",
            "qe",
            "Security",
            f"/c:{count}",
            "/f:text",
            "/rd:true",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        except TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return "⏳ Event log query timed out (>15s)."
        output = _decode_oem(stdout_b).strip()
        return truncate_for_context(output, max_chars=8000) if output else "No security events found."
    except Exception as e:
        return f"Error reading event log: {e}"


def terminate_process(pid: int, expected_create_time: float | None = None) -> str:
    """מסיים תהליך לפי PID — עם חסימה כפולה: לפי PID ולפי שם, ומגן מול PID recycling."""
    if not isinstance(pid, int) or pid <= 0:
        return f"BLOCKED: Invalid PID '{pid}'."
    if pid in _PROTECTED_PIDS:
        return f"BLOCKED: PID {pid} is a protected kernel process."
    try:
        proc = psutil.Process(pid)
        actual_create_time = proc.create_time()
        if expected_create_time is not None and abs(actual_create_time - expected_create_time) > 1.0:
            return (
                f"BLOCKED: PID {pid} has recycled (expected ct={expected_create_time}, actual ct={actual_create_time})."
            )
        name = proc.name().lower()
        if name in _PROTECTED_NAMES:
            return f"BLOCKED: '{name}' (PID {pid}) is a protected system process."
        proc.terminate()
        return f"SUCCESS: '{name}' (PID {pid}) terminated."
    except psutil.NoSuchProcess:
        return f"ERROR: PID {pid} does not exist."
    except psutil.AccessDenied:
        return f"ERROR: Access denied for PID {pid} — elevated privileges required."
    except Exception as e:
        return f"ERROR: {e}"


# ── Re-exports for backward compatibility ──
from services.system_intel_persistence import (  # noqa: E402,F401
    get_active_sessions_raw,
    get_scheduled_tasks_detail_raw,
    get_startup_items_raw,
)
