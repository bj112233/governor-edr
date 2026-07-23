# os_module.py

import asyncio

import psutil

from config import PROTECTED_PROCESSES
from services._winutil import _decode_oem  # noqa: F401  (re-exported for callers)


def get_all_disks_info() -> str:
    """דו״ח מפורט על כל הכוננים — לפקודת /disks"""
    partitions = psutil.disk_partitions(all=False)
    lines = ["💾 דו״ח כוננים מלא:\n"]
    for part in partitions:
        try:
            u = psutil.disk_usage(part.mountpoint)
            total_gb = u.total / (1024**3)
            used_gb = u.used / (1024**3)
            free_gb = u.free / (1024**3)
            filled = int(u.percent / 10)
            bar = "█" * filled + "░" * (10 - filled)
            status = "🔴" if u.percent > 85 else "🟡" if u.percent > 70 else "🟢"
            lines.append(
                f"{status} {part.device}  [{part.fstype}]\n"
                f"  [{bar}] {u.percent:.1f}%\n"
                f'  📦 {total_gb:.1f} GB סה"כ | בשימוש: {used_gb:.1f} GB | פנוי: {free_gb:.1f} GB\n'
            )
        except (PermissionError, OSError):
            lines.append(f"⚠️ {part.device} — PermissionError\n")
    return "\n".join(lines)


async def kill_process_by_name(process_name: str) -> str:
    """
    סורק את עץ התהליכים והורג את כל המופעים של שם התהליך המבוקש.
    לוגיקה: משתמש ב-psutil כדי לבצע Graceful Terminate (SIGTERM).
    """
    killed_count = 0
    process_name = process_name.lower()

    # Adversarial Truth: יש תהליכי מערכת שאסור לגעת בהם.
    # רשימה שחורה קשיחה (Blacklist) נטענת מ-config.py להגנה עצמית.
    if process_name in PROTECTED_PROCESSES:
        return f"🛡️ פעולה נחסמה: הריגת '{process_name}' תגרום לקריסת מערכת ההפעלה."

    target_base = process_name.removesuffix(".exe")
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            actual = (proc.info["name"] or "").lower()
            if actual == process_name or actual == f"{target_base}.exe":
                await asyncio.to_thread(proc.kill)
                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if killed_count > 0:
        return f"✅ בוצע: חוסלו {killed_count} תהליכים שעונים לשם '{process_name}'."
    else:
        return f"🔍 התהליך '{process_name}' לא נמצא בזיכרון כעת."


# ==========================================
# Legacy CMD runner removed.
# `execute_terminal_command` was retired in favor of
# `services.action_tools.run_powershell`, which has a stronger blocklist
# (PS_BLOCKED_KEYWORDS) and uses powershell.exe directly without `shell=True`.
# ==========================================
