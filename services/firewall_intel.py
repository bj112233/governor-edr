# services/firewall_intel.py
"""
Level 150: Windows Firewall Log Intelligence
ניתוח יומן חומת האש — DROP events, TOP sources, סטטיסטיקות.
"""

import logging
import os

logger = logging.getLogger(__name__)

_FW_LOG = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"


def get_firewall_log_raw(lines: int = 60) -> str:
    """קרא שורות אחרונות מיומן חומת האש."""
    if not os.path.exists(_FW_LOG):
        return "Firewall log not found.\nRun /fwlog enable to activate logging (requires Admin)."
    try:
        with open(_FW_LOG, errors="replace") as f:
            all_lines = f.readlines()
        data_lines = [line.rstrip() for line in all_lines if not line.startswith("#")]
        return "\n".join(data_lines[-lines:]) if data_lines else "Log file is empty."
    except PermissionError:
        return "Permission denied reading firewall log. Run bot as Administrator."
    except Exception as e:
        logger.error(f"[FW] read error: {e}")
        return f"[ERROR] {e}"


def get_firewall_drops(limit: int = 30) -> str:
    """מחזיר רק חיבורים שנחסמו (DROP)."""
    raw = get_firewall_log_raw(200)
    if raw.startswith("Firewall log not found") or raw.startswith("Permission"):
        return raw
    drops = [line for line in raw.splitlines() if " DROP " in line]
    if not drops:
        return "No DROP events found in recent firewall log."
    return "\n".join(drops[-limit:])
