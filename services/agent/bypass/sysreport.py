# services/agent/bypass/sysreport.py
"""System report bypass — gathers all system data in parallel and formats a single
Telegram report without LLM cycles. Formatters are extracted per-section to keep
the orchestrator's cyclomatic complexity low (Single Responsibility)."""

import asyncio
import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

from services.bot_memory import async_store_conversation

logger = logging.getLogger(__name__)

SEP = "─────────────────────"

_EVT_DESC: dict[str, str] = {
    "4624": "כניסה מוצלחת",
    "4625": "כניסה נכשלה",
    "4634": "יציאה",
    "4648": "כניסה עם credentials",
    "4688": "תהליך חדש",
    "4672": "הרשאות מיוחדות",
    "4720": "משתמש חדש",
    "4740": "חשבון ננעל",
}

_SYSREPORT_KEYWORDS: frozenset[str] = frozenset(
    [
        "דוח מערכת",
        "system report",
        "דוח מלא",
        "full report",
        "סטטוס מערכת",
        "דוח יומי",
        "daily report",
        "מצב מערכת",
    ]
)


def _detect_sysreport_query(q: str) -> bool:
    """Return True if the query requests a full system report."""
    q_low = q.strip().lower()
    return q_low == "דוח" or any(kw in q_low for kw in _SYSREPORT_KEYWORDS)


# ── Section formatters (each owns its separators → byte-identical assembly) ──


def _fmt_header(now: str) -> list[str]:
    """Report title + timestamp."""
    return ["📊 **דוח מערכת מלא**", f"_עודכן: {now}_", SEP]


def _fmt_loads(snap: Any) -> list[str]:
    """CPU/RAM load icons + disk alerts."""
    if not isinstance(snap, dict):
        return []
    cpu = snap.get("cpu", 0)
    mem = snap.get("mem", 0)
    c_icon = "🔴" if cpu > 85 else "🟡" if cpu > 60 else "🟢"
    m_icon = "🔴" if mem > 85 else "🟡" if mem > 70 else "🟢"
    out = ["**💡 עומסים:**", f"{c_icon} CPU: {cpu:.0f}%   {m_icon} RAM: {mem:.0f}%"]
    out += [f"⚠️ {da}" for da in snap.get("disk_alerts", [])]
    return out


def _fmt_disks(disk_info: Any) -> list[str]:
    """Disk report lines (drops the redundant 'דו״ח כוננים' header)."""
    if not isinstance(disk_info, str) or not disk_info.strip():
        return []
    return ["", SEP, "**💾 כוננים:**"] + [ln for ln in disk_info.splitlines() if "דו״ח כוננים" not in ln]


def _fmt_adapters(adapters: Any) -> list[str]:
    """Network adapter lines bearing an IPv4 address."""
    if not isinstance(adapters, str) or not adapters.strip():
        return []
    out = ["", SEP, "**🌐 ממשקי רשת:**"]
    for ln in adapters.splitlines():
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ln):
            parts = ln.split()
            if len(parts) >= 3:
                out.append(f"- {parts[0]:<20} → {parts[1]}/{parts[2]}")
    return out


def _fmt_ports(ports: Any) -> list[str]:
    """Listening ports, compact single-line (top 14 by port)."""
    if not isinstance(ports, str) or "No listening" in ports:
        return []
    entries = sorted(
        {
            f"{m.group(1)}/{m.group(2)} ({m.group(3)})"
            for ln in ports.splitlines()
            if (m := re.match(r"PORT=(\d+) \| (TCP|UDP) \| ADDR=\S+ \| PID=\d+ \| PROCESS=(\S+)", ln))
        },
        key=lambda x: int(x.split("/")[0]),
    )
    if not entries:
        return []
    return ["", "**🔌 פורטים מאזינים:**", "- " + " | ".join(entries[:14])]


def _fmt_ext_conns(ext_conns: Any) -> list[str]:
    """External network connections summary (always emits header)."""
    out = ["", "**🌍 חיבורים חיצוניים:**"]
    if not isinstance(ext_conns, str) or "No external" in (ext_conns or ""):
        return out + ["- ✅ אין חיבורים חיצוניים לא-מוכרים"]
    for ln in ext_conns.splitlines()[:6]:
        m = re.match(r"(.+?) \(PID=\d+\) \| \S+ -> (\S+)", ln)
        out.append(f"- {m.group(1)} → {m.group(2)}" if m else f"- {ln.strip()}")
    return out


def _fmt_users(users: Any) -> list[str]:
    """Local user accounts with enabled/logon info."""
    if not isinstance(users, str) or not users.strip():
        return []
    out = ["", SEP, "**👤 משתמשים מקומיים:**"]
    for ln in users.splitlines():
        if not ln.strip() or "----" in ln or ln.strip().startswith("Name"):
            continue
        parts = ln.split()
        if len(parts) >= 2:
            enabled = "✅" if parts[1].lower() == "true" else "❌"
            logon = " ".join(parts[2:4]) if len(parts) > 2 else "—"
            out.append(f"- {enabled} {parts[0]:<18} כניסה: {logon}")
    return out


def _fmt_top_procs(snap: Any) -> list[str]:
    """Top CPU-consuming processes (>1%, max 5)."""
    if not isinstance(snap, dict) or not snap.get("top_procs"):
        return []
    top = [p for p in snap["top_procs"] if p.get("cpu_percent", 0) > 1][:5]
    if not top:
        return []
    out = ["", SEP, "**⚙️ תהליכים (CPU):**"]
    for p in top:
        c = p.get("cpu_percent", 0)
        icon = "🔴" if c > 50 else "🟡" if c > 20 else "🟢"
        out.append(f"- {icon} {p.get('name', '?'):<28} {c:.1f}%  (PID {p.get('pid', '?')})")
    return out


def _fmt_event_log(evt_log: Any) -> list[str]:
    """Security event log summary (top 5 event IDs by frequency)."""
    if not isinstance(evt_log, str) or "No security" in evt_log:
        return []
    eids = re.findall(r"Event ID:\s*(\d+)", evt_log)
    if not eids:
        return []
    out = ["", SEP, "**🔒 לוג אבטחה (20 אחרונים):**"]
    for eid, cnt in Counter(eids).most_common(5):
        out.append(f"- [{eid}] {_EVT_DESC.get(eid, 'אירוע')}  ×{cnt}")
    return out


def _fmt_footer(snap: Any) -> list[str]:
    """Report footer with alert/ok status."""
    alert = isinstance(snap, dict) and snap.get("alert_needed", False)
    return ["", SEP, "⚠️ **התראה פעילה!**" if alert else "✅ **מצב מערכת: תקין**"]


async def _direct_sysreport_bypass(user_question: str) -> str:
    """Gather all system data in parallel — avoids 8+ sequential LLM cycles."""
    from services.monitor_engine import get_system_snapshot
    from services.net_intel import get_external_connections_raw, get_listening_ports_raw
    from services.os_module import get_all_disks_info
    from services.system_intel import get_event_log_raw
    from services.wmi_intel import get_local_users, get_network_adapters

    logger.info("[AGENT] Sysreport bypass: gathering data in parallel")
    snap, disk_info, ext_conns, ports, evt_log, users, adapters = await asyncio.gather(
        get_system_snapshot(),
        asyncio.to_thread(get_all_disks_info),
        asyncio.to_thread(get_external_connections_raw),
        asyncio.to_thread(get_listening_ports_raw),
        get_event_log_raw(),
        get_local_users(),
        get_network_adapters(),
        return_exceptions=True,
    )

    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    out: list[str] = []
    out += _fmt_header(now)
    out += _fmt_loads(snap)
    out += _fmt_disks(disk_info)
    out += _fmt_adapters(adapters)
    out += _fmt_ports(ports)
    out += _fmt_ext_conns(ext_conns)
    out += _fmt_users(users)
    out += _fmt_top_procs(snap)
    out += _fmt_event_log(evt_log)
    out += _fmt_footer(snap)

    result = "\n".join(out)
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
