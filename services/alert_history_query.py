"""Alert history — semantic search, query, and formatting.

Extracted from alert_history.py (SRP). Embedding-based search, 24h filtering,
plain-text query formatting, and daily summary grouping.
"""

import asyncio
import re
from datetime import datetime, timedelta

from config import EMBEDDING_MODEL, LLM_API_BASE
from services.alert_history import _pool, get_recent_alerts
from services.embedding_service import deserialize_vector


def _embed_texts_sync(texts: list[str], model: str = EMBEDDING_MODEL) -> list[list[float]] | None:
    """Compute embeddings via local LLM endpoint. Returns None on failure."""
    try:
        import requests

        url = f"{LLM_API_BASE}/embeddings"
        r = requests.post(
            url,
            json={"model": model, "input": texts},
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        return [d["embedding"] for d in data.get("data", [])]
    except Exception:
        return None


async def _embed_texts(texts: list[str], model: str = EMBEDDING_MODEL) -> list[list[float]] | None:
    """Async wrapper: offload blocking embedding call to thread pool."""
    return await asyncio.to_thread(_embed_texts_sync, texts, model)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity (-1..1)."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


async def search_alerts_semantic(query: str, limit: int = 10, threshold: float = 0.65) -> list:
    """חיפוש סמנטי — async via connection pool."""
    query_vec = await _embed_texts(["query: " + query])
    if not query_vec:
        return await get_recent_alerts(limit)

    q_vec = query_vec[0]
    results: list[tuple[float, tuple]] = []

    async with _pool.acquire() as db:
        rows = await (
            await db.execute("SELECT ts, trigger, report, embedding FROM alerts ORDER BY id DESC LIMIT 500")
        ).fetchall()

    for ts, trigger, report, emb_blob in rows:
        if not emb_blob:
            continue
        try:
            stored_vec = deserialize_vector(emb_blob)
            sim = _cosine_similarity(q_vec, stored_vec)
            if sim >= threshold:
                results.append((sim, (ts, trigger, report)))
        except Exception:
            continue

    results.sort(key=lambda x: x[0], reverse=True)
    return [r[1] for r in results[:limit]]


async def get_alerts_last_24h() -> list:
    """מחזיר את כל ההתראות מ-24 השעות האחרונות.

    NOTE: New alerts store `ts` as ISO 8601 (`%Y-%m-%d %H:%M:%S`).
    Legacy rows may still use `%d/%m %H:%M` (no year). We parse both
    formats in Python and filter by cutoff to ensure correct results
    across year/month boundaries.
    """
    now = datetime.now()
    cutoff = now - timedelta(hours=24)
    rows = []
    async with _pool.acquire() as db:
        all_rows = await (
            await db.execute("SELECT ts, trigger, report FROM alerts ORDER BY id DESC LIMIT 5000")
        ).fetchall()

    for ts, trigger, report in all_rows:
        try:
            parsed = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            try:
                parsed = datetime.strptime(ts, "%d/%m %H:%M").replace(year=now.year)
                if parsed > now + timedelta(minutes=5):
                    parsed = parsed.replace(year=now.year - 1)
            except ValueError:
                continue
        if parsed >= cutoff:
            rows.append((ts, trigger, report))
    return rows


async def query_alert_history_raw(limit: int = 10) -> str:
    """Plain-text dump of recent alerts — מעוצב לתצוגת Telegram.

    Uses _parse_alert_report for severity/value/baseline/z extraction
    (shared with the daily report and /intel). Produces compact per-alert
    blocks instead of dumping raw report text.
    """
    alerts = await get_recent_alerts(limit)
    if not alerts:
        return "📭 אין התראות שמורות."

    from services.telegram.headers import SEPARATOR  # lazy: avoid circular import

    lines = [
        "🚨 **היסטוריית התראות SOC**",
        f"_מציג {len(alerts)} התראות אחרונות_",
        SEPARATOR,
        "",
    ]
    for i, (ts, trigger, report) in enumerate(alerts, 1):
        parsed = _parse_alert_report(report)
        label = _label_for(trigger, parsed)
        sev_icon = parsed["sev_icon"]
        metric = parsed.get("metric") or (trigger.split(":")[1] if ":" in trigger else trigger)

        lines.append(f"**#{i}**  `{ts}`  {sev_icon} {label}")

        # Metric-specific detail lines (mirrors render_threat_row logic).
        if metric == "new_external_ip":
            ip_m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", report) or re.search(r"[0-9a-fA-F:]{8,}", report)
            if ip_m:
                lines.append(f"   • כתובת: {ip_m.group(0)}")
        elif metric == "new_heavy_process":
            proc_m = re.search(r"([\w\.-]+)\s*\(PID", report)
            if proc_m:
                lines.append(f"   • תהליך: {proc_m.group(1)}")
            cpu_m = re.search(r"(\d+\.?\d*)%\s*CPU", report)
            if cpu_m:
                lines.append(f"   • CPU: {float(cpu_m.group(1)):.1f}%")
        elif parsed["current"] is not None:
            lines.append(f"   • ערך: {parsed['current']:.1f}%")
            if parsed["z"] is not None:
                lines.append(f"   • z={parsed['z']:.1f}")
            if parsed["mu"] is not None and parsed["sigma"] is not None:
                lines.append(f"   • בסיס: μ={parsed['mu']:.1f} σ={parsed['sigma']:.1f}")
        else:
            # Fallback: clean single-line reason (strip separators).
            reason = report.replace("━", "").replace("\n", " ").strip()
            if reason:
                lines.append(f"   • {reason[:120]}")

        lines.append("")

    return "\n".join(lines)


# category:metric → (icon, hebrew label). Fallback derives from parsed report.
_TRIGGER_LABELS: dict[str, tuple[str, str]] = {
    "cpu:cpu_spike": ("🖥️", "CPU — זינוק מעורפל"),
    "ram:ram_spike": ("💾", "RAM — זינוק זיכרון"),
    "ram:ram_drop": ("💾", "RAM — צניחת זיכרון"),
    "net:new_external_ip": ("🌐", "רשת — IP חיצוני חדש"),
    "cpu:process_cpu_spike": ("⚙️", "תהליך — זינוק CPU"),
    "process_cpu_spike": ("⚙️", "תהליך — זינוק CPU"),
}

_CAT_HEBREW: dict[str, tuple[str, str]] = {
    "CPU": ("🖥️", "CPU"),
    "RAM": ("💾", "RAM"),
    "DISK": ("💿", "דיסק"),
    "רשת / איומים": ("🌐", "רשת"),
}

# Severity constants — lazy-loaded from SSOT to avoid circular import
# (services.telegram.severity triggers services/telegram/__init__.py →
# channel → routing → processing → agent → tools_registry → memory_tools →
# alert_history → alert_history_query). Populated on first use.
_SEV_ICON: dict[str, str] | None = None
_ICON_SEV: dict[str, str] | None = None


def _ensure_severity_tables() -> None:
    """Lazily populate severity lookup tables from the SSOT module."""
    global _SEV_ICON, _ICON_SEV
    if _SEV_ICON is not None:
        return
    from services.telegram.severity import EMOJI_SEVERITY, SEVERITY_EMOJI_UPPER

    _SEV_ICON = SEVERITY_EMOJI_UPPER
    _ICON_SEV = EMOJI_SEVERITY


_RE_SEV = re.compile(r"התראת Sentinel \[([A-Z]+)\]")
_RE_CAT = re.compile(r"קטגוריה:\s*(.+)")
_RE_METRIC = re.compile(r"מדד:\s*(\S+)")
_RE_CURRENT = re.compile(r"ערך נוכחי:\s*([\d.]+)")
_RE_BASELINE = re.compile(r"בסיס:\s*μ=([\d.]+),\s*σ=([\d.]+)")
_RE_Z = re.compile(r"z=([-\d.]+)")
_RE_TIME = re.compile(r"(\d{2}:\d{2})(?::\d{2})?")


def _parse_alert_report(report: str) -> dict:
    """Extract structured fields from a stored alert `report` text.

    Tolerates missing fields (legacy/shortened rows) — every key defaults to None/[].
    """
    _ensure_severity_tables()
    assert _SEV_ICON is not None and _ICON_SEV is not None
    p: dict = {
        "sev": None,
        "sev_icon": "⚪",
        "cat": None,
        "metric": None,
        "current": None,
        "mu": None,
        "sigma": None,
        "z": None,
    }
    if not report:
        return p
    if m := _RE_SEV.search(report):
        p["sev"] = m.group(1)
        p["sev_icon"] = _SEV_ICON.get(m.group(1), "⚪")
    else:
        # Fallback: read the leading severity emoji (robust to text corruption).
        for ic in ("🔴", "🟠", "🟡", "⚪"):
            if report.startswith(ic):
                p["sev_icon"] = ic
                p["sev"] = _ICON_SEV.get(ic)
                break
    if m := _RE_CAT.search(report):
        p["cat"] = m.group(1).strip()
    if m := _RE_METRIC.search(report):
        p["metric"] = m.group(1)
    if m := _RE_CURRENT.search(report):
        try:
            p["current"] = float(m.group(1))
        except ValueError:
            pass
    if m := _RE_BASELINE.search(report):
        try:
            p["mu"], p["sigma"] = float(m.group(1)), float(m.group(2))
        except ValueError:
            pass
    if m := _RE_Z.search(report):
        try:
            p["z"] = float(m.group(1))
        except ValueError:
            pass
    return p


def _label_for(trigger: str, parsed: dict) -> str:
    """Human-readable Hebrew label for a trigger group."""
    if trigger in _TRIGGER_LABELS:
        icon, label = _TRIGGER_LABELS[trigger]
        return f"{icon} {label}"
    cat = parsed.get("cat")
    if cat in _CAT_HEBREW:
        icon, name = _CAT_HEBREW[cat]
        metric = parsed.get("metric") or trigger
        return f"{icon} {name} — {metric}"
    return f"📌 {trigger}"


def _hhmm(ts: str) -> str:
    """Extract HH:MM from a timestamp (ISO or DD/MM HH:MM)."""
    if m := _RE_TIME.search(ts):
        return m.group(1)
    return ts


def format_daily_summary(alerts: list, max_alerts: int = 10) -> str:
    """מעצב התראות לדוח יומי — מקובץ לפי trigger עם חומרה, שיא z, baseline וסיכום ניהולי.

    Each alert tuple: (ts, trigger, report). The `report` field carries the rich
    per-alert text (severity icon, Hebrew category, current value, baseline μ/σ,
    z-score); we parse it instead of dumping bare timestamps.
    """
    if not alerts:
        return "📭 אין התראות ב-24 השעות האחרונות"

    groups: dict[str, list[tuple[str, dict]]] = {}
    for ts, trigger, report in alerts:
        parsed = _parse_alert_report(report)
        groups.setdefault(trigger, []).append((ts, parsed))

    # Executive summary: severity split + dominant group.
    sev_counts: dict[str, int] = {}
    for items in groups.values():
        for _, p in items:
            sev_counts[p["sev_icon"]] = sev_counts.get(p["sev_icon"], 0) + 1
    sev_str = " · ".join(f"{ic} {sev_counts[ic]}" for ic in ("🔴", "🟠", "🟡", "⚪") if sev_counts.get(ic))
    dominant = max(groups.items(), key=lambda kv: len(kv[1]))

    lines = [f"🚨 התראות 24 שעות ({len(alerts)} התראות)"]
    if sev_str:
        lines.append(f"חומרה: {sev_str}")
    lines.append(f"דומיננטית: {_label_for(dominant[0], dominant[1][0][1])} ({len(dominant[1])})")
    lines.append("")

    for trigger, items in sorted(groups.items(), key=lambda x: -len(x[1])):
        label = _label_for(trigger, items[0][1])
        lines.append(f"{label} ({len(items)})")
        # Peak by z-score (fallback: current value), with its time.
        peak = max(items, key=lambda it: (it[1]["z"] if it[1]["z"] is not None else -1e9, it[1]["current"] or -1e9))
        pts, pp = peak
        if pp["current"] is not None:
            peak_bits = [f"שיא: {pp['current']:.1f}%"]
            if pp["z"] is not None:
                peak_bits.append(f"z={pp['z']:.1f}")
            peak_bits.append(f"@ {_hhmm(pts)}")
            if pp["mu"] is not None and pp["sigma"] is not None:
                peak_bits.append(f"· בסיס μ={pp['mu']:.1f} σ={pp['sigma']:.1f}")
            lines.append("   " + " ".join(peak_bits))
        # Compact time list (newest first — alerts come DESC from DB).
        times = [_hhmm(ts) for ts, _ in items[:max_alerts]]
        if times:
            tail = f" +{len(items) - max_alerts}" if len(items) > max_alerts else ""
            lines.append("   " + " ".join(times) + tail)
        lines.append("")

    return "\n".join(lines).rstrip()
