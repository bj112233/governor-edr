"""Alert evaluation and parsing for --alert-on rules."""

import re

_DAILY_FIELD_MAP = {
    "wind_speed_10m": "wind_speed_10m_max",
    "precipitation": "precipitation_sum",
    "temperature_2m": "temperature_2m_max",
    "uv_index": "uv_index_max",
}


def _check_threshold(op: str, threshold: float, value: float) -> bool:
    """Check if value crosses threshold per operator."""
    return (op == ">" and value > threshold) or (op == "<" and value < threshold)


def _check_current(cur: dict, field: str, op: str, threshold: float) -> list[str]:
    """Check current conditions — returns alert strings."""
    if field not in cur or cur[field] is None:
        return []
    if _check_threshold(op, threshold, float(cur[field])):
        return [f"⚠️  {field} {op} {threshold} (עכשיו: {cur[field]})"]
    return []


def _check_daily(daily: dict, field: str, op: str, threshold: float) -> list[str]:
    """Check daily forecast array — returns alert strings."""
    daily_field = _DAILY_FIELD_MAP.get(field, field)
    arr = daily.get(daily_field) or []
    days = daily.get("time") or []
    alerts: list[str] = []
    for i, v in enumerate(arr):
        if v is None:
            continue
        try:
            if _check_threshold(op, threshold, float(v)):
                when = days[i] if i < len(days) else f"+{i}d"
                alerts.append(f"⚠️  {field} {op} {threshold} ({when}: {v})")
        except (TypeError, ValueError):
            continue
    return alerts


def evaluate_alerts(data: dict, conditions: list[tuple[str, str, float]]) -> list[str]:
    """Run --alert-on rules. condition tuple = (field, op, value).

    Operators: '>' or '<'. Fields scanned across daily arrays + current.
    Returns list of human-readable alert strings.
    """
    cur = data.get("current") or {}
    daily = data.get("daily") or {}
    alerts: list[str] = []
    for field, op, threshold in conditions:
        alerts.extend(_check_current(cur, field, op, threshold))
        alerts.extend(_check_daily(daily, field, op, threshold))
    return alerts


def parse_alert_spec(spec: str) -> list[tuple[str, str, float]]:
    """Parse '--alert-on rain>10,wind>50,temperature<5' into condition tuples."""
    conditions = []
    aliases = {
        "rain": "precipitation",
        "wind": "wind_speed_10m",
        "temp": "temperature_2m",
        "uv": "uv_index",
    }
    for raw in (spec or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        m = re.match(r"^([a-zA-Z_]+)\s*([<>])\s*([\d.]+)$", raw)
        if not m:
            continue
        field = aliases.get(m.group(1).lower(), m.group(1))
        conditions.append((field, m.group(2), float(m.group(3))))
    return conditions
