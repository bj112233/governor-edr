"""Format weather and air-quality data as Markdown."""

from datetime import datetime

from constants import WMO_CODES


def format_air_quality_md(loc: dict, data: dict) -> str:
    cur = data.get("current") or {}
    aqi = cur.get("european_aqi")
    if aqi is None:
        return "❌ אין נתוני איכות אוויר עבור מיקום זה."
    if aqi < 20:
        verdict = "🟢 מצוין"
    elif aqi < 40:
        verdict = "🟡 טוב"
    elif aqi < 60:
        verdict = "🟠 בינוני"
    elif aqi < 80:
        verdict = "🔴 ירוד"
    else:
        verdict = "🟣 גרוע מאוד"
    name = loc.get("name", "—")
    return (
        f"# 🌫️ איכות אוויר — {name}\n\n"
        f"- **AQI אירופי:** {aqi:.0f} — {verdict}\n"
        f"- **PM2.5:** {cur.get('pm2_5')} µg/m³\n"
        f"- **PM10:** {cur.get('pm10')} µg/m³\n"
        f"- **NO₂:** {cur.get('nitrogen_dioxide')} µg/m³\n"
        f"- **O₃:** {cur.get('ozone')} µg/m³\n"
        f"- **SO₂:** {cur.get('sulphur_dioxide')} µg/m³\n"
        f"- **CO:** {cur.get('carbon_monoxide')} µg/m³\n"
        f"- **UV index:** {cur.get('uv_index')}"
    )


def format_md(loc: dict, data: dict) -> str:
    cur = data.get("current", {})
    daily = data.get("daily", {})
    code = cur.get("weather_code", 0)
    emoji, desc = WMO_CODES.get(code, ("🌡️", f"קוד {code}"))

    name = loc.get("name", "—")
    country = loc.get("country", "")
    admin1 = loc.get("admin1", "")
    location_str = f"{name}, {admin1}".strip(", ") if admin1 else name
    if country:
        location_str += f" ({country})"

    lines = [
        f"# 🌤️ מזג אוויר — {location_str}",
        f"_עודכן: {datetime.now().strftime('%d/%m/%Y %H:%M')}_\n",
        "## עכשיו",
        f"- **{emoji} {desc}**",
        f"- 🌡️ טמפרטורה: **{cur.get('temperature_2m', '—')}°C** "
        f"(תחושה {cur.get('apparent_temperature', '—')}°C)",
        f"- 💧 לחות: {cur.get('relative_humidity_2m', '—')}%",
        f'- 💨 רוח: {cur.get("wind_speed_10m", "—")} קמ"ש',
        f'- 🌧️ משקעים: {cur.get("precipitation", 0)} מ"מ',
        "",
        "## תחזית 7 ימים",
        "| תאריך | מזג אוויר | מקס | מינ | משקעים |",
        "|--------|-----------|------|------|---------|",
    ]
    days = daily.get("time", [])
    for i, d in enumerate(days):
        c = daily.get("weather_code", [0] * len(days))[i]
        e, dsc = WMO_CODES.get(c, ("🌡️", "—"))
        tmax = daily.get("temperature_2m_max", [None] * len(days))[i]
        tmin = daily.get("temperature_2m_min", [None] * len(days))[i]
        prec = daily.get("precipitation_sum", [0] * len(days))[i]
        try:
            day_str = datetime.fromisoformat(d).strftime("%a %d/%m")
        except Exception:
            day_str = d
        lines.append(f'| {day_str} | {e} {dsc} | {tmax}° | {tmin}° | {prec} מ"מ |')
    return "\n".join(lines)
