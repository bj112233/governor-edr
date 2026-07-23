"""Rendering / formatting commands for geocode skill.

These functions take raw data and produce Markdown output for the LLM/user.
They call geo_clients for upstream data but contain zero orchestration logic.
"""

from pathlib import Path

try:
    from geo_clients import forward, here_forward, reverse
    from geo_math import haversine
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from geo_clients import forward, here_forward, reverse
    from geo_math import haversine


def cmd_forward(address: str) -> str:
    """Address → coordinates (Markdown)."""
    res = forward(address)
    source = "Nominatim (OSM)"
    if not res:
        res = here_forward(address)
        source = "HERE API"
    if not res:
        return f"❌ כתובת לא נמצאה: {address}"
    return (
        f"# 📍 {address}\n\n"
        f"- **שם מלא:** {res.get('display_name', '—')}\n"
        f"- **קואורדינטות:** {res['lat']}, {res['lon']}\n"
        f"- **סוג:** {res.get('type', '—')} ({res.get('class', '—')})\n"
        f"- **OSM ID:** {res.get('osm_type')}/{res.get('osm_id')}\n"
        f"- **מקור:** {source}\n"
        f"- **מפה:** https://www.openstreetmap.org/?mlat={res['lat']}&mlon={res['lon']}&zoom=15"
    )


def cmd_reverse(lat: float, lon: float) -> str:
    """Coordinates → address (Markdown)."""
    res = reverse(lat, lon)
    if not res or "error" in res:
        return f"❌ לא נמצאה כתובת ל-({lat}, {lon})"
    addr = res.get("address", {})
    return (
        f"# 📍 ({lat}, {lon})\n\n"
        f"- **כתובת:** {res.get('display_name', '—')}\n"
        f"- **רחוב:** {addr.get('road', '—')}\n"
        f"- **בית:** {addr.get('house_number', '—')}\n"
        f"- **עיר:** {addr.get('city') or addr.get('town') or addr.get('village', '—')}\n"
        f"- **מדינה:** {addr.get('country', '—')}\n"
        f"- **מיקוד:** {addr.get('postcode', '—')}"
    )


def cmd_bbox(address: str) -> str:
    """Bounding box (Markdown)."""
    res = forward(address)
    if not res or "boundingbox" not in res:
        return f"❌ לא נמצא bounding box ל-{address}"
    bb = res["boundingbox"]  # [south, north, west, east]
    return (
        f"# 📐 Bounding Box — {address}\n\n"
        f"- **דרום:** {bb[0]}\n"
        f"- **צפון:** {bb[1]}\n"
        f"- **מערב:** {bb[2]}\n"
        f"- **מזרח:** {bb[3]}\n"
        f"- **מרכז:** {res.get('lat')}, {res.get('lon')}\n"
        f"- **שם:** {res.get('display_name', '—')}"
    )


def cmd_distance(args) -> str:
    """Distance between two points (Markdown)."""
    if args.frm and args.to:
        a = forward(args.frm)
        b = forward(args.to)
        if not a or not b:
            return "❌ אחת הכתובות לא נמצאה"
        lat1, lon1 = float(a["lat"]), float(a["lon"])
        lat2, lon2 = float(b["lat"]), float(b["lon"])
        a_name = a.get("display_name", args.frm)
        b_name = b.get("display_name", args.to)
    else:
        if None in (args.from_lat, args.from_lon, args.to_lat, args.to_lon):
            return "❌ דורש --from + --to (כתובות) או --from-lat/lon + --to-lat/lon"
        lat1, lon1 = args.from_lat, args.from_lon
        lat2, lon2 = args.to_lat, args.to_lon
        a_name = f"({lat1}, {lon1})"
        b_name = f"({lat2}, {lon2})"
    km = haversine(lat1, lon1, lat2, lon2)
    return (
        f"# 📏 מרחק קו אווירי\n\n"
        f"- **מ:** {a_name}\n"
        f"- **אל:** {b_name}\n"
        f'- **מרחק:** **{km:.2f} ק"מ** ({km * 0.621371:.2f} מייל)\n'
        f"- _הערה: זה מרחק haversine (great-circle), לא מרחק נסיעה._"
    )
