"""Route command implementation — endpoint resolution, routing cascade, output formatting.

Extracted from geocode.py. _cmd_route_impl was F(54) CC.
"""
import logging
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

try:
    from geo_clients import forward, here_route
    from geo_math import fmt_hours, haversine
    from geo_state import HEADERS, OSRM
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from geo_clients import forward, here_route
    from geo_math import fmt_hours, haversine
    from geo_state import HEADERS, OSRM

load_dotenv()

logger = logging.getLogger(__name__)

HERE_API_KEY = os.getenv("HERE_API_KEY")


def _resolve_endpoints(args, is_alternative: bool, last_ctx: dict):
    """Resolve route endpoints from args or saved context.

    Returns (lat1, lon1, lat2, lon2, a_name, b_name) or error string.
    """
    if is_alternative:
        if last_ctx.get("from") and last_ctx.get("to"):
            lat1, lon1 = last_ctx["from_lat"], last_ctx["from_lon"]
            lat2, lon2 = last_ctx["to_lat"], last_ctx["to_lon"]
            args.alternatives = 1
            return lat1, lon1, lat2, lon2, last_ctx["from"], last_ctx["to"]
        return "❌ אין מסלול קודם בזיכרון. קודם צריך לבקש מסלול ראשי עם route."

    if args.frm and args.to:
        a = forward(args.frm)
        b = forward(args.to)
        if not a or not b:
            return "❌ אחת הכתובות לא נמצאה"
        return (
            float(a["lat"]), float(a["lon"]),
            float(b["lat"]), float(b["lon"]),
            a.get("display_name", args.frm), b.get("display_name", args.to),
        )

    if None in (args.from_lat, args.from_lon, args.to_lat, args.to_lon):
        return "❌ דורש --from + --to (כתובות) או --from-lat/lon + --to-lat/lon"
    lat1, lon1 = args.from_lat, args.from_lon
    lat2, lon2 = args.to_lat, args.to_lon
    return lat1, lon1, lat2, lon2, f"({lat1}, {lon1})", f"({lat2}, {lon2})"


def _geocode_waypoints(args):
    """Geocode waypoint addresses to coordinate tuples."""
    if not getattr(args, "waypoints", None):
        return None
    waypoints = []
    for wp in args.waypoints:
        wp_res = forward(wp)
        if wp_res:
            waypoints.append((float(wp_res["lat"]), float(wp_res["lon"])))
    return waypoints


def _try_here_routing(lat1, lon1, lat2, lon2, waypoints, alternatives):
    """Tier 1: HERE Traffic API. Returns (ok, km, minutes, incidents, traffic_delay, traffic_percent, alt_routes)."""
    if not HERE_API_KEY:
        return False, 0.0, 0.0, [], 0.0, 0, []
    return here_route(lat1, lon1, lat2, lon2, waypoints=waypoints, alternatives=alternatives)


def _try_osrm_routing(lat1, lon1, lat2, lon2, args):
    """Tier 2: OSRM. Returns (ok, km, minutes, annotations_data)."""
    profile = (args.profile or "driving").lower()
    url = f"{OSRM}/route/v1/{profile}/{lon1},{lat1};{lon2},{lat2}"
    try:
        params = {"overview": "false"}
        if getattr(args, "annotations", False):
            params["annotations"] = "true"
        r = requests.get(url, params=params, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("code") == "Ok" and data.get("routes"):
            route = data["routes"][0]
            km = route["distance"] / 1000.0
            minutes = route["duration"] / 60.0
            annotations_data = None
            if "legs" in route and route["legs"]:
                annotations_data = route["legs"][0].get("annotation")
            return True, km, minutes, annotations_data
    except Exception as e:
        logger.warning(f"[Geocode] OSRM error: {e}")
    return False, 0.0, 0.0, None


def _format_alt_routes(alt_routes, km, minutes):
    """Format alternative routes section."""
    if not alt_routes:
        return ""
    output = "\n\n## 🔀 מסלולים חלופיים\n\n"
    for i, alt in enumerate(alt_routes, 1):
        alt_time = fmt_hours(alt["minutes"])
        diff_km = alt["km"] - km
        diff_min = alt["minutes"] - minutes
        diff_str = ""
        if diff_min > 0:
            diff_str = f' (+{diff_min:.0f} דק\', +{diff_km:.0f} ק"מ)'
        elif diff_min < 0:
            diff_str = f' ({abs(diff_min):.0f} דק\' פחות, {diff_km:.0f} ק"מ)'
        output += f'{i}. **{alt["km"]:.0f} ק"מ, {alt_time}**{diff_str}'
        if alt["traffic_delay"] > 1:
            output += f" | +{alt['traffic_delay']:.0f}דק' עומסים"
        output += "\n"
    return output


def _format_incidents(incidents):
    """Format traffic incidents section."""
    if not incidents:
        return ""
    output = "\n\n## 🚨 עומסים/תקלות בדרך\n\n"
    for inc in incidents[:3]:
        desc_raw = inc.get("description", "תקלה לא ידועה")
        if isinstance(desc_raw, dict):
            desc = desc_raw.get("value", "תקלה לא ידועה")
        else:
            desc = str(desc_raw)
        inc_type = inc.get("type", "Unknown")
        output += f"- **{inc_type}:** {desc}\n"
    if len(incidents) > 3:
        output += f"\n_... ועוד {len(incidents) - 3} התראות_"
    return output


def _format_annotations(annotations_data):
    """Format OSRM annotations section."""
    if not (
        annotations_data
        and annotations_data.get("distance")
        and annotations_data.get("duration")
        and annotations_data.get("speed")
    ):
        return ""
    output = "\n\n## 📊 פירוט מקטעים\n\n"
    distances = annotations_data["distance"]
    durations = annotations_data["duration"]
    speeds = annotations_data["speed"]

    if speeds:
        avg_speed = sum(speeds) / len(speeds)
        max_speed = max(speeds)
        min_speed = min(s for s in speeds if s > 0)
        output += f"- **מהירות ממוצעת:** {avg_speed:.1f} קמ/ש\n"
        output += f"- **מהירות מקסימלית:** {max_speed:.1f} קמ/ש\n"
        output += f"- **מהירות מינימלית:** {min_speed:.1f} קמ/ש\n"

    num_segments = min(len(distances), 5)
    output += f"\n### מקטעים (ראשונים {num_segments}):\n\n"
    for i in range(num_segments):
        output += f"{i+1}. {distances[i]:.0f}m, {durations[i]:.1f}s, {speeds[i]:.1f} קמ/ש\n"
    if len(distances) > 5:
        output += f"\n_... ועוד {len(distances) - 5} מקטעים_"
    return output


def _build_route_output(
    here_ok, osrm_ok, km, minutes, traffic_delay, traffic_percent,
    incidents, annotations_data, alt_routes, waypoints,
    a_name, b_name, lat1, lon1, lat2, lon2, is_alternative,
):
    """Build the conversational route output string."""
    base_minutes = minutes - traffic_delay if traffic_delay > 0 else minutes
    time_with_traffic = fmt_hours(minutes)
    time_without_traffic = fmt_hours(base_minutes)

    source = "🚦 HERE Traffic" if here_ok else "🗺️ OSRM"
    route_type = "🔄 מסלול חלופי" if is_alternative else f"🛣️ מסלול ראשי ({source})"
    a_short = a_name.split(",")[0] if "," in a_name else a_name
    b_short = b_name.split(",")[0] if "," in b_name else b_name
    output = f"{route_type}: {a_short} → {b_short}\n\n"
    output += f'📍 **מרחק:** כ-{km:.0f} ק"מ\n'

    if here_ok:
        output += f"⏱️ **זמן נסיעה עם תנועה:** {time_with_traffic}"
        if traffic_delay > 1:
            output += f" (+{traffic_delay:.0f} דקות יתרה בגלל עומסים)\n"
            output += f"🕐 **בשעה ללא תנועה:** {time_without_traffic}\n"
        else:
            output += "\n"
    else:
        output += f"⏱️ **זמן נסיעה משוער:** {time_with_traffic}\n"

    waze_url = f"https://www.waze.com/ul?ll={lat2},{lon2}&navigate=yes"
    osm_route_coords = [f"{lat1}%2C{lon1}"]
    if waypoints:
        for wp in waypoints:
            osm_route_coords.append(f"{wp[0]}%2C{wp[1]}")
    osm_route_coords.append(f"{lat2}%2C{lon2}")
    osm_url = f"https://www.openstreetmap.org/directions?engine=fossgis_osrm_car&route={'%3B'.join(osm_route_coords)}"
    output += f"\n🚗 [ניווט ב-Waze]({waze_url}) | 🗺️ [מפת OSM]({osm_url})"

    output += _format_alt_routes(alt_routes, km, minutes)

    if traffic_percent > 50:
        output += "\n\n⚠️ **שים לב:** יש עומסים משמעותיים בדרך. מומלץ לצאת מוקדם יותר או לבדוק מסלול חלופי."

    output += _format_incidents(incidents)
    output += _format_annotations(annotations_data)
    return output


def cmd_route_impl(args, is_alternative: bool, last_ctx: dict, save_ctx_fn):
    """Actual implementation of cmd_route.

    Args:
        args: argparse namespace
        is_alternative: whether this is an "alternative" subcommand
        last_ctx: the _last_route_context[0] dict
        save_ctx_fn: callable to save context (no-op if is_alternative)
    """
    endpoints = _resolve_endpoints(args, is_alternative, last_ctx)
    if isinstance(endpoints, str):
        return endpoints
    lat1, lon1, lat2, lon2, a_name, b_name = endpoints

    waypoints = _geocode_waypoints(args) if HERE_API_KEY else None
    alternatives = getattr(args, "alternatives", 0)

    here_ok, km, minutes, incidents, traffic_delay, traffic_percent, alt_routes = (
        _try_here_routing(lat1, lon1, lat2, lon2, waypoints, alternatives)
    )

    annotations_data = None
    if not here_ok:
        osrm_ok, km, minutes, annotations_data = _try_osrm_routing(lat1, lon1, lat2, lon2, args)
        if not osrm_ok:
            km = haversine(lat1, lon1, lat2, lon2)
            minutes = (km / 60.0) * 60
            return (
                "# מרחק משוער (רק חישוב קו אווירי)\n\n"
                f"- **מ:** {a_name}\n"
                f"- **אל:** {b_name}\n"
                f'- **מרחק קו אווירי:** **{km:.2f} ק"מ**\n'
                f"- **זמן נסיעה משוער:** **~{minutes:.0f} דק'** (הערכה @ 60 קמ/ש)\n"
                "- _הערה: HERE ו-OSRM לא זמינים - משתמש בחישוב haversine._"
            )

    output = _build_route_output(
        here_ok, True, km, minutes, traffic_delay, traffic_percent,
        incidents, annotations_data, alt_routes, waypoints,
        a_name, b_name, lat1, lon1, lat2, lon2, is_alternative,
    )

    if not is_alternative:
        last_ctx.clear()
        last_ctx.update({
            "from": a_name, "to": b_name,
            "from_lat": lat1, "from_lon": lon1,
            "to_lat": lat2, "to_lon": lon2,
        })
        save_ctx_fn()

    return output
