"""Network I/O clients for geocode skill — Nominatim + HERE API calls.

State/cache/rate-limiting extracted to geo_state.py (SRP).
"""
import logging
from datetime import datetime
from typing import Dict, List, Tuple

import requests
from dotenv import load_dotenv

from geo_state import (
    EARTH_RADIUS_KM,
    HEADERS,
    HERE_API_KEY,
    HERE_GEOCODE,
    HERE_ROUTING,
    HERE_TIME_AWARE_ENABLED,
    NOMINATIM,
    OSRM,
    _here_rate_limit,
    _here_time_aware_rate_limit,
    _load_cache,
    _save_cache,
    _throttle_nominatim,
)

load_dotenv()

logger = logging.getLogger(__name__)


def forward(address: str) -> dict | None:
    """Forward geocode with disk-based cache (Nominatim caching is permitted)."""
    cache = _load_cache()
    key = address.strip().lower()
    if key in cache.get("forward", {}):
        return cache["forward"][key]
    _throttle_nominatim()
    params = {"q": address, "format": "json", "limit": 1, "accept-language": "he,en"}
    try:
        r = requests.get(f"{NOMINATIM}/search", params=params, headers=HEADERS, timeout=10)
        r.raise_for_status()
        results = r.json()
        result = results[0] if results else None
        cache.setdefault("forward", {})[key] = result
        _save_cache(cache)
        return result
    except Exception as e:
        logger.warning("[Geocode] Nominatim forward error: %s", e)
    return None


def here_forward(address: str) -> dict | None:
    """HERE Geocoding API — more accurate for some addresses."""
    if not HERE_API_KEY:
        return None
    if not _here_rate_limit():
        return None
    params = {"q": address, "apiKey": HERE_API_KEY, "limit": 1, "lang": "he,en"}
    try:
        r = requests.get(HERE_GEOCODE, params=params, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()
        if "items" in data and data["items"]:
            item = data["items"][0]
            pos = item.get("position", {})
            address_data = item.get("address", {})
            return {
                "lat": str(pos.get("lat")),
                "lon": str(pos.get("lng")),
                "display_name": item.get("title", address),
                "type": address_data.get("entityType", "place"),
                "class": address_data.get("label", "—"),
                "osm_type": "here",
                "osm_id": item.get("id", "—"),
            }
    except Exception as e:
        logger.warning("[Geocode] HERE geocode error: %s", e)
    return None


def reverse(lat: float, lon: float) -> dict | None:
    """Reverse geocode with disk-based cache (Nominatim caching is permitted)."""
    cache = _load_cache()
    key = f"{round(float(lat), 5)},{round(float(lon), 5)}"
    if key in cache.get("reverse", {}):
        return cache["reverse"][key]
    _throttle_nominatim()
    params = {"lat": lat, "lon": lon, "format": "json", "accept-language": "he,en"}
    try:
        r = requests.get(f"{NOMINATIM}/reverse", params=params, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()
        cache.setdefault("reverse", {})[key] = data
        _save_cache(cache)
        return data
    except Exception as e:
        logger.warning("[Geocode] Nominatim reverse error: %s", e)
    return None


def _parse_route(route: dict) -> tuple[float, float, float, int, list]:
    """Parse a HERE route section into (km, minutes, traffic_delay_min, traffic_pct, incidents)."""
    total_length = 0
    total_duration = 0
    total_base_duration = 0
    all_incidents = []
    for section in route["sections"]:
        summary = section.get("summary", {})
        total_length += summary.get("length", 0)
        section_incidents = section.get("incidents", [])
        if section_incidents:
            all_incidents.extend(section_incidents)
        travel_summary = section.get("travelSummary", {})
        if travel_summary:
            total_duration += travel_summary.get("duration", 0)
            total_base_duration += travel_summary.get("baseDuration", 0)
        else:
            total_duration += summary.get("duration", 0)
    km = total_length / 1000.0
    minutes = total_duration / 60.0
    traffic_delay_minutes = 0.0
    traffic_percent = 0
    if total_base_duration > 0:
        traffic_delay_seconds = total_duration - total_base_duration
        if traffic_delay_seconds > 0:
            traffic_delay_minutes = traffic_delay_seconds / 60.0
            traffic_percent = int((traffic_delay_seconds / total_base_duration) * 100)
    return km, minutes, traffic_delay_minutes, traffic_percent, all_incidents


def here_route(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float,
    waypoints: List[Tuple[float, float]] = None,
    alternatives: int = 0,
) -> Tuple[bool, float, float, List[Dict], float, int, List[Dict]]:
    """HERE Routing API v8 with traffic awareness."""
    if not HERE_API_KEY:
        return False, 0.0, 0.0, [], 0.0, 0, []
    if not _here_rate_limit():
        return False, 0.0, 0.0, [], 0.0, 0, []

    param_list = [
        ("transportMode", "car"),
        ("origin", f"{lat1},{lon1}"),
    ]
    if waypoints:
        for wp in waypoints:
            param_list.append(("via", f"{wp[0]},{wp[1]}"))
    param_list.append(("destination", f"{lat2},{lon2}"))
    param_list.append(("return", "summary,travelSummary,incidents,polyline"))

    if HERE_TIME_AWARE_ENABLED and _here_time_aware_rate_limit():
        now_iso = datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S")
        param_list.append(("departureTime", now_iso))
        logger.info("[Geocode] Using Time-Aware Routing with current time")

    param_list.append(("apiKey", HERE_API_KEY))
    if alternatives > 0:
        param_list.append(("alternatives", min(alternatives, 3)))

    try:
        r = requests.get(HERE_ROUTING, params=param_list, headers=HEADERS, timeout=10)
        r.raise_for_status()
        data = r.json()

        if "routes" not in data or not data["routes"]:
            if isinstance(data, dict) and "error" in data:
                logger.warning("[Geocode] HERE error: %s", data["error"])
            return False, 0.0, 0.0, [], 0.0, 0, []

        routes = data["routes"]
        primary = routes[0]
        if "sections" not in primary or not primary["sections"]:
            return False, 0.0, 0.0, [], 0.0, 0, []

        km, minutes, traffic_delay_minutes, traffic_percent, incidents = _parse_route(primary)

        alt_routes = []
        for alt in routes[1:]:
            if "sections" in alt and alt["sections"]:
                a_km, a_min, a_delay, a_pct, _ = _parse_route(alt)
                alt_routes.append({
                    "km": a_km, "minutes": a_min,
                    "traffic_delay": a_delay, "traffic_percent": a_pct,
                })

        logger.info(
            "[Geocode] HERE route: %.1fkm, %.1fmin (+%.0fmin traffic, %d alts)",
            km, minutes, traffic_delay_minutes, len(alt_routes),
        )
        return (True, km, minutes, incidents, traffic_delay_minutes, traffic_percent, alt_routes)
    except Exception as e:
        logger.warning("[Geocode] HERE error: %s", e)

    return False, 0.0, 0.0, [], 0.0, 0, []
