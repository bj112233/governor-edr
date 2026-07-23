"""Geocoding — resolve city names (Hebrew/Latin) to lat/lon."""

import requests

from constants import GEOCODE_URL, NOMINATIM_URL, _HEBREW_RE


def _geocode_nominatim(query: str) -> dict | None:
    """Fallback to OSM Nominatim — handles Hebrew/Arabic/non-Latin city names
    that Open-Meteo's geocoder does not index."""
    try:
        r = requests.get(
            NOMINATIM_URL,
            params={"q": query, "format": "json", "limit": 1, "accept-language": "he"},
            headers={"User-Agent": "sentinel-weather-skill/1.0"},
            timeout=10,
        )
        r.raise_for_status()
        results = r.json() or []
        if not results:
            return None
        item = results[0]
        display = item.get("display_name", "") or item.get("name", query)
        parts = [p.strip() for p in display.split(",")]
        return {
            "name": item.get("name") or parts[0] or query,
            "country": parts[-1] if parts else "",
            "admin1": parts[-2] if len(parts) >= 2 else "",
            "latitude": float(item["lat"]),
            "longitude": float(item["lon"]),
        }
    except Exception:
        return None


def geocode(query: str, lang: str = "he") -> dict | None:
    """Resolve city name to lat/lon.

    Hebrew (and other non-Latin) queries go straight to Nominatim because
    Open-Meteo's geocoder has limited Hebrew coverage and often returns
    incorrect matches (e.g. mapping \"ראש העין\" to \"בני ברק\").
    Latin queries are tried on Open-Meteo first for speed, with Nominatim
    as fallback.
    """
    # Non-Latin script → Nominatim directly (avoids Open-Meteo mismatch)
    if _HEBREW_RE.search(query):
        return _geocode_nominatim(query)

    params = {"name": query, "count": 1, "language": lang, "format": "json"}
    try:
        r = requests.get(GEOCODE_URL, params=params, timeout=10)
        r.raise_for_status()
        results = r.json().get("results") or []
        if not results:
            # Retry in English (response language only — query is unchanged)
            if lang != "en":
                alt = geocode(query, lang="en")
                if alt:
                    return alt
            # Fallback: OSM Nominatim
            return _geocode_nominatim(query)
        return results[0]
    except Exception:
        return _geocode_nominatim(query)
