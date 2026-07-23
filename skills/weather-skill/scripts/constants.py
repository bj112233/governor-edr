"""Shared constants for the weather skill (URLs, WMO codes, regex)."""

import re

GEOCODE_URL = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST_URL = "https://api.open-meteo.com/v1/forecast"
AIR_QUALITY_URL = "https://air-quality-api.open-meteo.com/v1/air-quality"
NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"

# WMO Weather interpretation codes -> Hebrew description + emoji
WMO_CODES = {
    0: ("☀️", "בהיר"),
    1: ("🌤️", "בהיר ברובו"),
    2: ("⛅", "מעונן חלקית"),
    3: ("☁️", "מעונן"),
    45: ("🌫️", "ערפל"),
    48: ("🌫️", "ערפל קרח"),
    51: ("🌦️", "טפטוף קל"),
    53: ("🌦️", "טפטוף בינוני"),
    55: ("🌦️", "טפטוף חזק"),
    61: ("🌧️", "גשם קל"),
    63: ("🌧️", "גשם בינוני"),
    65: ("🌧️", "גשם חזק"),
    71: ("🌨️", "שלג קל"),
    73: ("🌨️", "שלג בינוני"),
    75: ("❄️", "שלג חזק"),
    80: ("🌦️", "ממטרים קלים"),
    81: ("🌧️", "ממטרים"),
    82: ("⛈️", "ממטרים חזקים"),
    95: ("⛈️", "סופת רעמים"),
    96: ("⛈️", "סופת רעמים עם ברד"),
    99: ("⛈️", "סופת רעמים חזקה עם ברד"),
}

_HEBREW_RE = re.compile(r"[\u0590-\u05FF]")
