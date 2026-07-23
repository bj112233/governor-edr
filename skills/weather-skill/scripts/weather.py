"""Weather forecast via Open-Meteo (free, no API key required).

Facade module — re-exports the public API from the split submodules so
existing imports (`from weather import *`, `from weather import geocode`)
continue to work unchanged.
"""

from alerts import evaluate_alerts, parse_alert_spec
from cli import main
from constants import (
    AIR_QUALITY_URL,
    FORECAST_URL,
    GEOCODE_URL,
    NOMINATIM_URL,
    WMO_CODES,
)
from fetch import fetch_air_quality, fetch_weather
from format import format_air_quality_md, format_md
from geocode import geocode

__all__ = [
    # constants
    "GEOCODE_URL",
    "FORECAST_URL",
    "AIR_QUALITY_URL",
    "NOMINATIM_URL",
    "WMO_CODES",
    # geocoding
    "geocode",
    # fetching
    "fetch_weather",
    "fetch_air_quality",
    # formatting
    "format_md",
    "format_air_quality_md",
    # alerts
    "evaluate_alerts",
    "parse_alert_spec",
    # CLI
    "main",
]

if __name__ == "__main__":
    main()
