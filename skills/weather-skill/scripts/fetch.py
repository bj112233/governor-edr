"""Fetch weather forecast and air-quality data from Open-Meteo APIs."""

import requests

from constants import AIR_QUALITY_URL, FORECAST_URL


def fetch_weather(lat: float, lon: float) -> dict:
    """Fetch current + 7-day forecast (incl. UV index)."""
    params = {
        "latitude": lat,
        "longitude": lon,
        "current": "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m,uv_index",
        "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_sum,wind_speed_10m_max,uv_index_max",
        "timezone": "auto",
        "forecast_days": 7,
    }
    r = requests.get(FORECAST_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def fetch_air_quality(lat: float, lon: float) -> dict:
    """European AQI + PM2.5 / PM10 / NO2 / O3 / SO2."""
    params = {
        "latitude": lat,
        "longitude": lon,
        "current": "european_aqi,pm10,pm2_5,nitrogen_dioxide,sulphur_dioxide,ozone,carbon_monoxide,uv_index",
        "timezone": "auto",
    }
    r = requests.get(AIR_QUALITY_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()
