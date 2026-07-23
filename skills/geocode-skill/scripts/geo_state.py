"""Geocode skill state management — constants, disk cache, rate limiting.

Extracted from geo_clients.py (SRP).
"""
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Constants ──
NOMINATIM = "https://nominatim.openstreetmap.org"
OSRM = os.getenv("SENTINEL_OSRM_URL", "https://router.project-osrm.org")
HEADERS = {"User-Agent": "tactical_bot/1.0 (+https://github.com/)"}
EARTH_RADIUS_KM = 6371.0
_NOMINATIM_MIN_INTERVAL = 1.1

HERE_API_KEY = os.getenv("HERE_API_KEY") or ""
HERE_ROUTING = "https://router.hereapi.com/v8/routes"
HERE_GEOCODE = "https://geocode.search.hereapi.com/v1/geocode"

_HERE_MONTHLY_CAP = int(os.getenv("HERE_MONTHLY_CAP", "25000"))
HERE_TIME_AWARE_ENABLED = os.getenv("HERE_TIME_AWARE_ENABLED", "false").lower() == "true"
HERE_TIME_AWARE_CAP = int(os.getenv("HERE_TIME_AWARE_CAP", "4500"))

_STATE_TMP_SUFFIX = ".tmp"


# ── State / Cache I/O ──
def _state_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills" / "geocode"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _geocode_state_file() -> Path:
    return _state_dir() / "geocode_state.json"


def _nominatim_cache_file() -> Path:
    return _state_dir() / "nominatim_cache.json"


def _current_month_key() -> str:
    return datetime.utcnow().strftime("month_%Y_%m")


def _load_state() -> dict:
    try:
        f = _geocode_state_file()
        if f.exists():
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                data.setdefault("last_nominatim_time", 0.0)
                data.setdefault("here_monthly_calls", {})
                data.setdefault("here_time_aware_calls", {})
                return data
    except Exception as e:
        logger.warning("[Geocode] state read failed: %s", e)
    return {
        "last_nominatim_time": 0.0,
        "here_monthly_calls": {},
        "here_time_aware_calls": {},
    }


def _save_state(state: dict) -> None:
    try:
        f = _geocode_state_file()
        tmp = f.with_suffix(f.suffix + _STATE_TMP_SUFFIX)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, f)
    except Exception as e:
        logger.warning("[Geocode] state write failed: %s", e)


def _load_cache() -> dict:
    try:
        f = _nominatim_cache_file()
        if f.exists():
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                data.setdefault("forward", {})
                data.setdefault("reverse", {})
                return data
    except Exception as e:
        logger.warning("[Geocode] cache read failed: %s", e)
    return {"forward": {}, "reverse": {}}


def _save_cache(cache: dict) -> None:
    try:
        for k in ("forward", "reverse"):
            bucket = cache.get(k, {})
            if len(bucket) > 512:
                items = list(bucket.items())
                cache[k] = dict(items[-256:])
        f = _nominatim_cache_file()
        tmp = f.with_suffix(f.suffix + _STATE_TMP_SUFFIX)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, ensure_ascii=False)
        os.replace(tmp, f)
    except Exception as e:
        logger.warning("[Geocode] cache write failed: %s", e)


# ── Rate limiting ──
def _here_rate_limit() -> bool:
    state = _load_state()
    month = _current_month_key()
    counts = state.setdefault("here_monthly_calls", {})
    current = int(counts.get(month, 0))
    if current >= _HERE_MONTHLY_CAP:
        logger.warning("[Geocode] HERE monthly cap exceeded: %d/%d", current, _HERE_MONTHLY_CAP)
        return False
    counts[month] = current + 1
    _save_state(state)
    return True


def _here_time_aware_rate_limit() -> bool:
    state = _load_state()
    month = _current_month_key()
    counts = state.setdefault("here_time_aware_calls", {})
    current = int(counts.get(month, 0))
    if current >= HERE_TIME_AWARE_CAP:
        logger.warning("[Geocode] HERE Time-Aware monthly cap exceeded: %d/%d", current, HERE_TIME_AWARE_CAP)
        return False
    counts[month] = current + 1
    _save_state(state)
    return True


def _throttle_nominatim() -> None:
    state = _load_state()
    last = float(state.get("last_nominatim_time", 0.0))
    now = time.time()
    delta = now - last
    if delta < _NOMINATIM_MIN_INTERVAL:
        time.sleep(_NOMINATIM_MIN_INTERVAL - delta)
    state["last_nominatim_time"] = time.time()
    _save_state(state)
