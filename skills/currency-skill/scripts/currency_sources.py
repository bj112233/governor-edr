"""Currency skill source fetchers — cache, 3 API sources, fallback chain.

Extracted from currency.py (SRP).
"""
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

import requests

logger = logging.getLogger(__name__)


class AllSourcesUnavailable(RuntimeError):
    """Raised when every upstream currency API in the fallback chain fails."""


FRANKFURTER_URL = "https://api.frankfurter.app"
EXCHANGERATE_URL = "https://open.er-api.com/v6/latest"
FAWAZAHMED0_BASE = "https://cdn.jsdelivr.net/npm/@fawazahmed0/currency-api@{ver}/v1/currencies/{cur}.json"
PRIMARY_URL = EXCHANGERATE_URL
FALLBACK_URL = FRANKFURTER_URL
_CACHE_TTL_LATEST = int(os.getenv("SENTINEL_CURRENCY_TTL", "3600"))
_CACHE_TTL_HISTORICAL = 30 * 86400


def _cache_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills" / "currency_cache"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _cache_get(key: str, ttl: int) -> dict | None:
    f = _cache_dir() / f"{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"
    if not f.is_file():
        return None
    if time.time() - f.stat().st_mtime > ttl:
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(key: str, data: dict) -> None:
    f = _cache_dir() / f"{hashlib.sha256(key.encode()).hexdigest()[:24]}.json"
    try:
        f.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _fetch_frankfurter_rates(base: str, date: str = "latest") -> dict | None:
    """Fetch from Frankfurter (ECB). ~30 fiat, history from 1999. Returns None on failure."""
    try:
        url = f"{FRANKFURTER_URL}/{date}"
        r = requests.get(url, params={"from": base.upper()}, timeout=10)
        r.raise_for_status()
        data = r.json()
        rates = data.get("rates")
        if not isinstance(rates, dict):
            return None
        return {
            "base": data.get("base", base.upper()),
            "date": data.get("date", date),
            "rates": rates,
            "_source": "ECB (Frankfurter)",
        }
    except requests.exceptions.RequestException as e:
        logger.warning("Frankfurter unavailable: %s", e)
        return None
    except (ValueError, KeyError) as e:
        logger.warning("Frankfurter parse error: %s", e)
        return None


def _fetch_exchangerate_rates(base: str, date: str = "latest") -> dict | None:
    """Fetch from exchangerate-api.com v6 (open.er-api.com). ~160 fiat, latest only."""
    if date != "latest":
        return None
    try:
        url = f"{EXCHANGERATE_URL}/{base.upper()}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("result") != "success":
            return None
        rates = data.get("rates")
        if not isinstance(rates, dict):
            return None
        date_str = "latest"
        utc_str = data.get("time_last_update_utc")
        if utc_str:
            try:
                dt = datetime.strptime(utc_str, "%a, %d %b %Y %H:%M:%S %z")
                date_str = dt.strftime("%Y-%m-%d")
            except Exception:
                pass
        return {
            "base": data.get("base_code", base.upper()),
            "date": date_str,
            "rates": rates,
            "_source": "exchangerate-api.com",
        }
    except requests.exceptions.RequestException as e:
        logger.warning("exchangerate-api unavailable: %s", e)
        return None
    except (ValueError, KeyError) as e:
        logger.warning("exchangerate-api parse error: %s", e)
        return None


def _fetch_fawazahmed0_rates(base: str, date: str = "latest") -> dict | None:
    """Fetch from fawazahmed0/currency-api via jsDelivr CDN. 200+ incl crypto."""
    try:
        ver = "latest" if date == "latest" else date
        cur = base.lower()
        url = FAWAZAHMED0_BASE.format(ver=ver, cur=cur)
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        raw_rates = data.get(cur)
        if not isinstance(raw_rates, dict):
            return None
        rates = {k.upper(): float(v) for k, v in raw_rates.items()}
        rates.pop(base.upper(), None)
        return {
            "base": base.upper(),
            "date": data.get("date", date),
            "rates": rates,
            "_source": "fawazahmed0/currency-api",
        }
    except requests.exceptions.RequestException as e:
        logger.warning("fawazahmed0 unavailable: %s", e)
        return None
    except (ValueError, KeyError) as e:
        logger.warning("fawazahmed0 parse error: %s", e)
        return None


def _fetch_rates_chain(base: str, date: str = "latest", target: str | None = None) -> dict:
    """Try sources in priority order. Target-aware: skips sources lacking target."""
    sources = (_fetch_frankfurter_rates, _fetch_exchangerate_rates, _fetch_fawazahmed0_rates)
    last: dict | None = None
    for fn in sources:
        data = fn(base, date)
        if not data:
            continue
        last = data
        if target is None:
            return data
        if target.upper() in (data.get("rates") or {}):
            return data
    if last is not None:
        return last
    raise AllSourcesUnavailable(
        f"All currency sources failed for base={base.upper()}, date={date}"
    )


def _fetch_primary_rates(base: str) -> dict | None:
    return _fetch_frankfurter_rates(base, "latest") or _fetch_exchangerate_rates(base, "latest")


def _fetch_fallback_rates(base: str, date: str = "latest") -> dict:
    """Legacy alias: Frankfurter first, with hard-fail on its specific error."""
    data = _fetch_frankfurter_rates(base, date)
    if data is not None:
        return data
    url = f"{FRANKFURTER_URL}/{date}"
    r = requests.get(url, params={"from": base.upper()}, timeout=10)
    r.raise_for_status()
    out = r.json()
    out["_source"] = "ECB (Frankfurter)"
    return out
