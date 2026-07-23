"""Quote fetching with multi-source fallback.

Source priority for snapshot quotes:
  1. Finnhub (real-time US, 60 calls/min free) — only if FINNHUB_API_KEY is set.
  2. yfinance (Yahoo Finance, free, no key) — always available, used as fallback
     and for non-quote calls (history, news, crypto pairs).
"""

import os
import sys

import requests

from _stocks_utils import _safe, yf

_FINNHUB_KEY = os.getenv("FINNHUB_API_KEY", "").strip()
_FINNHUB_BASE = "https://finnhub.io/api/v1"
_FINNHUB_TIMEOUT = 8


def _finnhub_quote(symbol: str) -> dict | None:
    """Real-time quote via Finnhub. Returns None if key missing or request fails.

    Endpoint shape: {c, d, dp, h, l, o, pc, t}
      c  = current price, d = change, dp = change percent,
      h  = day high, l = day low, o = day open, pc = previous close, t = ts.
    """
    if not _FINNHUB_KEY:
        return None
    try:
        r = requests.get(
            f"{_FINNHUB_BASE}/quote",
            params={"symbol": symbol.upper(), "token": _FINNHUB_KEY},
            timeout=_FINNHUB_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json() or {}
        # Finnhub returns c=0 for unknown symbols — treat as miss.
        if not d.get("c"):
            return None
        return d
    except Exception as exc:
        if os.getenv("SENTINEL_DEBUG_FINNHUB"):
            import traceback as _tb

            print(f"[finnhub_quote] {type(exc).__name__}: {exc}", file=sys.stderr)
            _tb.print_exc()
        return None


def _finnhub_profile(symbol: str) -> dict | None:
    """Company profile via Finnhub. Returns name, currency, market cap (USD millions)."""
    if not _FINNHUB_KEY:
        return None
    try:
        r = requests.get(
            f"{_FINNHUB_BASE}/stock/profile2",
            params={"symbol": symbol.upper(), "token": _FINNHUB_KEY},
            timeout=_FINNHUB_TIMEOUT,
        )
        r.raise_for_status()
        d = r.json() or {}
        return d if d.get("name") else None
    except Exception:
        return None


def _finnhub_basic_financials(symbol: str) -> dict | None:
    """Basic fundamentals (P/E, 52W high/low). Free tier supports US tickers."""
    if not _FINNHUB_KEY:
        return None
    try:
        r = requests.get(
            f"{_FINNHUB_BASE}/stock/metric",
            params={
                "symbol": symbol.upper(),
                "metric": "all",
                "token": _FINNHUB_KEY,
            },
            timeout=_FINNHUB_TIMEOUT,
        )
        r.raise_for_status()
        d = (r.json() or {}).get("metric") or {}
        return d or None
    except Exception:
        return None


def _quote_via_finnhub(symbol: str) -> dict | None:
    """Compose full quote dict from Finnhub endpoints. None if unavailable."""
    fq = _finnhub_quote(symbol)
    if fq is None:
        return None
    profile = _finnhub_profile(symbol) or {}
    metric = _finnhub_basic_financials(symbol) or {}
    market_cap_m = profile.get("marketCapitalization")  # millions of currency
    market_cap = float(market_cap_m) * 1e6 if market_cap_m else None
    # Finnhub reports 10-day avg trading volume in *millions of shares*.
    vol_m = metric.get("10DayAverageTradingVolume")
    volume = float(vol_m) * 1e6 if vol_m else None
    return {
        "symbol": symbol.upper(),
        "name": profile.get("name") or symbol.upper(),
        "currency": profile.get("currency") or "USD",
        "price": _safe(lambda: float(fq.get("c"))),
        "previous_close": _safe(lambda: float(fq.get("pc"))),
        "change": _safe(lambda: float(fq.get("d"))),
        "change_pct": _safe(lambda: float(fq.get("dp"))),
        "market_cap": market_cap,
        "pe_ratio": metric.get("peNormalizedAnnual") or metric.get("peTTM"),
        "day_high": _safe(lambda: float(fq.get("h"))),
        "day_low": _safe(lambda: float(fq.get("l"))),
        "volume": volume,
        "fifty_two_week_high": metric.get("52WeekHigh"),
        "fifty_two_week_low": metric.get("52WeekLow"),
        "_source": "finnhub",
    }


def _quote_via_yfinance(symbol: str, deep: bool = False) -> dict:
    """Snapshot via yfinance fast_info (light) + optional Ticker.info (deep)."""
    t = yf.Ticker(symbol)
    fi = t.fast_info
    last = _safe(lambda: float(fi.last_price))
    prev = _safe(lambda: float(fi.previous_close))
    change = (last - prev) if (last is not None and prev is not None) else None
    change_pct = (100 * change / prev) if (change is not None and prev) else None
    quote: dict = {
        "symbol": symbol.upper(),
        "name": symbol.upper(),
        "currency": _safe(lambda: fi.currency, "USD"),
        "price": last,
        "previous_close": prev,
        "change": change,
        "change_pct": change_pct,
        "market_cap": _safe(lambda: fi.market_cap),
        "pe_ratio": None,
        "day_high": _safe(lambda: fi.day_high),
        "day_low": _safe(lambda: fi.day_low),
        "volume": _safe(lambda: fi.last_volume),
        "fifty_two_week_high": _safe(lambda: fi.year_high),
        "fifty_two_week_low": _safe(lambda: fi.year_low),
        "_source": "yfinance",
    }
    if deep:
        info = _safe(lambda: t.info, {}) or {}
        quote["name"] = info.get("shortName") or info.get("longName") or quote["name"]
        quote["pe_ratio"] = info.get("trailingPE")
    return quote


def get_quote(symbol: str, deep: bool = False) -> dict:
    """Fetch current snapshot for a single ticker.

    Tries Finnhub first when FINNHUB_API_KEY is set (real-time US tickers,
    60 calls/min free). Falls back to yfinance otherwise — yfinance is also
    used for non-US / crypto-pair (BTC-USD) symbols where Finnhub returns
    nothing.
    """
    if _FINNHUB_KEY:
        fh = _quote_via_finnhub(symbol)
        if fh is not None:
            return fh
    return _quote_via_yfinance(symbol, deep=deep)
