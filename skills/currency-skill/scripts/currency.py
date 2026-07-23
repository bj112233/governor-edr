"""Currency conversion with multi-source fallback chain.

Source priority:
  1. Frankfurter (ECB official, no key, ~30 fiat, history from 1999)
  2. exchangerate-api.com v6 (open.er-api.com, free, ~160 fiat, real-time)
  3. fawazahmed0/currency-api (jsDelivr CDN, 200+ inc. crypto BTC/ETH/etc)

The chain is target-aware: if a specific `to` currency is not present in an
earlier source's response, the next source is tried.

Implementations extracted to focused modules:
- currency_sources.py: cache, 3 API fetchers, fallback chain
- currency_format.py:  Markdown formatters, currency codes/flags
"""
import argparse
import json
import sys
from datetime import date as _date

import requests

from currency_format import (
    CURRENCY_CODES,
    CURRENCY_FLAGS,
    format_conversion_md,
    format_rates_md,
    format_timeseries_md,
)
from currency_sources import (
    AllSourcesUnavailable,
    FALLBACK_URL,
    _cache_get,
    _cache_put,
    _fetch_exchangerate_rates,
    _fetch_fawazahmed0_rates,
    _fetch_frankfurter_rates,
    _fetch_rates_chain,
)


def convert(amount: float, frm: str, to: str, date: str = "latest") -> dict:
    from currency_sources import _CACHE_TTL_HISTORICAL, _CACHE_TTL_LATEST
    key = f"convert:{date}:{frm.upper()}:{to.upper()}:{amount}"
    ttl = _CACHE_TTL_LATEST if date == "latest" else _CACHE_TTL_HISTORICAL
    cached = _cache_get(key, ttl)
    if cached:
        return cached
    data = _fetch_rates_chain(frm.upper(), date, target=to.upper())
    rate = data.get("rates", {}).get(to.upper())
    if rate is None:
        raise ValueError(f"Currency {to.upper()} not available")
    result = amount * rate
    out = {
        "amount": amount,
        "base": frm.upper(),
        "date": data.get("date", date),
        "rates": {to.upper(): result},
        "_source": data.get("_source", "unknown"),
    }
    _cache_put(key, out)
    return out


def get_rates(base: str, date: str = "latest") -> dict:
    from currency_sources import _CACHE_TTL_HISTORICAL, _CACHE_TTL_LATEST
    key = f"rates:{date}:{base.upper()}"
    ttl = _CACHE_TTL_LATEST if date == "latest" else _CACHE_TTL_HISTORICAL
    cached = _cache_get(key, ttl)
    if cached:
        return cached
    data = _fetch_rates_chain(base.upper(), date)
    _cache_put(key, data)
    return data


def timeseries(frm: str, to: str, start: str, end: str) -> dict:
    from currency_sources import _CACHE_TTL_HISTORICAL
    key = f"ts:{start}:{end}:{frm.upper()}:{to.upper()}"
    cached = _cache_get(key, _CACHE_TTL_HISTORICAL)
    if cached:
        return cached
    url = f"{FALLBACK_URL}/{start}..{end}"
    params = {"from": frm.upper(), "to": to.upper()}
    r = requests.get(url, params=params, timeout=15)
    r.raise_for_status()
    data = r.json()
    _cache_put(key, data)
    return data


def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--amount", type=float, default=1.0)
    parser.add_argument("--amounts", help="Comma-separated list of amounts (e.g. 100,500,1000)")
    parser.add_argument("--from", dest="frm", help="Source currency (e.g. USD)")
    parser.add_argument("--to", help="Target currency (e.g. ILS)")
    parser.add_argument("--rates", help="Show all rates against this base (e.g. ILS)")
    parser.add_argument("--date", default="latest", help="YYYY-MM-DD or 'latest'")
    parser.add_argument("--start", help="Time-series start date (YYYY-MM-DD)")
    parser.add_argument("--end", help="Time-series end date (YYYY-MM-DD); defaults to today")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output")
    args = parser.parse_args()

    try:
        if args.start and args.frm and args.to:
            end = args.end or _date.today().isoformat()
            data = timeseries(args.frm, args.to, args.start, end)
            out = (json.dumps(data, ensure_ascii=False, indent=2)
                   if args.format == "json" else format_timeseries_md(data, args.frm, args.to))
        elif args.rates:
            data = get_rates(args.rates, args.date)
            out = (json.dumps(data, ensure_ascii=False, indent=2)
                   if args.format == "json" else format_rates_md(data))
        elif args.amounts and args.frm and args.to:
            results = []
            for raw in args.amounts.split(","):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    amt = float(raw)
                except ValueError:
                    continue
                results.append((amt, convert(amt, args.frm, args.to, args.date)))
            if args.format == "json":
                out = json.dumps([{"amount": a, "data": d} for a, d in results], ensure_ascii=False, indent=2)
            else:
                lines = [f"# 💱 המרות מרובות ({args.frm.upper()} → {args.to.upper()})\n"]
                for amt, d in results:
                    lines.append(format_conversion_md(d, amt, args.frm, args.to))
                    lines.append("")
                out = "\n".join(lines)
        elif args.frm and args.to:
            data = convert(args.amount, args.frm, args.to, args.date)
            out = (json.dumps(data, ensure_ascii=False, indent=2)
                   if args.format == "json" else format_conversion_md(data, args.amount, args.frm, args.to))
        else:
            print("❌ Need either --from/--to OR --rates BASE OR --start/--from/--to")
            sys.exit(1)
    except AllSourcesUnavailable:
        print("❌ All currency API sources are currently unavailable.")
        sys.exit(2)
    except requests.HTTPError as e:
        print(f"❌ API error: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"✅ Saved to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
