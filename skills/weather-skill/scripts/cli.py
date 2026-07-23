"""CLI entry point for the weather skill."""

import argparse
import json
import sys

from alerts import evaluate_alerts, parse_alert_spec
from fetch import fetch_air_quality, fetch_weather
from format import format_air_quality_md, format_md
from geocode import geocode


def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--location", default="Tel Aviv", help="City name (Hebrew or English)"
    )
    parser.add_argument("--lat", type=float)
    parser.add_argument("--lon", type=float)
    parser.add_argument(
        "--air-quality",
        dest="air_quality",
        action="store_true",
        help="Return air-quality report (AQI + PM2.5/PM10/NO2/O3/SO2) instead of weather forecast",
    )
    parser.add_argument(
        "--alert-on",
        dest="alert_on",
        help="Comma-separated thresholds (e.g. 'rain>10,wind>50,temp<5,uv>8')",
    )
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output")
    args = parser.parse_args()

    if args.lat is not None and args.lon is not None:
        loc = {"name": f"({args.lat:.2f}, {args.lon:.2f})", "country": ""}
        lat, lon = args.lat, args.lon
    else:
        loc = geocode(args.location)
        if not loc:
            print(f"❌ Location not found: {args.location}", file=sys.stderr)
            sys.exit(1)
        lat, lon = loc["latitude"], loc["longitude"]

    try:
        if args.air_quality:
            data = fetch_air_quality(lat, lon)
            if args.format == "json":
                out = json.dumps(
                    {"location": loc, "air_quality": data}, ensure_ascii=False, indent=2
                )
            else:
                out = format_air_quality_md(loc, data)
        else:
            data = fetch_weather(lat, lon)
            if args.format == "json":
                out = json.dumps(
                    {"location": loc, "weather": data}, ensure_ascii=False, indent=2
                )
            else:
                out = format_md(loc, data)
            if args.alert_on:
                conds = parse_alert_spec(args.alert_on)
                alerts = evaluate_alerts(data, conds)
                if args.format == "json":
                    out = json.dumps(
                        {"location": loc, "weather": data, "alerts": alerts},
                        ensure_ascii=False,
                        indent=2,
                    )
                elif alerts:
                    out += "\n\n## 🚨 התראות מזג-אוויר\n" + "\n".join(
                        f"- {a}" for a in alerts
                    )
                else:
                    out += "\n\n_✅ אין התראות לפי הספים שנקבעו._"
    except Exception as e:
        print(f"❌ Weather API error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"✅ Saved to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
