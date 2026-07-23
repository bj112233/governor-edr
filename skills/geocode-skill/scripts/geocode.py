"""Geocoding via Nominatim (OpenStreetMap, free, no key, 1 req/sec policy)."""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

try:
    from geo_clients import forward, here_forward, reverse, here_route
    from geo_math import haversine, fmt_hours
    from geo_render import cmd_forward, cmd_reverse, cmd_bbox, cmd_distance
    from geo_route import cmd_route_impl
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from geo_clients import forward, here_forward, reverse, here_route
    from geo_math import haversine, fmt_hours
    from geo_render import cmd_forward, cmd_reverse, cmd_bbox, cmd_distance
    from geo_route import cmd_route_impl

load_dotenv()

logger = logging.getLogger(__name__)

OSRM = os.getenv("SENTINEL_OSRM_URL", "https://router.project-osrm.org")
HERE_API_KEY = os.getenv("HERE_API_KEY")

_last_route_context: list[dict] = [{}]


def _state_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills" / "geocode"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _context_file() -> Path:
    return _state_dir() / "route_context.json"


def _load_route_context() -> None:
    global _last_route_context
    try:
        ctx_file = _context_file()
        if ctx_file.exists():
            with open(ctx_file, "r", encoding="utf-8") as f:
                _last_route_context[0] = json.load(f)
    except Exception:
        _last_route_context[0] = {}


def _save_route_context() -> None:
    try:
        ctx_file = _context_file()
        with open(ctx_file, "w", encoding="utf-8") as f:
            json.dump(_last_route_context[0], f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning(f"[Geocode] Failed to save route context: {e}")


def cmd_route(args) -> str:
    """Traffic-aware routing: HERE → OSRM → Haversine fallback."""
    try:
        return cmd_route_impl(args, is_alternative=False, last_ctx=_last_route_context[0], save_ctx_fn=_save_route_context)
    except Exception as e:
        import traceback
        return f"❌ Error in cmd_route: {e}\n\nTraceback:\n{traceback.format_exc()}"


def main():
    _load_route_context()

    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_f = sub.add_parser("forward")
    p_f.add_argument("--address", required=True)

    p_r = sub.add_parser("reverse")
    p_r.add_argument("--lat", type=float, required=True)
    p_r.add_argument("--lon", type=float, required=True)

    p_d = sub.add_parser("distance")
    p_d.add_argument("--from", dest="frm")
    p_d.add_argument("--to")
    p_d.add_argument("--from-lat", dest="from_lat", type=float)
    p_d.add_argument("--from-lon", dest="from_lon", type=float)
    p_d.add_argument("--to-lat", dest="to_lat", type=float)
    p_d.add_argument("--to-lon", dest="to_lon", type=float)

    p_b = sub.add_parser("bbox")
    p_b.add_argument("--address", required=True)

    p_route = sub.add_parser("route")
    p_route.add_argument("--from", dest="frm")
    p_route.add_argument("--to")
    p_route.add_argument("--from-lat", dest="from_lat", type=float)
    p_route.add_argument("--from-lon", dest="from_lon", type=float)
    p_route.add_argument("--to-lat", dest="to_lat", type=float)
    p_route.add_argument("--to-lon", dest="to_lon", type=float)
    p_route.add_argument("--profile", default="driving", choices=["driving", "walking", "cycling"])
    p_route.add_argument("--annotations", action="store_true")
    p_route.add_argument("--waypoint", action="append", dest="waypoints")
    p_route.add_argument("--alternatives", type=int, default=0, choices=[0, 1, 2, 3])

    p_alt = sub.add_parser("alternative")
    p_alt.add_argument("--waypoint", action="append", dest="waypoints")

    args = parser.parse_args()
    try:
        if args.cmd == "forward":
            out = cmd_forward(args.address)
        elif args.cmd == "reverse":
            out = cmd_reverse(args.lat, args.lon)
        elif args.cmd == "distance":
            out = cmd_distance(args)
        elif args.cmd == "bbox":
            out = cmd_bbox(args.address)
        elif args.cmd == "route":
            out = cmd_route(args)
        elif args.cmd == "alternative":
            out = cmd_route_impl(args, is_alternative=True, last_ctx=_last_route_context[0], save_ctx_fn=_save_route_context)
        else:
            out = "❌ Unknown command"
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(2)
    print(out)


if __name__ == "__main__":
    main()
