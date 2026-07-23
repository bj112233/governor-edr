"""Stocks skill CLI entry point — argparse orchestration."""

import argparse
import sys

from stocks_render import cmd_crypto, cmd_history, cmd_news, cmd_quote
from stocks_watchlist import cmd_watchlist

_PERIODS = [
    "1d",
    "5d",
    "1mo",
    "3mo",
    "6mo",
    "1y",
    "2y",
    "5y",
    "10y",
    "ytd",
    "max",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_q = sub.add_parser("quote")
    p_q.add_argument("--symbol", required=True, help="Comma-separated tickers")

    p_h = sub.add_parser("history")
    p_h.add_argument("--symbol", required=True)
    p_h.add_argument("--period", default="1mo", choices=_PERIODS)
    p_h.add_argument("--output")

    p_n = sub.add_parser("news")
    p_n.add_argument("--symbol", required=True)
    p_n.add_argument("--limit", type=int, default=10)

    p_c = sub.add_parser("crypto")
    p_c.add_argument("--symbol", required=True, help="BTC, ETH, BTC-USD, etc.")

    p_w = sub.add_parser("watchlist")
    p_w.add_argument(
        "--action",
        required=True,
        choices=["add", "remove", "list", "quotes", "check"],
    )
    p_w.add_argument("--symbol")
    p_w.add_argument("--target", type=float, help="Price target (used with action=add)")
    p_w.add_argument(
        "--direction",
        choices=["above", "below"],
        default="below",
        help="Trigger when price crosses target in this direction (default: below)",
    )
    p_w.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format for action=check",
    )
    return parser


def _dispatch(args) -> str:
    if args.cmd == "quote":
        return cmd_quote([s for s in args.symbol.split(",")])
    if args.cmd == "history":
        return cmd_history(args.symbol, args.period, args.output)
    if args.cmd == "news":
        return cmd_news(args.symbol, args.limit)
    if args.cmd == "crypto":
        return cmd_crypto(args.symbol)
    if args.cmd == "watchlist":
        symbols = args.symbol.split(",") if args.symbol else None
        return cmd_watchlist(
            args.action,
            symbols,
            target=args.target,
            direction=args.direction,
            fmt=args.format,
        )
    return "❌ Unknown command"


def main():
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = _build_parser()
    args = parser.parse_args()
    try:
        out = _dispatch(args)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(2)
    print(out)


if __name__ == "__main__":
    main()
