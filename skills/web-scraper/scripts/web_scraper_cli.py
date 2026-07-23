"""Web Scraper CLI — argparse dispatch to per-subcommand handlers.

Handlers are split out of the legacy monolithic ``main`` to keep each
function's cyclomatic complexity at grade C or below.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from _config import _load_profiles, _state_dir
from _session import _save_cookies, _session
from extractors import extract_price, extract_table, extract_text, hash_content, to_csv
from fetcher import DEFAULT_UA, fetch


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user-agent", default=DEFAULT_UA)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--no-robots", action="store_true", help="Skip robots.txt check"
    )
    parser.add_argument(
        "--cookies",
        help="Path to Mozilla cookies.txt for session persistence (W3)",
    )
    sub = parser.add_subparsers(dest="cmd")

    p_profile = sub.add_parser(
        "profile", help="Use a preset profile from config/scrape_targets.json"
    )
    p_profile.add_argument("--name", required=True, help="Profile key (e.g. zap_price)")
    p_profile.add_argument(
        "--query", default="", help="Substituted into url_template's {query}"
    )
    p_profile.add_argument("--limit", type=int, default=10)
    p_profile.add_argument("--output")
    p_profile.add_argument(
        "--list", action="store_true", help="List available profiles and exit"
    )

    p_fetch = sub.add_parser("fetch")
    p_fetch.add_argument("--url", required=True)
    p_fetch.add_argument("--selector", default="article, .content, main")
    p_fetch.add_argument("--limit", type=int, default=0, help="Max elements to extract")
    p_fetch.add_argument("--output")

    p_price = sub.add_parser("price")
    p_price.add_argument("--url", required=True)
    p_price.add_argument("--selector", required=True)
    p_price.add_argument("--threshold", type=float, default=0)
    p_price.add_argument("--alert", action="store_true")

    p_table = sub.add_parser("table")
    p_table.add_argument("--url", required=True)
    p_table.add_argument("--selector", required=True)
    p_table.add_argument("--format", choices=["csv", "json", "markdown"], default="csv")
    p_table.add_argument("--output")

    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--url", required=True)
    p_watch.add_argument("--selector", required=True)
    p_watch.add_argument("--interval", type=int, default=3600)
    p_watch.add_argument("--alert", action="store_true")
    p_watch.add_argument("--once", action="store_true")

    p_batch = sub.add_parser("batch")
    p_batch.add_argument("--urls", required=True)
    p_batch.add_argument("--selector", default="h2")
    p_batch.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Seconds between URLs (default: 1.0)",
    )
    p_batch.add_argument("--output")
    return parser


def _make_fetcher(args, sess):
    """Return a closure that fetches with the shared session and persists cookies."""

    def _fetch(u: str) -> str:
        result = fetch(
            u,
            user_agent=args.user_agent,
            retries=args.retries,
            respect_robots=not args.no_robots,
            session=sess,
        )
        if sess and args.cookies:
            _save_cookies(sess, args.cookies)
        return result

    return _fetch


def _cmd_profile(args, _fetch) -> None:
    profiles = _load_profiles()
    if args.list:
        print("📋 Available profiles:")
        for name, p in profiles.items():
            print(f"  - {name:<28} | {p.get('description', '')}")
        return
    prof = profiles.get(args.name)
    if not prof:
        print(f"❌ Profile '{args.name}' not found. Use --list to see options.")
        sys.exit(1)
    url = prof.get("url") or prof.get("url_template", "").replace(
        "{query}", args.query
    )
    if not url:
        print(f"❌ Profile '{args.name}' missing url/url_template")
        sys.exit(1)
    if prof.get("needs_js"):
        print(
            f"⚠️ Profile '{args.name}' requires JS rendering (Playwright not installed)"
        )
    html = _fetch(url)
    ptype = prof.get("type", "text")
    selector = prof.get("selector", "body")
    if ptype == "price":
        price = extract_price(html, selector)
        print(f"💰 Price: {price}" if price else "❌ Price not found")
    elif ptype == "list":
        text = extract_text(html, selector, limit=args.limit)
        output = f"# {prof.get('description', args.name)}\n\n{text}\n"
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
            print(f"✅ Saved to {args.output}")
        else:
            print(output)
    else:  # text
        text = extract_text(html, selector, limit=args.limit)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"✅ Saved to {args.output}")
        else:
            print(text[:5000])


def _cmd_fetch(args, _fetch) -> None:
    html = _fetch(args.url)
    text = extract_text(html, args.selector, limit=args.limit)
    md = f"# {args.url}\n\n{text}\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"✅ Saved to {args.output}")
    else:
        print(md)


def _cmd_price(args, _fetch) -> None:
    html = _fetch(args.url)
    price = extract_price(html, args.selector)
    if price is None:
        print("❌ Price not found")
        sys.exit(1)
    print(f"💰 Price: {price}")
    if args.threshold and price < args.threshold:
        msg = f"🔻 Price dropped below {args.threshold}: {price}"
        print(msg)
        if args.alert:
            print(f"ALERT: {msg}")


def _cmd_table(args, _fetch) -> None:
    html = _fetch(args.url)
    rows = extract_table(html, args.selector)
    if not rows:
        print("❌ Table not found")
        sys.exit(1)
    if args.format == "csv":
        print(to_csv(rows, args.output))
    elif args.format == "json":
        out = json.dumps(rows, ensure_ascii=False, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"✅ Saved to {args.output}")
        else:
            print(out)
    elif args.format == "markdown":
        lines = ["| " + " | ".join(row) + " |" for row in rows]
        lines.insert(1, "| " + " | ".join(["---"] * len(rows[0])) + " |")
        out = "\n".join(lines)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"✅ Saved to {args.output}")
        else:
            print(out)


def _cmd_watch(args, _fetch) -> None:
    # Persist last-seen hash per URL+selector so --once invocations
    # (e.g. via cron / scheduled tasks) can detect changes across runs.
    key = hashlib.sha256(f"{args.url}|{args.selector}".encode("utf-8")).hexdigest()[
        :16
    ]
    state_file = _state_dir() / f"web_scraper_watch_{key}.json"
    try:
        prev_hash = json.loads(state_file.read_text(encoding="utf-8")).get("hash")
    except (FileNotFoundError, json.JSONDecodeError):
        prev_hash = None
    while True:
        html = _fetch(args.url)
        text = extract_text(html, args.selector)
        h = hash_content(text)
        if prev_hash and h != prev_hash:
            msg = f"🔄 Change detected on {args.url} (hash {h})"
            print(msg)
            if args.alert:
                print(f"ALERT: {msg}")
        else:
            print(f"✅ No change (hash {h})")
        prev_hash = h
        state_file.write_text(
            json.dumps({"hash": h, "url": args.url, "ts": time.time()}),
            encoding="utf-8",
        )
        if args.once:
            break
        time.sleep(args.interval)


def _cmd_batch(args, _fetch) -> None:
    try:
        with open(args.urls, encoding="utf-8") as f:
            urls = [u.strip() for u in f if u.strip()]
    except (FileNotFoundError, PermissionError, OSError) as exc:
        print(f"❌ ERROR: Cannot read '{args.urls}': {exc}. Do not retry with this tool.")
        return
    results = []
    for url in urls:
        try:
            html = _fetch(url)
            text = extract_text(html, args.selector)
            results.append({"url": url, "text": text[:1000]})
            if args.delay > 0:
                time.sleep(args.delay)
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    out = json.dumps(results, ensure_ascii=False, indent=2)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot write to '{args.output}': {exc}. Do not retry with this tool.")
            return
        print(f"✅ Batch results saved to {args.output}")
    else:
        print(out)


_DISPATCH = {
    "profile": _cmd_profile,
    "fetch": _cmd_fetch,
    "price": _cmd_price,
    "table": _cmd_table,
    "watch": _cmd_watch,
    "batch": _cmd_batch,
}


def main() -> None:
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = _build_parser()
    args = parser.parse_args()

    # Persistent session for cookies (W3)
    sess = _session(args.cookies) if args.cookies else None
    _fetch = _make_fetcher(args, sess)

    handler = _DISPATCH.get(args.cmd)
    if handler is not None:
        handler(args, _fetch)


if __name__ == "__main__":
    main()
