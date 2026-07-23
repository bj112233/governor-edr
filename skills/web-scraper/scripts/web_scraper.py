"""Web Scraper — fetch pages, extract text/tables/prices, watch for changes.

Shim facade for backward compatibility.
All logic has been moved to focused modules (SRP, ≤300 lines each):
  _fetch_safety.py   — SSRF blocking, per-domain throttle, robots.txt checks
  _hebrew.py         — Hebrew-aware encoding detection/normalization
  _session.py        — requests Session + Mozilla cookies.txt persistence
  _config.py         — scrape_targets.json profiles + state-dir resolution
  fetcher.py         — HTTP fetch with retries/backoff/size cap
  extractors.py      — text/table/price extraction, hashing, CSV
  web_scraper_cli.py — argparse CLI + per-subcommand handlers
"""

from __future__ import annotations

# ── Re-export public API ──
from _config import _load_profiles, _state_dir
from _fetch_safety import (
    DOMAIN_MIN_INTERVAL,
    _is_blocked,
    _robots_allowed,
    _throttle_domain,
)
from _hebrew import _looks_like_hebrew_mojibake, _normalize_hebrew_encoding
from _session import _save_cookies, _session
from extractors import extract_price, extract_table, extract_text, hash_content, to_csv
from fetcher import DEFAULT_UA, MAX_RESPONSE_BYTES, fetch
from web_scraper_cli import main

__all__ = [
    # Constants
    "DEFAULT_UA",
    "MAX_RESPONSE_BYTES",
    "DOMAIN_MIN_INTERVAL",
    # Fetcher
    "fetch",
    # Extractors
    "extract_text",
    "extract_table",
    "extract_price",
    "hash_content",
    "to_csv",
    # Safety
    "_is_blocked",
    "_throttle_domain",
    "_robots_allowed",
    # Hebrew
    "_looks_like_hebrew_mojibake",
    "_normalize_hebrew_encoding",
    # Session / cookies
    "_session",
    "_save_cookies",
    # Config / state
    "_load_profiles",
    "_state_dir",
    # CLI
    "main",
]

if __name__ == "__main__":
    main()
