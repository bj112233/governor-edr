"""Stock quotes + watchlist with multi-source fallback.

Shim layer for backward compatibility.
All logic has been moved to the new modular architecture:
  _stocks_utils.py     — state paths, safe accessor, warning suppression
  stocks_quotes.py     — Finnhub + yfinance quote fetching
  stocks_render.py     — Markdown rendering (quote, news, crypto, history)
  stocks_watchlist.py  — watchlist state + price-target triggers
  stocks_facade.py     — CLI argparse orchestration
"""

from __future__ import annotations

# ── Re-export public API from facade ──
from stocks_facade import main

# ── Re-export infrastructure for downstream imports ──
from _stocks_utils import (
    TARGETS_FILE,
    WATCHLIST_FILE,
    _safe,
    _state_dir,
    yf,
)
from stocks_quotes import (
    _FINNHUB_BASE,
    _FINNHUB_KEY,
    _FINNHUB_TIMEOUT,
    _finnhub_basic_financials,
    _finnhub_profile,
    _finnhub_quote,
    _quote_via_finnhub,
    _quote_via_yfinance,
    get_quote,
)
from stocks_render import (
    cmd_crypto,
    cmd_history,
    cmd_news,
    cmd_quote,
    format_quote_md,
)
from stocks_watchlist import (
    _normalize_wl,
    _wl_add,
    _wl_check,
    _wl_list,
    _wl_quotes,
    _wl_remove,
    cmd_watchlist,
    load_targets,
    load_watchlist,
    save_targets,
    save_watchlist,
)

__all__ = [
    # CLI / facade
    "main",
    # Infra
    "WATCHLIST_FILE",
    "TARGETS_FILE",
    "_state_dir",
    "_safe",
    "yf",
    # Quotes
    "_FINNHUB_KEY",
    "_FINNHUB_BASE",
    "_FINNHUB_TIMEOUT",
    "_finnhub_quote",
    "_finnhub_profile",
    "_finnhub_basic_financials",
    "_quote_via_finnhub",
    "_quote_via_yfinance",
    "get_quote",
    # Render
    "format_quote_md",
    "cmd_quote",
    "cmd_news",
    "cmd_crypto",
    "cmd_history",
    # Watchlist
    "load_watchlist",
    "save_watchlist",
    "load_targets",
    "save_targets",
    "_normalize_wl",
    "_wl_list",
    "_wl_add",
    "_wl_remove",
    "_wl_quotes",
    "_wl_check",
    "cmd_watchlist",
]

if __name__ == "__main__":
    raise SystemExit(main())
