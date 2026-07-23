"""Shared infrastructure for stocks skill: state paths, safe accessor, warning suppression.

Pandas4Warning emitted from yfinance internals is non-actionable for us
(upstream issue) and pollutes stderr/stdout. We silence ALL warnings before
importing yfinance via simplefilter('ignore') — the only filter category that
catches Pandas4Warning, since it inherits from a pandas-specific base class
outside the standard hierarchy.
"""

import os
import warnings
from pathlib import Path

warnings.simplefilter("ignore")  # noqa: E402 — must precede yfinance import
os.environ.setdefault("PYTHONWARNINGS", "ignore")

import yfinance as yf  # noqa: E402


def _state_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills"
    p.mkdir(parents=True, exist_ok=True)
    return p


WATCHLIST_FILE = _state_dir() / "stocks_watchlist.json"
TARGETS_FILE = _state_dir() / "stocks_targets.json"


def _safe(getter, default=None):
    try:
        v = getter()
        return v if v is not None else default
    except Exception:
        return default
