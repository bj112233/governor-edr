"""Profile and state-directory resolution for the web scraper skill."""

from __future__ import annotations

import json
import os
from pathlib import Path


def _load_profiles() -> dict:
    """Load scrape_targets.json profiles."""
    cfg_paths = [
        Path(__file__).parent.parent / "config" / "scrape_targets.json",
        Path(__file__).resolve().parents[3] / "config" / "scrape_targets.json",
    ]
    for p in cfg_paths:
        if p.is_file():
            try:
                with open(p, encoding="utf-8") as f:
                    return json.load(f).get("profiles", {})
            except Exception:
                pass
    return {}


def _state_dir() -> Path:
    base = os.getenv("SENTINEL_STATE_DIR")
    p = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
    p = p / "skills"
    p.mkdir(parents=True, exist_ok=True)
    return p
