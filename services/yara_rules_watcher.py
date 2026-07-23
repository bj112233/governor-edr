# services/yara_rules_watcher.py
"""Watchdog observer on rules/yara/ — auto-triggers hot-reload on .yar changes.

The local filesystem is the Trust Zone: the act of placing a .yar file in
rules/yara/ IS the authorization gate (a human or authorized script put it
there after review). This watcher closes the loop on yara_engine.reload_rules()
by firing it deterministically whenever rules change — no scheduling, no API
surface, no LLM involvement.

Debounce: 2s timer resets on every file event. A `git pull` that writes 50
.yar files in quick succession triggers exactly ONE reload, not 50.

Architecture mirrors fim_engine.py: watchdog Observer (background thread) →
asyncio.run_coroutine_threadsafe → main event loop → reload_rules().
"""

from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"
_DEBOUNCE_SECONDS = 2.0

_observer: BaseObserver | None = None
_debounce_timer: threading.Timer | None = None
_debounce_lock = threading.Lock()
_main_loop: asyncio.AbstractEventLoop | None = None


class _YaraRulesHandler(FileSystemEventHandler):
    """Watchdog handler — bridges to asyncio loop with debounce."""

    def on_created(self, event: Any) -> None:
        self._maybe_reload(event.src_path)

    def on_modified(self, event: Any) -> None:
        self._maybe_reload(event.src_path)

    def _maybe_reload(self, src_path: str) -> None:
        """Filter to .yar files, then debounce → schedule reload on main loop."""
        if event_is_dir(src_path):
            return
        if not src_path.lower().endswith(".yar"):
            return
        global _debounce_timer
        with _debounce_lock:
            if _debounce_timer is not None:
                _debounce_timer.cancel()
            _debounce_timer = threading.Timer(_DEBOUNCE_SECONDS, _fire_reload)
            _debounce_timer.daemon = True
            _debounce_timer.start()
        logger.debug("[YARA-Watcher] File changed: %s — reload in %.1fs", src_path, _DEBOUNCE_SECONDS)


def event_is_dir(src_path: str) -> bool:
    """Check if the event source is a directory (watchdog may report false positives)."""
    try:
        return Path(src_path).is_dir()
    except (OSError, ValueError):
        return False


def _fire_reload() -> None:
    """Called by debounce timer (background thread) — schedule reload on main loop."""
    if _main_loop is None or not _main_loop.is_running():
        logger.warning("[YARA-Watcher] Main loop unavailable — skipping reload")
        return
    from services.yara_engine import reload_rules

    asyncio.run_coroutine_threadsafe(reload_rules(), _main_loop)


def start_watcher(main_loop: asyncio.AbstractEventLoop) -> bool:
    """Start the watchdog observer on rules/yara/. Returns True if started."""
    global _observer, _main_loop
    _main_loop = main_loop

    if not _RULES_DIR.exists():
        logger.warning("[YARA-Watcher] Rules directory not found: %s — watcher disabled", _RULES_DIR)
        return False

    handler = _YaraRulesHandler()
    _observer = Observer()
    _observer.schedule(handler, str(_RULES_DIR), recursive=False)

    try:
        _observer.start()
        logger.info("[YARA-Watcher] Watching %s (debounce %.1fs)", _RULES_DIR, _DEBOUNCE_SECONDS)
        return True
    except Exception as exc:
        logger.error("[YARA-Watcher] Failed to start observer: %s", exc)
        _observer = None
        return False


def stop_watcher() -> None:
    """Stop the watcher gracefully."""
    global _observer, _debounce_timer
    with _debounce_lock:
        if _debounce_timer is not None:
            _debounce_timer.cancel()
            _debounce_timer = None
    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None
        logger.info("[YARA-Watcher] Observer stopped")


def is_running() -> bool:
    """Check if the watcher observer is active."""
    return _observer is not None and _observer.is_alive()
