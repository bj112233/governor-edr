"""File Integrity Monitor — watchdog Observer + YARA auto-scan.

Architecture:
  watchdog Observer (background thread, ReadDirectoryChangesW)
    → SentinelFIMHandler.on_created (sync, fast filters)
    → asyncio.run_coroutine_threadsafe (thread-safe handoff to main loop)
    → _scan_with_retry (async, exponential backoff for file locks)
    → yara_engine.match_with_retry → emit alert on match

3 filter layers (applied synchronously in on_created):
  1. Path whitelist (Downloads, Desktop, Documents)
  2. Extension filter (.ps1, .exe, .dll, etc.)
  3. Size gate (< FIM_MAX_SCAN_SIZE)
"""

import asyncio
import logging
import os
import threading
from pathlib import Path
from typing import Any

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver

from config import (
    FIM_DANGEROUS_EXTS,
    FIM_IGNORE_PATH_PATTERNS,
    FIM_MAX_RETRIES,
    FIM_MAX_SCAN_SIZE,
    FIM_WATCH_PATHS,
)

logger = logging.getLogger(__name__)

_observer: BaseObserver | None = None

# Backpressure: limit concurrent YARA scans to prevent event loop starvation
# during sensory overload attacks (e.g., 5000 files dropped into Downloads).
_FIM_SCAN_SEMAPHORE = asyncio.Semaphore(4)
# Burst protection: drop scans if too many are queued (prevents memory exhaustion)
_FIM_MAX_PENDING = 50
_fim_pending_count = 0
_fim_pending_lock = threading.Lock()

# In-memory ring buffer of recent YARA matches — consumed by pre_hunt_enricher
# to inject hard facts into the agent's context window before the LLM runs.
_RECENT_YARA_HITS: list[dict[str, Any]] = []
_YARA_HISTORY_MAX = 20
_YARA_HISTORY_TTL = 3600  # 1 hour


def get_recent_yara_hits(hours: float = 1.0) -> list[dict[str, Any]]:
    """Return YARA matches from the last `hours` hours (for pre-hunt enrichment).

    Each entry: {"path": str, "rules": list[str], "mitre_ids": list[str],
                 "severity": str, "timestamp": float}
    """
    import time

    cutoff = time.time() - (hours * 3600)
    return [h for h in _RECENT_YARA_HITS if h.get("timestamp", 0) >= cutoff]


def _record_yara_hit(path: str, results: list[dict]) -> None:
    """Record a YARA match in the in-memory ring buffer."""
    import time

    top = results[0] if results else {}
    severity = top.get("meta", {}).get("severity", "high")
    rule_names = [r["rule"] for r in results]
    mitre_ids = [r.get("meta", {}).get("mitre", "") for r in results if r.get("meta", {}).get("mitre")]

    _RECENT_YARA_HITS.append(
        {
            "path": path,
            "rules": rule_names,
            "mitre_ids": mitre_ids,
            "severity": severity,
            "timestamp": time.time(),
        }
    )
    # Trim to max size + TTL
    cutoff = time.time() - _YARA_HISTORY_TTL
    _RECENT_YARA_HITS[:] = [h for h in _RECENT_YARA_HITS if h["timestamp"] >= cutoff][-_YARA_HISTORY_MAX:]


class SentinelFIMHandler(FileSystemEventHandler):
    """Watchdog event handler — bridges watchdog thread → asyncio main loop."""

    def __init__(self, main_loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._loop = main_loop
        self._exts = FIM_DANGEROUS_EXTS
        self._max_size = FIM_MAX_SCAN_SIZE
        self._max_retries = FIM_MAX_RETRIES
        self._ignore_patterns = tuple(p.lower() for p in FIM_IGNORE_PATH_PATTERNS)
        self._stats = {"scanned": 0, "matched": 0, "filtered": 0, "errors": 0}

    def on_created(self, event: Any) -> None:
        """Called by watchdog background thread — must be fast + non-blocking."""
        if event.is_directory:
            return
        path = event.src_path
        if not self._passes_filters(path):
            self._stats["filtered"] += 1
            return
        # Burst protection: drop scan if too many are pending (DoS defense)
        global _fim_pending_count
        with _fim_pending_lock:
            if _fim_pending_count >= _FIM_MAX_PENDING:
                self._stats["filtered"] += 1
                logger.warning("[FIM] Burst protection: dropping scan (pending=%d)", _fim_pending_count)
                return
            _fim_pending_count += 1
        asyncio.run_coroutine_threadsafe(self._scan_with_retry(path), self._loop)

    def on_modified(self, event: Any) -> None:
        """Also scan on modify — catches .crdownload → final rename."""
        if event.is_directory:
            return
        path = event.src_path
        if not self._passes_filters(path):
            return
        global _fim_pending_count
        with _fim_pending_lock:
            if _fim_pending_count >= _FIM_MAX_PENDING:
                self._stats["filtered"] += 1
                return
            _fim_pending_count += 1
        asyncio.run_coroutine_threadsafe(self._scan_with_retry(path), self._loop)

    def _passes_filters(self, path: str) -> bool:
        """Layer 0+1+2+3: ignore-path + extension + size filters (sync, fast).

        Layer 0: ignore-path blacklist (Cache/Temp subdirs) — prevents
                 watchdog buffer overflow from browser/app cache writes
                 when recursive=True is enabled on Temp/AppData paths.
        """
        # Layer 0: ignore-path blacklist (case-insensitive path segment match)
        path_lower = path.lower()
        if any(p in path_lower for p in self._ignore_patterns):
            return False
        # Layer 2: extension whitelist
        ext = Path(path).suffix.lower()
        if ext not in self._exts:
            return False
        # Layer 3: size gate (stat is fast, no file read)
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size > self._max_size:
            logger.debug("[FIM] Skipping large file (%d bytes): %s", size, path)
            return False
        if size == 0:
            return False  # empty file (still being written)
        return True

    async def _scan_with_retry(self, path: str) -> None:
        """Async scan with exponential backoff — runs in main event loop.

        Backpressure: semaphore limits concurrent YARA scans to 4.
        Burst protection: pending counter decremented on completion.

        M11 fix: Stable-size check before scanning. Two size reads 100ms
        apart — if file is still being written (size changed), wait
        instead of scanning partial content. Prevents YARA false negatives
        on partial writes.
        """
        global _fim_pending_count
        from services.yara_engine import match_with_retry

        try:
            # M11: Wait for stable file size (not being actively written)
            if not await self._wait_for_stable_size(path):
                self._stats["filtered"] += 1
                logger.debug("[FIM] Skipping unstable file (still writing): %s", path)
                return

            async with _FIM_SCAN_SEMAPHORE:
                self._stats["scanned"] += 1
                results = await match_with_retry(path, max_retries=self._max_retries)
                if results:
                    self._stats["matched"] += 1
                    _record_yara_hit(path, results)
                    await self._emit_yara_alert(path, results)
        except Exception as exc:
            self._stats["errors"] += 1
            logger.error("[FIM] Scan failed for %s: %s", path, exc)
        finally:
            with _fim_pending_lock:
                _fim_pending_count = max(0, _fim_pending_count - 1)

    async def _wait_for_stable_size(self, path: str, max_waits: int = 3) -> bool:
        """M11: Wait until file size is stable across two reads 100ms apart.

        Returns True if file is stable (safe to scan).
        Returns False if file keeps changing after max_waits (skip scan).
        """
        import asyncio

        for _ in range(max_waits):
            try:
                size1 = os.path.getsize(path)
            except OSError:
                return False
            await asyncio.sleep(0.1)
            try:
                size2 = os.path.getsize(path)
            except OSError:
                return False
            if size1 == size2 and size1 > 0:
                return True
        return False

    async def _emit_yara_alert(self, path: str, results: list[dict]) -> None:
        """Emit a YARA match alert to the event bus."""
        from services.sentinel_events import event_bus

        top = results[0]
        severity_val = top.get("meta", {}).get("severity", "high")
        rule_names = [r["rule"] for r in results]
        mitre_ids = [r["meta"].get("mitre", "") for r in results if r.get("meta", {}).get("mitre")]
        alert_needed = severity_val == "critical"

        snapshot = {
            "alert_needed": alert_needed,
            "trigger": f"yara_match:{Path(path).name}",
            "yara_matches": rule_names,
            "mitre_ids": mitre_ids,
            "file_path": path,
        }
        analysis = f"YARA match: {', '.join(rule_names[:3])} | MITRE: {', '.join(mitre_ids[:3])}"
        remediation = {
            "category": "file",
            "metric": "yara_match",
            "yara_rules": rule_names,
            "file_path": path,
        }
        await event_bus.emit_alert(snapshot, analysis=analysis, remediation=remediation)
        logger.warning("[FIM] YARA match in %s: %s", path, rule_names)

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)


def start_fim(main_loop: asyncio.AbstractEventLoop) -> bool:
    """Start the FIM observer. Returns True if started, False if skipped/failed."""
    global _observer

    # Lazy-resolve paths (handles NSSM/service where USERPROFILE is absent at import)
    from config import _resolve_fim_paths

    watch_paths = FIM_WATCH_PATHS or _resolve_fim_paths()
    if not watch_paths:
        logger.warning("[FIM] No watch paths configured — FIM disabled")
        return False

    handler = SentinelFIMHandler(main_loop)
    _observer = Observer()

    for watch_path in watch_paths:
        if not os.path.isdir(watch_path):
            logger.debug("[FIM] Watch path does not exist: %s", watch_path)
            continue
        _observer.schedule(handler, watch_path, recursive=True)
        logger.info("[FIM] Watching (recursive): %s", watch_path)

    try:
        _observer.start()
        logger.info(
            "[FIM] Observer started — %d paths (recursive), exts=%d, ignore=%d patterns, max_size=%d bytes",
            len(watch_paths),
            len(FIM_DANGEROUS_EXTS),
            len(FIM_IGNORE_PATH_PATTERNS),
            FIM_MAX_SCAN_SIZE,
        )
        return True
    except Exception as exc:
        logger.error("[FIM] Failed to start observer: %s", exc)
        _observer = None
        return False


def stop_fim() -> None:
    """Stop the FIM observer gracefully."""
    global _observer
    if _observer is not None:
        _observer.stop()
        _observer.join(timeout=5)
        _observer = None
        logger.info("[FIM] Observer stopped")


def is_running() -> bool:
    """Check if FIM observer is active."""
    return _observer is not None and _observer.is_alive()
