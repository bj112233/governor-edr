# services/yara_engine.py
"""
YARA scanning engine — Singleton with compile-on-boot rule loading.

Loads all .yar files from rules/yara/ at startup, compiles them once,
and provides a fast match() API for file scanning. Supports hot-reload
via reload_rules() for ingesting external rule packs without service
restarts.

Severity gating: only High/Critical matches are returned to callers (and
thus reach the Event Bus). Medium/Low/Info matches are logged locally via
logger.info and dropped — prevents Alert Fatigue when ingesting hundreds
of external community rule packs.

Used by file_analyst skill to detect malware patterns in files.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

import yara

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"
_compiled_rules: yara.Rules | None = None
_initialized = False
_reload_lock: asyncio.Lock | None = None  # lazily bound on first reload_rules() call


# ── Severity Gating ───────────────────────────────────────────────
# Only High/Critical matches are returned to callers (and thus reach the
# Event Bus). Medium/Low/Info matches are logged locally via logger.info
# and dropped — prevents Alert Fatigue when ingesting hundreds of external
# community rule packs (many of which are medium/noise).
# If no severity meta is present, assume High (backward compat with the
# original 5-rule set).
_HIGH_SEVERITIES = frozenset({"high", "critical", "crit", "very_high", "very-high"})


def _extract_severity(meta: dict[str, Any]) -> str:
    """Extract normalized severity from rule meta.

    Checks 'severity', 'level', 'severity_level' keys (case-insensitive).
    Returns 'high' if no severity meta is present (backward compat).
    """
    if not meta:
        return "high"
    lowered = {k.lower(): v for k, v in meta.items()}
    for key in ("severity", "level", "severity_level"):
        if key in lowered:
            return str(lowered[key]).strip().lower()
    return "high"


def _passes_severity_gate(meta: dict[str, Any]) -> bool:
    """True if the rule's severity meets the High/Critical dispatch threshold."""
    return _extract_severity(meta) in _HIGH_SEVERITIES


def _extract_strings(m: Any, limit: int = 5) -> list[dict[str, Any]]:
    """Extract string match info from a YARA match object (yara-python 4.5+ aware)."""
    strings_info: list[dict[str, Any]] = []
    for s in (m.strings or [])[:limit]:
        if hasattr(s, "offset"):
            strings_info.append(
                {
                    "offset": s.offset,
                    "identifier": str(s.identifier),
                    "data": str(getattr(s, "data", b""))[:100],
                }
            )
        elif isinstance(s, (tuple, list)) and len(s) >= 3:
            strings_info.append(
                {
                    "offset": s[0],
                    "identifier": str(s[1]),
                    "data": str(s[2])[:100],
                }
            )
    return strings_info


def initialize() -> None:
    """Compile all .yar files from rules/yara/ into memory. Call once at boot."""
    global _compiled_rules, _initialized
    if _initialized:
        return

    if not _RULES_DIR.exists():
        logger.warning("[YARA] Rules directory not found: %s", _RULES_DIR)
        _initialized = True
        return

    yar_files = list(_RULES_DIR.glob("*.yar"))
    if not yar_files:
        logger.warning("[YARA] No .yar files found in %s", _RULES_DIR)
        _initialized = True
        return

    # Build file mapping for compilation
    file_dict: dict[str, str] = {}
    for yar in yar_files:
        file_dict[yar.stem] = str(yar)

    try:
        _compiled_rules = yara.compile(filepaths=file_dict)
        rule_count = len(file_dict)
        logger.info("[YARA] Compiled %d rule file(s) from %s", rule_count, _RULES_DIR)
    except Exception as exc:
        logger.error("[YARA] Failed to compile rules: %s", exc)
        _compiled_rules = None

    _initialized = True


def match(filepath: str) -> list[dict[str, Any]]:
    """Scan a file against compiled YARA rules.

    Returns list of match dicts: {"rule": name, "tags": [...], "meta": {...}}
    Empty list if no matches or engine not initialized.
    """
    if not _initialized:
        initialize()
    if _compiled_rules is None:
        return []

    if not os.path.isfile(filepath):
        logger.debug("[YARA] File not found: %s", filepath)
        return []

    try:
        matches = _compiled_rules.match(filepath)
        results: list[dict[str, Any]] = []
        gated: list[str] = []
        allowlisted: list[str] = []
        from services.yara_allowlist import is_allowlisted

        for m in matches:
            meta = dict(m.meta) if hasattr(m, "meta") else {}
            if not _passes_severity_gate(meta):
                gated.append(m.rule)
                continue
            if is_allowlisted(m.rule, filepath):
                allowlisted.append(m.rule)
                continue
            results.append(
                {
                    "rule": m.rule,
                    "tags": list(m.tags) if hasattr(m, "tags") else [],
                    "meta": meta,
                    "strings": _extract_strings(m),
                }
            )
        if gated:
            logger.info("[YARA] %s gated %d low/medium/info match(es): %s", filepath, len(gated), gated)
        if allowlisted:
            logger.info("[YARA] %s allowlisted %d match(es): %s", filepath, len(allowlisted), allowlisted)
        if results:
            logger.info("[YARA] %s matched %d rule(s): %s", filepath, len(results), [r["rule"] for r in results])
        return results
    except Exception as exc:
        logger.error("[YARA] Scan failed for %s: %s", filepath, exc)
        return []


def match_data(data: bytes) -> list[dict[str, Any]]:
    """Scan raw bytes against compiled YARA rules (for in-memory scanning)."""
    if not _initialized:
        initialize()
    if _compiled_rules is None:
        return []

    try:
        matches = _compiled_rules.match(data=data)
        results: list[dict[str, Any]] = []
        gated: list[str] = []
        for m in matches:
            meta = dict(m.meta) if hasattr(m, "meta") else {}
            if not _passes_severity_gate(meta):
                gated.append(m.rule)
                continue
            results.append(
                {
                    "rule": m.rule,
                    "tags": list(m.tags) if hasattr(m, "tags") else [],
                    "meta": meta,
                }
            )
        if gated:
            logger.info("[YARA] Data scan gated %d low/medium/info match(es): %s", len(gated), gated)
        return results
    except Exception as exc:
        logger.error("[YARA] Data scan failed: %s", exc)
        return []


def get_rule_count() -> int:
    """Return number of compiled rules (0 if not initialized)."""
    if not _initialized:
        initialize()
    if _compiled_rules is None:
        return 0
    try:
        return sum(1 for _ in _compiled_rules)
    except Exception:
        return 0


async def match_with_retry(filepath: str, max_retries: int = 5) -> list[dict[str, Any]]:
    """Scan a file with exponential backoff for PermissionError (file lock race).

    Backoff: 100ms, 200ms, 400ms, 800ms, 1600ms (total max ~3.1s).
    Returns match list (empty on failure or no match).
    """
    import asyncio as _aio

    for attempt in range(max_retries + 1):
        try:
            return match(filepath)
        except PermissionError:
            if attempt < max_retries:
                backoff = 0.1 * (2**attempt)
                logger.debug(
                    "[YARA] File locked (attempt %d/%d), retry in %.1fs: %s",
                    attempt + 1,
                    max_retries,
                    backoff,
                    filepath,
                )
                await _aio.sleep(backoff)
            else:
                logger.warning("[YARA] File locked after %d retries, abandoning: %s", max_retries, filepath)
                return []
        except FileNotFoundError:
            logger.debug("[YARA] File deleted before scan: %s", filepath)
            return []
        except Exception as exc:
            logger.error("[YARA] Scan error for %s: %s", filepath, exc)
            return []
    return []


async def reload_rules() -> dict[str, Any]:
    """Hot-reload YARA rules from rules/yara/ without service restart.

    Re-compiles all .yar files into a new index in a worker thread, then
    atomically swaps the global _compiled_rules. Active scans hold their own
    reference to the old index until their match() call returns, so the swap
    cannot crash in-flight scans. If compilation fails, the old index is
    preserved — no degradation.

    Returns {"files": N, "rules": M} on success,
    {"files": 0, "rules": 0, "error": str} on failure.
    """
    global _reload_lock, _compiled_rules, _initialized
    if _reload_lock is None:
        _reload_lock = asyncio.Lock()
    async with _reload_lock:

        def _compile_sync() -> tuple[yara.Rules, int]:
            if not _RULES_DIR.exists():
                raise FileNotFoundError(f"Rules directory not found: {_RULES_DIR}")
            yar_files = list(_RULES_DIR.glob("*.yar"))
            if not yar_files:
                raise FileNotFoundError(f"No .yar files in {_RULES_DIR}")
            file_dict = {yar.stem: str(yar) for yar in yar_files}
            compiled = yara.compile(filepaths=file_dict)
            return compiled, len(file_dict)

        try:
            new_rules, file_count = await asyncio.to_thread(_compile_sync)
        except FileNotFoundError as exc:
            logger.warning("[YARA] Reload skipped: %s", exc)
            return {"files": 0, "rules": 0, "error": str(exc)}
        except Exception as exc:
            logger.error("[YARA] Reload compile failed (keeping old rules): %s", exc)
            return {"files": 0, "rules": 0, "error": str(exc)}

        old_count = get_rule_count()
        _compiled_rules = new_rules  # atomic swap (GIL-protected single assignment)
        _initialized = True
        new_count = get_rule_count()
        logger.info(
            "[YARA] Hot-reload complete: %d file(s) -> %d rules (was %d)",
            file_count,
            new_count,
            old_count,
        )
        return {"files": file_count, "rules": new_count}
