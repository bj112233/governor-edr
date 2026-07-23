# services/yara_allowlist.py
"""YARA rule allowlist — suppress false positives without deleting rules.

Loads rules/yara/allowlist.yml at boot and provides is_allowlisted()
to check if a (rule_name, filepath) pair should be suppressed.

Supports two match modes:
  - path: exact file path (case-insensitive on Windows)
  - hash: SHA256 of file content (computed lazily, cached)
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_ALLOWLIST_PATH = Path(__file__).parent.parent / "rules" / "yara" / "allowlist.yml"
_allowlist: dict[str, list[dict[str, str]]] = {}
_hash_cache: dict[str, str] = {}
_loaded = False


def load_allowlist() -> None:
    """Load allowlist from YAML. Called once at boot (idempotent)."""
    global _allowlist, _loaded
    if _loaded:
        return
    _loaded = True
    if not _ALLOWLIST_PATH.exists():
        logger.debug("[YARA-Allowlist] No allowlist file found at %s", _ALLOWLIST_PATH)
        return
    try:
        with open(_ALLOWLIST_PATH, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            logger.warning("[YARA-Allowlist] Invalid format — expected dict, got %s", type(data).__name__)
            return
        _allowlist = data
        entry_count = sum(len(v) for v in data.values() if isinstance(v, list))
        if entry_count:
            logger.info("[YARA-Allowlist] Loaded %d entries for %d rules", entry_count, len(data))
    except Exception as exc:
        logger.error("[YARA-Allowlist] Failed to load: %s", exc)


def _file_sha256(filepath: str) -> str:
    """Compute SHA256 of file, with cache (keyed by mtime+path)."""
    try:
        stat = os.stat(filepath)
        cache_key = f"{filepath}:{stat.st_mtime}:{stat.st_size}"
        if cache_key in _hash_cache:
            return _hash_cache[cache_key]
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        _hash_cache[cache_key] = digest
        # Trim cache to prevent unbounded growth
        if len(_hash_cache) > 500:
            _hash_cache.clear()
            _hash_cache[cache_key] = digest
        return digest
    except OSError:
        return ""


def _path_matches(allowed_path: str, path_lower: str) -> bool:
    """S-9: Path match with directory prefix support.

    Exact match OR prefix match when allowed_path ends with os.sep
    (e.g. "C:\\Windows\\System32\\" suppresses all files in that directory).
    """
    if not allowed_path:
        return False
    if path_lower == allowed_path:
        return True
    return allowed_path.endswith(os.sep) and path_lower.startswith(allowed_path)


def is_allowlisted(rule_name: str, filepath: str) -> bool:
    """Check if a (rule_name, filepath) pair is in the allowlist.

    Returns True if the match should be suppressed (false positive).
    """
    if not _loaded:
        load_allowlist()
    entries = _allowlist.get(rule_name)
    if not entries:
        return False
    path_lower = filepath.lower()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # Path match (case-insensitive on Windows, with directory prefix)
        allowed_path = entry.get("path", "").lower()
        if _path_matches(allowed_path, path_lower):
            logger.info("[YARA-Allowlist] Suppressing %s on %s (path match)", rule_name, filepath)
            return True
        # Hash match
        allowed_hash = entry.get("hash", "").lower()
        if allowed_hash:
            file_hash = _file_sha256(filepath)
            if file_hash and file_hash.lower() == allowed_hash:
                logger.info("[YARA-Allowlist] Suppressing %s on %s (hash match)", rule_name, filepath)
                return True
    return False


def get_allowlist() -> dict[str, Any]:
    """Return the loaded allowlist (for observability/debugging)."""
    if not _loaded:
        load_allowlist()
    return dict(_allowlist)
