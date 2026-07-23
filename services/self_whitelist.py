# services/self_whitelist.py
"""Self-whitelist — prevents the agent from detecting its own processes.

The Sentinel agent makes OSINT API calls (Maltiverse, VirusTotal, AbuseIPDB)
which appear as "new external connections" from python.exe. Without this filter,
the agent's threat hunter detects its own OSINT queries as suspicious network
activity — the classic "biting your own tail" problem.

Verification layers (defense against masquerading):
  1. Process name match (koboldcpp.exe, python.exe)
  2. Executable path contains project fragment (tactical_bot/sentinel)
  3. Process lineage — koboldcpp must be spawned by Sentinel's python process
  4. SHA256 hash — executable must match known-good hash (registered at startup)

A process is whitelisted ONLY if ALL applicable layers pass.
An attacker naming their malware "koboldcpp.exe" will fail layers 2-4.
"""

import hashlib
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = [
    "is_self_process",
    "is_self_process_by_name",
    "is_self_cmdline",
    "filter_self_connections",
    "register_self_hash",
    "reload_hashes",
    "clear_pid_cache",
    "set_sentinel_pid",
    "get_koboldcpp_cpu_percent",
]

# Process names that are always self (subject to hash/lineage verification)
_SELF_PROC_NAMES = frozenset({"koboldcpp.exe", "koboldcpp", "koboldcpp-server.exe"})

# Path fragments that identify the Sentinel project directory
_SELF_PATH_FRAGMENTS = ("tactical_bot", "sentinel")

# Cache TTL in seconds
_CACHE_TTL = 60
_pid_cache: dict[int, tuple[bool, float]] = {}

# Known-good SHA256 hashes of self executables (registered at startup)
# Maps exe_path_lower -> sha256_hex
_known_good_hashes: dict[str, str] = {}

# Sentinel's own PID (set at startup) — used for lineage verification
_sentinel_pid: int | None = None


def register_self_hash(exe_path: str) -> None:
    """Register a known-good SHA256 hash for a self executable.

    Called at startup for:
    - The Sentinel python.exe
    - The koboldcpp.exe binary

    Once registered, any process claiming to be self must match this hash.
    """
    try:
        path_lower = os.path.abspath(exe_path).lower()
        with open(path_lower, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        _known_good_hashes[path_lower] = sha
        logger.info("[SelfWhitelist] Registered hash %s... for %s", sha[:16], path_lower)
    except Exception as exc:
        logger.warning("[SelfWhitelist] Failed to hash %s: %s", exe_path, exc)


def set_sentinel_pid(pid: int) -> None:
    """Set Sentinel's own PID for lineage verification."""
    global _sentinel_pid
    _sentinel_pid = pid


def reload_hashes() -> dict[str, str]:
    """Hot-reload SHA256 hashes for all registered executables.

    Call this after updating koboldcpp.exe or python.exe to prevent
    Self-DoS (hash mismatch → self-isolation). Can be triggered from
    the C2 dashboard or Telegram without restarting the bot.

    Returns dict of {exe_path: status} where status is "ok" or "error".
    """
    results: dict[str, str] = {}
    # Re-hash all currently registered paths
    registered_paths = list(_known_good_hashes.keys())
    _known_good_hashes.clear()
    _pid_cache.clear()  # Force re-verification on next check
    for path in registered_paths:
        try:
            with open(path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
            _known_good_hashes[path] = sha
            results[path] = f"ok ({sha[:16]}...)"
            logger.info("[SelfWhitelist] Re-registered hash %s... for %s", sha[:16], path)
        except Exception as exc:
            results[path] = f"error: {exc}"
            logger.warning("[SelfWhitelist] Reload failed for %s: %s", path, exc)
    logger.info("[SelfWhitelist] Hash reload complete: %d paths", len(results))
    return results


def clear_pid_cache() -> None:
    """Clear the PID verification cache. Call after process tree changes."""
    _pid_cache.clear()


def _get_proc_exe(pid: int) -> str | None:
    """Get the executable path for a PID. Returns None if inaccessible."""
    try:
        import psutil

        return psutil.Process(pid).exe().lower()
    except Exception:
        return None


def _get_proc_parent_pid(pid: int) -> int | None:
    """Get the parent PID for a process. Returns None if inaccessible."""
    try:
        import psutil

        return psutil.Process(pid).ppid()
    except Exception:
        return None


def _verify_lineage(pid: int, proc_name: str) -> bool:
    """Verify process lineage — koboldcpp should be spawned by Sentinel's python.

    For koboldcpp: parent (or grandparent) must be Sentinel's PID.
    For python.exe: must BE Sentinel's PID (or descendant of it).
    """
    if _sentinel_pid is None:
        # No sentinel PID registered — fail-open on lineage (path check still applies)
        return True

    proc_lower = proc_name.lower()

    if proc_lower in _SELF_PROC_NAMES:
        # koboldcpp: check if Sentinel is an ancestor (up to 3 levels)
        current = pid
        for _ in range(3):
            parent = _get_proc_parent_pid(current)
            if parent is None or parent <= 0:
                return False
            if parent == _sentinel_pid:
                return True
            current = parent
        return False

    # python.exe: must be Sentinel itself or direct child
    if pid == _sentinel_pid:
        return True
    parent = _get_proc_parent_pid(pid)
    return parent == _sentinel_pid


def _verify_hash(exe_path: str) -> bool | None:
    """Verify executable SHA256 matches known-good hash.

    Returns:
      True  — hash registered and matches
      False — hash registered but MISMATCH (masquerading detected)
      None  — no hash registered for this path (can't verify)
    """
    path_lower = os.path.abspath(exe_path).lower()
    expected = _known_good_hashes.get(path_lower)
    if expected is None:
        return None  # no hash registered
    try:
        with open(path_lower, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != expected:
            logger.warning(
                "[SelfWhitelist] HASH MISMATCH for %s: expected %s... got %s... — POSSIBLE MASQUERADING",
                path_lower,
                expected[:16],
                actual[:16],
            )
            return False
        return True
    except Exception:
        return None  # can't read file — treat as unregistered


def is_self_process(pid: int | None, proc_name: str = "") -> bool:
    """Check if a PID/process belongs to the Sentinel agent itself.

    Verification layers (all must pass):
    1. Name match (koboldcpp.exe or python.exe)
    2. Path contains project fragment (tactical_bot/sentinel)
    3. Lineage — koboldcpp spawned by Sentinel, or PID IS Sentinel
    4. Hash — executable matches known-good SHA256 (if registered)

    Returns True only if ALL applicable layers pass.
    """
    if pid is None or pid <= 0:
        return False

    proc_lower = proc_name.lower()

    # Layer 1: Name match
    is_kobold = proc_lower in _SELF_PROC_NAMES
    is_python = proc_lower in ("python.exe", "python")
    if not is_kobold and not is_python:
        return False

    # Check cache
    now = time.monotonic()
    cached = _pid_cache.get(pid)
    if cached is not None:
        result, ts = cached
        if now - ts < _CACHE_TTL:
            return result

    # Layer 2: Path verification (or hash-only bypass)
    exe = _get_proc_exe(pid)
    if exe is None:
        _pid_cache[pid] = (False, now)
        return False

    path_ok = any(frag in exe for frag in _SELF_PATH_FRAGMENTS)

    # Layer 4 (early): Hash verification — if hash matches, bypass path check.
    # A matching SHA256 is stronger evidence than a path fragment.
    hash_result = _verify_hash(exe)
    if hash_result is True and not path_ok:
        # Hash registered and matches — accept even if path doesn't contain fragment
        logger.debug("[SelfWhitelist] PID %d (%s) hash-verified (path bypass)", pid, proc_name)
        _pid_cache[pid] = (True, now)
        return True

    if hash_result is False:
        # Hash registered but MISMATCH — masquerading detected
        _pid_cache[pid] = (False, now)
        return False

    # hash_result is None (no hash registered) — fall through to path + lineage checks
    if not path_ok:
        _pid_cache[pid] = (False, now)
        return False

    # Layer 3: Lineage verification
    lineage_ok = _verify_lineage(pid, proc_name)
    if not lineage_ok:
        logger.warning(
            "[SelfWhitelist] LINEAGE FAIL for PID %d (%s) — not spawned by Sentinel (PID=%s)",
            pid,
            proc_name,
            _sentinel_pid,
        )
        _pid_cache[pid] = (False, now)
        return False

    _pid_cache[pid] = (True, now)
    logger.debug("[SelfWhitelist] PID %d (%s) verified self — exe=%s", pid, proc_name, exe)
    return True


def is_self_process_by_name(proc_name: str) -> bool:
    """Check if a process name belongs to the Sentinel agent (name-only check).

    Used when PID is not available (e.g. parsing from log strings).
    Only koboldcpp is matched — python.exe requires PID for full verification.
    """
    return proc_name.lower() in _SELF_PROC_NAMES


def is_self_cmdline(cmdline: str) -> bool:
    """Check if a command line belongs to Sentinel's own sensor/launcher scripts.

    Used by _scan_suspicious_procs to drop PowerShell/cmd processes that are
    the bot's own monitoring launchers (e.g. pytest runs, hunt poll scripts,
    coverage gates) before TTP analysis. Without this, the threat hunter
    flags its own -NoProfile/-ExecutionPolicy Bypass flags as T1059.001.

    Verification: cmdline contains a self-path fragment (tactical_bot/sentinel).
    Case-insensitive. Matches both Windows (C:\\Users\\...\\tactical_bot) and
    forward-slash (c:/Users/.../tactical_bot) path forms.
    """
    if not cmdline:
        return False
    lowered = cmdline.lower()
    return any(frag in lowered for frag in _SELF_PATH_FRAGMENTS)


def filter_self_connections(
    connections: list[tuple[str, int, int | None, str]],
) -> list[tuple[str, int, int | None, str]]:
    """Filter out network connections originating from Sentinel's own processes.

    Args:
        connections: list of (ip, port, pid, proc_name) tuples

    Returns:
        Filtered list with self-connections removed.
    """
    filtered = []
    removed = 0
    for ip, port, pid, proc_name in connections:
        if is_self_process(pid, proc_name):
            removed += 1
            continue
        filtered.append((ip, port, pid, proc_name))
    if removed:
        logger.info("[SelfWhitelist] Filtered %d self-connections (Sentinel/KoboldCpp).", removed)
    return filtered


def get_koboldcpp_cpu_percent() -> float:
    """Get current CPU% of the koboldcpp process (for load subtraction).

    Returns 0.0 if koboldcpp is not running or inaccessible.
    Used by the load subtraction system to subtract expected LLM inference
    CPU load from total CPU spike detection.
    """
    try:
        import psutil

        for proc in psutil.process_iter(["name", "cpu_percent"]):
            name = (proc.info.get("name") or "").lower()
            if name in _SELF_PROC_NAMES:
                return float(proc.info.get("cpu_percent") or 0.0)
    except Exception:
        pass
    return 0.0
