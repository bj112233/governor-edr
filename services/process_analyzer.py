# services/process_analyzer.py
"""analyze_process_event — Sysmon-enriched process analysis wrapper.

Wraps `analyze_cmdline` (the existing regex engine, unchanged) and adds
4 checks that require Sysmon fields unavailable to psutil:

  1. Parent anomaly (T1059.005) — suspicious parent→child chain
  2. Hash reputation — known-malicious SHA256 (placeholder for intel feed)
  3. Integrity level — Medium spawning High = UAC bypass attempt
  4. Unsigned masquerading — unsigned binary in C:\\Windows\\

Each check gracefully skips when its required field is None (psutil path
or Sysmon partial event). The wrapper NEVER throws on missing data —
it falls back to `analyze_cmdline` results alone.

Returns `list[CmdlineMatch]` — same type as `analyze_cmdline`, so
downstream consumers (monitor_analyzer, _proc_formatter) can use either
function interchangeably.
"""

from __future__ import annotations

import asyncio
import logging
import os

from services.cmdline_analyzer import CmdlineMatch, analyze_cmdline
from services.process_event import ProcessEvent

logger = logging.getLogger(__name__)

# ── Parent anomaly: legitimate parent images for common processes ──
# If a process is spawned by a parent that should never spawn it, that's
# T1059.005 (Process Injection) or T1059.001 (PowerShell) abuse.
# Example: winword.exe → cmd.exe is classic macro-dropper behavior.
_SUSPICIOUS_PARENT_PAIRS: dict[str, frozenset[str]] = {
    # Office apps should never spawn shells or scripting engines
    "winword.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"}),
    "excel.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}),
    "outlook.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}),
    "powerpoint.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"}),
    # Browsers spawning shells — possible drive-by exploit
    "chrome.exe": frozenset({"cmd.exe", "powershell.exe"}),
    "msedge.exe": frozenset({"cmd.exe", "powershell.exe"}),
    "firefox.exe": frozenset({"cmd.exe", "powershell.exe"}),
    # PDF reader spawning shell
    "acrord32.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe"}),
    "acrobat.exe": frozenset({"cmd.exe", "powershell.exe", "wscript.exe"}),
}


def _basename_lower(path: str) -> str:
    """Extract lowercase basename from a full path."""
    if not path:
        return ""
    # Handle both \ and / separators
    return path.replace("/", "\\").split("\\")[-1].lower()


def _check_parent_anomaly(event: ProcessEvent) -> CmdlineMatch | None:
    """T1059.005 — suspicious parent→child process chain.

    Returns a CmdlineMatch if the parent image is a known "should never
    spawn a shell" application (Office, browser, PDF reader) and the
    child is a shell/scripting engine. Returns None if:
      - parent_image is None (psutil path or orphan)
      - parent is not in the suspicious-parent table
      - child name is not in the parent's forbidden-children set
    """
    if event.parent_image is None:
        return None
    parent_name = _basename_lower(event.parent_image)
    child_name = event.name.lower() if event.name else ""

    forbidden_children = _SUSPICIOUS_PARENT_PAIRS.get(parent_name)
    if forbidden_children is None:
        return None  # parent not in table — no anomaly
    if child_name not in forbidden_children:
        return None  # child is not a forbidden spawn

    return CmdlineMatch(
        technique_id="T1059.005",
        name="Suspicious parent process chain",
        tactic="Defense Evasion",
        confidence=0.85,
        signals=[f"parent={parent_name}", f"child={child_name}"],
        suggested_score=75,  # High suspicion but not auto-block (needs context)
    )


# ── Hash reputation: known-malicious SHA256 set ──
# Placeholder for local threat intel. In production, this is populated
# from threat_feeds sync (Maltiverse, VT) via a periodic background refresh.
# The check is sync (no I/O) to keep the consumer thread fast — async
# enrichment via intel_enricher.enrich_hash happens in a separate worker
# if the sync check flags the hash as "needs deeper lookup".
_KNOWN_BAD_HASHES: set[str] = set()  # populated at runtime by threat feed sync


def register_malicious_hash(sha256: str) -> None:
    """Add a SHA256 to the known-bad set (called by threat feed sync)."""
    h = sha256.lower().strip()
    if len(h) == 64:
        _KNOWN_BAD_HASHES.add(h)


def known_bad_hash_count() -> int:
    """Return the current size of the known-bad hash set (for monitoring/tests)."""
    return len(_KNOWN_BAD_HASHES)


async def sync_hashes_from_threatfox() -> int:
    """Sync SHA256 IOCs from ThreatFox into the known-bad hash set.

    Called by the scheduler every 2h (alongside feed_refresh). Pulls
    ThreatFox IOCs with confidence >= 50, filters for sha256_hash type,
    and registers each via register_malicious_hash.

    Trade-off (documented): the set is always "behind" the live feed —
    a hash published seconds ago won't be detected until the next sync
    (up to 2h lag). This is acceptable: the sync check is instant and
    safe in the consumer thread; async per-event lookup would add
    latency and network dependency to the hot path.

    Returns the number of new hashes added.
    """
    from services.threat_feeds import _fetch_threatfox_sync

    before = len(_KNOWN_BAD_HASHES)
    try:
        iocs = await asyncio.to_thread(_fetch_threatfox_sync, 1)
    except Exception as exc:
        logger.warning("[ProcessAnalyzer] ThreatFox hash sync failed: %s", exc)
        return 0
    added = 0
    for ioc in iocs:
        ioc_type = (ioc.get("ioc_type") or "").lower()
        if ioc_type != "sha256_hash":
            continue
        ioc_val = (ioc.get("ioc") or "").strip().lower()
        if len(ioc_val) == 64 and ioc_val not in _KNOWN_BAD_HASHES:
            register_malicious_hash(ioc_val)
            added += 1
    after = len(_KNOWN_BAD_HASHES)
    logger.info(
        "[ProcessAnalyzer] ThreatFox hash sync: +%d new (set: %d → %d)",
        added, before, after,
    )
    return added


def _check_hash_reputation(event: ProcessEvent) -> CmdlineMatch | None:
    """T1027 — known-malicious file hash.

    Returns a CmdlineMatch if event.sha256 is in the known-bad set.
    Returns None if:
      - sha256 is None (psutil path, or Sysmon hash timeout)
      - sha256 is not in the known-bad set

    Note: this is a fast sync check against a local set. Deep async
    enrichment (VT/Maltiverse lookup) is triggered separately by the
    consumer if this check flags the hash, to avoid blocking the
    consumer thread on network I/O.
    """
    if event.sha256 is None:
        return None
    if event.sha256 not in _KNOWN_BAD_HASHES:
        return None

    return CmdlineMatch(
        technique_id="T1027",
        name="Known-malicious file hash",
        tactic="Defense Evasion",
        confidence=0.95,
        signals=[f"sha256={event.sha256[:16]}..."],
        suggested_score=90,  # Known-bad hash → auto-block threshold
    )


# ── Integrity level: UAC bypass detection ──
# Windows integrity levels (low to high): Untrusted < Low < Medium < High < System
# Normal: Medium-integrity process spawns Medium-integrity child.
# Suspicious: Medium-integrity process spawns High-integrity child → UAC bypass
# (T1548.002 — Bypass UAC). This should never happen legitimately.
_INTEGRITY_ORDER = ["untrusted", "low", "medium", "high", "system"]


def _integrity_rank(level: str) -> int:
    """Return numeric rank of an integrity level string (0-4). -1 if unknown."""
    if not level:
        return -1
    try:
        return _INTEGRITY_ORDER.index(level.lower().strip())
    except ValueError:
        return -1


def _check_integrity_level(event: ProcessEvent) -> CmdlineMatch | None:
    """T1548.002 — UAC bypass via integrity level escalation.

    Returns a CmdlineMatch if the process integrity level is High or
    System but the parent (if known) is Medium or lower — indicating
    a Medium-integrity process spawned a High-integrity child without
    UAC consent prompt.

    Returns None if:
      - integrity_level is None (psutil path or Sysmon didn't capture it)
      - integrity_level is Medium or lower (normal)
      - integrity_level is High/System but parent is also High/System
        (legitimate elevation, e.g. via UAC consent)
      - integrity_level is unknown string
    """
    if event.integrity_level is None:
        return None

    child_rank = _integrity_rank(event.integrity_level)
    if child_rank < 0:
        return None  # unknown integrity level string
    if child_rank <= _INTEGRITY_ORDER.index("medium"):
        return None  # Medium or lower — normal, no escalation

    # Child is High or System — check parent if known
    if event.parent_image is not None:
        # We don't have parent integrity level in Event 1, but if the
        # parent is a known Medium-integrity app (Office, browser), the
        # escalation is suspicious. For now, flag any High/System child
        # whose parent is in the suspicious-parent table (those are all
        # Medium-integrity apps).
        parent_name = _basename_lower(event.parent_image)
        if parent_name in _SUSPICIOUS_PARENT_PAIRS:
            return CmdlineMatch(
                technique_id="T1548.002",
                name="UAC bypass — integrity level escalation",
                tactic="Privilege Escalation",
                confidence=0.80,
                signals=[
                    f"integrity={event.integrity_level}",
                    f"parent={parent_name} (Medium)",
                ],
                suggested_score=80,
            )

    # High/System integrity without a known-Medium parent — could be
    # legitimate (UAC consent, scheduled task, service). Don't flag
    # without parent context to avoid false positives.
    return None


# ── Unsigned masquerading: unsigned binary in C:\Windows\ ──
# Legitimate Windows system binaries are Authenticode-signed. An unsigned
# binary in C:\Windows\System32\ is almost certainly masquerading (T1036).
# This check requires the `signed` field, which Event 1 does NOT provide
# (it comes from Event 7 — Image Load). When signed is None (Event 1 only,
# or psutil path), this check skips — it cannot determine unsigned status
# from Event 1 alone.
_WINDOWS_DIRS = ("c:\\windows\\", "c:\\windows\\system32\\", "c:\\windows\\syswow64\\")


def _check_unsigned_masquerading(event: ProcessEvent) -> CmdlineMatch | None:
    """T1036 — unsigned binary masquerading as Windows system binary.

    Returns a CmdlineMatch if:
      - signed is False (explicitly unsigned, from Event 7 enrichment)
      - image is in C:\\Windows\\ (system directory)

    Returns None if:
      - signed is None (Event 1 doesn't carry signature info — cannot
        determine, skip to avoid false positives)
      - signed is True (legitimately signed)
      - image is None or not in a Windows system directory

    Note: this check is only meaningful when the consumer also processes
    Event 7 (Image Load) to populate the `signed` field. With Event 1
    alone, signed is always None and this check always skips.
    """
    if event.signed is None:
        return None  # cannot determine — Event 1 doesn't carry signature
    if event.signed:
        return None  # legitimately signed
    if event.image is None:
        return None

    image_lower = event.image.lower()
    if not any(image_lower.startswith(d) for d in _WINDOWS_DIRS):
        return None  # not in a Windows system directory

    return CmdlineMatch(
        technique_id="T1036",
        name="Unsigned binary in Windows system directory",
        tactic="Defense Evasion",
        confidence=0.90,
        signals=[f"unsigned image={event.image}"],
        suggested_score=85,  # auto-block threshold
    )


def analyze_process_event(event: ProcessEvent) -> list[CmdlineMatch]:
    """Analyze a ProcessEvent for MITRE TTPs.

    Always runs `analyze_cmdline(event.cmdline)` (the regex engine).
    Additionally runs Sysmon-enriched checks when their required fields
    are present (skips gracefully when None).

    Args:
        event: ProcessEvent from psutil or Sysmon.

    Returns:
        List of CmdlineMatch sorted by suggested_score descending.
        Empty list if no suspicious patterns found.
    """
    # 1. Base regex analysis — always runs, even on empty cmdline
    matches = list(analyze_cmdline(event.cmdline))

    # 2. Parent anomaly (T1059.005) — requires parent_image
    parent_match = _check_parent_anomaly(event)
    if parent_match is not None:
        matches.append(parent_match)

    # 3. Hash reputation (T1027) — requires sha256
    hash_match = _check_hash_reputation(event)
    if hash_match is not None:
        matches.append(hash_match)

    # 4. Integrity level (T1548.002) — requires integrity_level + parent context
    integrity_match = _check_integrity_level(event)
    if integrity_match is not None:
        matches.append(integrity_match)

    # 5. Unsigned masquerading (T1036) — requires signed (from Event 7)
    unsigned_match = _check_unsigned_masquerading(event)
    if unsigned_match is not None:
        matches.append(unsigned_match)

    return sorted(matches, key=lambda m: m.suggested_score, reverse=True)
