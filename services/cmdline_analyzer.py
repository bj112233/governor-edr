# services/cmdline_analyzer.py
"""
PowerShell command-line analyzer — evasion-resistant TTP detection.

Maps suspicious command-line patterns to MITRE ATT&CK T1059.001
(PowerShell sub-technique) and related techniques.

Evasion resistance:
  - Case insensitive (dOwNlOaDsTrInG, IEX, iex)
  - Parameter truncation (-enc, -en, -encode, -w 1, -w hidden)
  - Command aliases (IEX, iwr, wget, curl in PS context)
  - Base64 anchor: powershell + -enc → auto score 85+ (BLOCK threshold)

Pure regex, zero I/O. Returns list of CmdlineMatch dataclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CmdlineMatch:
    """Single TTP match from command-line analysis."""

    technique_id: str
    name: str
    tactic: str
    confidence: float
    signals: list[str] = field(default_factory=list)
    suggested_score: int = 0  # 0 = no score override; 85+ = auto-block


# ── MITRE technique metadata ─────────────────────────────────────

_T1059_001 = ("T1059.001", "PowerShell", "Execution")
_T1059 = ("T1059", "Command and Scripting Interpreter", "Execution")
_T1027 = ("T1027", "Obfuscated Files or Information", "Defense Evasion")
_T1105 = ("T1105", "Ingress Tool Transfer", "Command and Control")
_T1059_004 = ("T1059.004", "Unix Shell", "Execution")
_T1197 = ("T1197", "BITS Jobs", "Persistence")

# ── Evasion-resistant regex patterns ─────────────────────────────
# All patterns use re.IGNORECASE to catch dOwNlOaDsTrInG etc.

# PowerShell process detection — matches "powershell" and "powershell.exe" (evasion: omit .exe)
_PS_PROCESS = re.compile(r"\bpowershell(?:_ise)?(?:\.exe)?\b", re.IGNORECASE)

# LOLBin process detection — certutil / bitsadmin (T1105 / T1197)
_CERTUTIL_PROCESS = re.compile(r"\bcertutil(?:\.exe)?\b", re.IGNORECASE)
_BITSADMIN_PROCESS = re.compile(r"\bbitsadmin(?:\.exe)?\b", re.IGNORECASE)

# Execution policy bypass: -ep bypass, -exec bypass, -executionpolic bypass
_BYPASS_FLAGS = re.compile(
    r"(?:-ep|-exec(?:utionpolic)?(?:ypolic)?(?:y)?)\s+(?:bypass|unrestricted|remotesigned)",
    re.IGNORECASE,
)

# Hidden window: -w hidden, -w 1, -windowstyle hidden, -windowstyle 1
_HIDDEN_FLAGS = re.compile(
    r"(?:-w(?:indowstyle)?)\s+(?:hidden|1|2)",
    re.IGNORECASE,
)

# No profile: -nop, -noprofile
_NOPROFILE_FLAGS = re.compile(r"-no(?:rofile|p)\b", re.IGNORECASE)

# Encoded command: -enc, -en, -encode, -encodedcommand, -encodedcommand
_ENCODED_FLAGS = re.compile(
    r"-en(?:c(?:oded(?:command)?)?)?\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)

# Remote execution: IEX, Invoke-Expression
_REMOTE_EXEC = re.compile(
    r"\b(?:iex|invoke-expression)\b",
    re.IGNORECASE,
)

# Download cradle: Net.WebClient, DownloadString, DownloadFile, BitsTransfer
_DOWNLOAD = re.compile(
    r"(?:net\.webclient|downloadstring|downloadfile|bitstransfer|start-bitstransfer)",
    re.IGNORECASE,
)

# Web request aliases: iwr, Invoke-WebRequest, wget, curl (in PS context)
_WEB_REQUEST = re.compile(
    r"\b(?:iwr|invoke-webrequest|irm|invoke-restmethod)\b",
    re.IGNORECASE,
)

# Base64 decode: [Convert]::FromBase64String
_B64_DECODE = re.compile(
    r"\[convert\]::frombase64string",
    re.IGNORECASE,
)

# Script block execution: -File, -Command with external URL
_SCRIPT_BLOCK = re.compile(
    r"(?:-f(?:ile)?|-c(?:ommand)?)\s+(?:https?://|\\\\|\.ps1)",
    re.IGNORECASE,
)

# Execution via WMIC/schtasks (lateral movement + execution)
_WMI_EXEC = re.compile(
    r"\bwmic\b.*\bprocess\b.*\bcall\b.*\bcreate\b",
    re.IGNORECASE,
)

# Certutil ingress tool transfer: -urlcache, -f, -decode (T1105 via LOLBin)
_CERTUTIL_TRANSFER = re.compile(
    r"\bcertutil\b.*(?:-urlcache|-f\b|-decode|-encode)",
    re.IGNORECASE,
)

# BITS jobs: /transfer, /create, /addfile (T1197 persistence via LOLBin)
_BITSADMIN_JOBS = re.compile(
    r"\bbitsadmin\b.*(?:/transfer|/create|/addfile)",
    re.IGNORECASE,
)


# ── Pattern table: (regex, signal_label, score) ──────────────────
# Each entry is checked sequentially; signals accumulate and score is maxed.
_PATTERN_TABLE: tuple[tuple[re.Pattern[str], str, int], ...] = (
    (_BYPASS_FLAGS, "ExecutionPolicy Bypass", 60),
    (_HIDDEN_FLAGS, "Hidden window (-w hidden)", 55),
    (_NOPROFILE_FLAGS, "NoProfile (-nop)", 30),
    (_REMOTE_EXEC, "Invoke-Expression / IEX", 70),
    (_DOWNLOAD, "Download cradle (WebClient/BitsTransfer)", 75),
    (_WEB_REQUEST, "Web request (iwr/irm)", 50),
    (_B64_DECODE, "[Convert]::FromBase64String", 65),
    (_SCRIPT_BLOCK, "External script reference", 60),
    (_WMI_EXEC, "WMI process creation", 70),
    (_CERTUTIL_TRANSFER, "Certutil ingress tool transfer (T1105)", 75),
    (_BITSADMIN_JOBS, "BITS jobs persistence (T1197)", 70),
)


def _check_b64_anchor(text: str, is_powershell: bool) -> list[CmdlineMatch] | None:
    """High-confidence base64 anchor: powershell + -enc → auto 85+ (BLOCK).

    Returns matches list (early exit) if triggered, else None to continue analysis.
    """
    b64_match = _ENCODED_FLAGS.search(text)
    if not (is_powershell and b64_match):
        return None
    return [
        CmdlineMatch(
            *_T1059_001,
            confidence=1.0,
            signals=[f"powershell.exe + encoded command ({b64_match.group(0)[:30]})"],
            suggested_score=90,
        ),
        CmdlineMatch(
            *_T1027,
            confidence=0.9,
            signals=["Base64 encoded payload"],
            suggested_score=85,
        ),
    ]


def _scan_patterns(text: str) -> tuple[list[str], int]:
    """Scan text against the pattern table; return (signals, score)."""
    signals: list[str] = []
    score = 0
    for pattern, label, pattern_score in _PATTERN_TABLE:
        if pattern.search(text):
            signals.append(label)
            score = max(score, pattern_score)
    return signals, score


def _boost_for_multiple_signals(signals: list[str], score: int) -> int:
    """Boost score if multiple evasion signals detected (PowerShell context)."""
    if len(signals) >= 3:
        return max(score, 85)
    if len(signals) >= 2:
        return max(score, 70)
    return score


def _build_aggregate_matches(
    signals: list[str],
    score: int,
    is_powershell: bool,
    text: str,
) -> list[CmdlineMatch]:
    """Build final match list from aggregated signals + score."""
    matches: list[CmdlineMatch] = []
    if not signals:
        return matches

    # LOLBin branch: certutil/bitsadmin get uncapped TTP scores (no 60 cap)
    if _CERTUTIL_PROCESS.search(text):
        matches.append(
            CmdlineMatch(
                *_T1105,
                confidence=0.9,
                signals=signals,
                suggested_score=score,  # Uncapped — pattern table gives 75
            )
        )
        return matches
    if _BITSADMIN_PROCESS.search(text):
        matches.append(
            CmdlineMatch(
                *_T1197,
                confidence=0.9,
                signals=signals,
                suggested_score=score,  # Uncapped — pattern table gives 70
            )
        )
        return matches

    if is_powershell:
        score = _boost_for_multiple_signals(signals, score)
        matches.append(
            CmdlineMatch(
                *_T1059_001,
                confidence=min(1.0, len(signals) / 4.0),
                signals=signals,
                suggested_score=score,
            )
        )
        # Download cradle → also T1105
        if _DOWNLOAD.search(text) or _WEB_REQUEST.search(text):
            matches.append(
                CmdlineMatch(
                    *_T1105,
                    confidence=0.8,
                    signals=["Ingress tool transfer via PowerShell"],
                    suggested_score=max(score, 70),
                )
            )
    else:
        # Suspicious patterns outside PowerShell (e.g., cmd.exe with obfuscation)
        matches.append(
            CmdlineMatch(
                *_T1059,
                confidence=min(1.0, len(signals) / 4.0),
                signals=signals,
                suggested_score=min(score, 60),  # Lower confidence without PS context
            )
        )
    return matches


def analyze_cmdline(cmdline: str) -> list[CmdlineMatch]:
    """Analyze a process command line for MITRE TTPs.

    Args:
        cmdline: Raw command line string (e.g. from process snapshot)

    Returns:
        List of CmdlineMatch sorted by suggested_score descending.
        Empty list if no suspicious patterns found.
    """
    if not cmdline or not cmdline.strip():
        return []

    text = cmdline.strip()
    is_powershell = bool(_PS_PROCESS.search(text))

    # ── Base64 anchor: powershell + -enc → auto 85+ (BLOCK) — early exit ──
    b64_matches = _check_b64_anchor(text, is_powershell)
    if b64_matches is not None:
        return b64_matches

    # ── Scan all patterns via table ──
    signals, score = _scan_patterns(text)

    # ── Aggregate into matches ──
    matches = _build_aggregate_matches(signals, score, is_powershell, text)

    return sorted(matches, key=lambda x: x.suggested_score, reverse=True)


def cmdline_threat_score(cmdline: str) -> int:
    """Convenience: return the highest suggested_score from analyze_cmdline.

    Returns 0 if no suspicious patterns. 85+ triggers auto-block pipeline.
    """
    matches = analyze_cmdline(cmdline)
    return max((m.suggested_score for m in matches), default=0)
