"""Deterministic tool-claim audit — pre-LLM filter for fabricated tool references.

Extracted from _agent_critic.py (SRP: file-length gate ≤300 LLOC).

The 4B model frequently claims it ran tools that were stripped by the planner
or never authorized (e.g., "בוצעו בדיקות על ידי get_event_log" when
get_event_log was stripped). This module extracts tool-name references from
the draft answer and cross-checks against the actual execution log.
"""

import re

# Pattern: tool names with known prefixes (get_, sentinel_, skill_)
# Applied both to backtick-quoted and bare text. This is precise enough
# to avoid false positives from process names (Widgets.exe), alert triggers
# (cpu_spike, ram_drop), and general tech terms (CPU, RAM, JSON).
# Negative lookahead: skip names followed by .exe/.dll/.sys (process filenames)
_TOOL_REF_RE = re.compile(
    r"\b((?:get_|sentinel_|skill_)[a-z0-9_]+(?:-[a-z0-9_]+)*\b)(?!\.(?:exe|dll|sys|py|js|ts|bat|ps1|cmd|com|scr|pif|ocx))",
    re.IGNORECASE,
)


def _audit_tool_claims(draft_answer: str, tools_used: list[dict]) -> list[str]:
    """Deterministic check: find tool names mentioned in draft that never ran.

    Returns list of fabricated tool names (empty = no fabrication detected).
    This is a PRE-FILTER run before the LLM critic — if it finds fabricated
    tools, the verdict is forced to FAIL regardless of CoVe output, because
    the 4B CoVe model often PASSes drafts that reference non-existent tool
    outputs (it can't distinguish real tool_data from hallucinated references).

    Args:
        draft_answer: The synthesized draft report.
        tools_used: ctx._tools_used — list of {"name": ...} dicts for tools
            that actually executed.

    Returns:
        List of tool names found in draft but NOT in tools_used.
    """
    if not draft_answer or not tools_used:
        return []

    ran_names = {t["name"] for t in tools_used if "name" in t}
    # Also accept final_answer (always available, not in _tools_used)
    ran_names.add("final_answer")

    # Extract tool-name candidates (must have get_/sentinel_/skill_ prefix)
    candidates = set(_TOOL_REF_RE.findall(draft_answer))

    fabricated: list[str] = []
    for cand in candidates:
        lower = cand.lower()
        # Skip if it actually ran (exact or skill_ prefix variant)
        if lower in ran_names or f"skill_{lower}" in ran_names:
            continue
        # Skip if it's a substring of a ran tool or vice versa
        if any(lower in ran or ran in lower for ran in ran_names):
            continue
        fabricated.append(cand)

    return fabricated


# ── Entity audit: detect hallucinated PIDs, file paths, IPs in draft ──

# PID pattern: "PID: 12345" or "PID 12345" or "(PID: 12345)"
_PID_RE = re.compile(r"\bPID[:\s]*}?(\d{3,8})\b", re.IGNORECASE)

# IPv4 pattern: standard dotted quad (excludes version numbers like 1.2.3.4 in SW versions)
_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# File path pattern: Windows or Unix paths with extensions commonly used in security
# Matches: C:\Users\...\temp_script.ps1, /tmp/malware.exe, etc.
_FILEPATH_RE = re.compile(
    r"(?:[A-Za-z]:\\|/)[^\s<>'\"]+\.(?:ps1|exe|bat|cmd|dll|vbs|js|jar|sh|py|scr|com|pif|ocx|hta|msi|msp)",
    re.IGNORECASE,
)

# Whitelist: IPs that appear in boilerplate/system context, not as IOCs
_IP_WHITELIST = {"127.0.0.1", "0.0.0.0", "255.255.255.255", "1.0.0.0"}

# Known benign provider IP prefixes — these are legitimate infrastructure
# (Google, Microsoft, Cloudflare, Apple, Amazon DNS, etc.) that the 4B model
# may reference from general knowledge. They are NOT IOCs and should not
# trigger entity audit failures.
_BENIGN_PROVIDER_PREFIXES = (
    "142.250.",  # Google
    "172.217.",  # Google
    "142.251.",  # Google
    "216.58.",  # Google
    "8.8.8.",  # Google DNS (8.8.8.8)
    "8.8.4.",  # Google DNS (8.8.4.4)
    "1.1.1.",  # Cloudflare DNS
    "1.0.0.",  # Cloudflare DNS
    "13.107.",  # Microsoft
    "20.190.",  # Microsoft
    "20.42.",  # Microsoft
    "52.96.",  # Microsoft
    "52.100.",  # Microsoft
    "52.102.",  # Microsoft
    "52.103.",  # Microsoft
    "104.43.",  # Microsoft Azure
    "13.224.",  # AWS CloudFront
    "99.84.",  # AWS CloudFront
    "13.35.",  # AWS CloudFront
    "17.0.0.",  # Apple
    "17.32.",  # Apple
    "17.41.",  # Apple
)


def _is_benign_provider_ip(ip: str) -> bool:
    """Check if IP belongs to a known benign provider (Google, MS, Cloudflare, etc.)."""
    return any(ip.startswith(prefix) for prefix in _BENIGN_PROVIDER_PREFIXES)


def extract_auditable_ips(draft_answer: str) -> set[str]:
    """Public IPs in the draft subject to entity audit.

    Excludes loopback/boilerplate and known benign-provider prefixes — the
    same IPs the audit itself would skip. The orchestration layer uses this to
    decide which IPs to resolve against the runtime net baseline (async) before
    calling the pure/sync audit.
    """
    if not draft_answer:
        return set()
    return {ip for ip in _IPV4_RE.findall(draft_answer) if ip not in _IP_WHITELIST and not _is_benign_provider_ip(ip)}


def _audit_entity_claims(draft_answer: str, tool_data: str, known_benign_ips: set[str] | None = None) -> list[str]:
    """Deterministic check: find PIDs/IPs/file paths in draft NOT in tool data.

    Returns list of hallucinated entity strings (empty = all entities grounded).
    This is a PRE-FILTER run before the LLM critic — the 4B CoVe model has
    "resolution blindness": it verifies macro-claims (CPU is 20%) but cannot
    reliably cross-check micro-entities (PID 12847) against tool data.

    Args:
        draft_answer: The synthesized draft report.
        tool_data: Raw concatenated tool outputs (the <TOOL_DATA> content).
        known_benign_ips: (Deprecated v2 — kept for API compat, no longer
            bypasses the provenance check. An IP in the baseline but absent
            from the current tool_data is still ungrounded.)

    Returns:
        List of entities found in draft but NOT in tool_data.
    """
    if not draft_answer or not tool_data:
        return []

    hallucinated: list[str] = []

    # ── PIDs: extract all PID numbers from draft, check each in tool_data ──
    draft_pids = set(_PID_RE.findall(draft_answer))
    for pid in draft_pids:
        if pid not in tool_data:
            hallucinated.append(f"PID {pid}")

    # ── File paths: extract paths from draft, check in tool_data ──
    draft_paths = set(_FILEPATH_RE.findall(draft_answer))
    for path in draft_paths:
        filename = path.split("\\")[-1].split("/")[-1]
        if filename not in tool_data and path not in tool_data:
            hallucinated.append(f"path {path}")

    hallucinated.extend(_audit_ip_claims(draft_answer, tool_data, known_benign_ips))
    return hallucinated


def _audit_ip_claims(draft_answer: str, tool_data: str, known_benign_ips: set[str] | None) -> list[str]:
    """IP branch of the entity audit: draft IPs absent from tool_data.

    Provenance law (v2): an IP cited in the draft MUST appear in the current
    hunt's tool_data — regardless of baseline status. known_benign_ips only
    exempts loopback/boilerplate-class IPs from the _IP_WHITELIST filter,
    NOT from the provenance check. A baseline IP that wasn't reported by any
    tool in THIS hunt is still ungrounded (hallucination or stale memory).

    Skips: loopback/boilerplate (_IP_WHITELIST), known benign-provider prefixes
    (Google/Microsoft/Cloudflare DNS ranges that appear in system boilerplate).
    """
    out: list[str] = []
    for ip in set(_IPV4_RE.findall(draft_answer)):
        if ip in _IP_WHITELIST or _is_benign_provider_ip(ip):
            continue
        if ip not in tool_data:
            out.append(f"IP {ip}")
    return out


def _check_entity_audit(
    draft_answer: str, tool_data: str, known_benign_ips: set[str] | None = None
) -> tuple[bool, str, str]:
    """Run entity audit and return (is_pass, feedback_he, logical_flaw).

    Wrapper that formats the result for direct use in _run_critic_evaluation.
    Returns (True, "", "") if all entities are grounded, else
    (False, feedback_he, logical_flaw) for the critic feedback dict.

    known_benign_ips: (Deprecated v2 — kept for API compat, no longer bypasses
    provenance. See _audit_ip_claims docstring.)
    """
    hallucinated = _audit_entity_claims(draft_answer, tool_data, known_benign_ips)
    if not hallucinated:
        return True, "", ""
    entity_list = "; ".join(hallucinated[:5])
    fb = (
        f"אופטימיזציית טיוטה — סבב שיפור ישויות.\n"
        f"<ANCHOR_SUCCESS>\nהמבנה הכללי והנתונים הטכניים מדויקים ומצוינים. שמור עליהם.\n</ANCHOR_SUCCESS>\n"
        f"<REVISE_TARGET>\nהמזהים הבאים אינם מופיעים בנתוני הכלים ויש להחליפם בנתונים המדויקים מ-<TOOL_DATA>: {entity_list}\n</REVISE_TARGET>\n"
        f"<ADD_EVIDENCE>\nהשתמש אך ורק במזהים המופיעים ב-<TOOL_DATA>. אם מזהה אינו נמצא שם, השמט אותו.\n</ADD_EVIDENCE>"
    )
    flaw = f"Unverified entities not in tool data: {entity_list}"
    return False, fb, flaw


# ── Speculation detection: terms that indicate theoretical analysis ──
# These appear in draft reports when the 4B model invents threat scenarios
# not grounded in tool data (e.g., "PowerShell Bypass" when only Python was seen).
_SPECULATIVE_MARKERS = (
    "powershell bypass",
    "עקומות powershell",
    "מודולריים",
    "ייתכן ו",
    "ייתכן ויישמו",
    "סיכון נמוך של שימוש",
    "קיים סיכון",
    "theoretical",
    "תיאורטי",
    "פוטנציאליים",
    "potential threat",
    "may have been",
    "could be used",
    "might be",
)


def _detect_speculation(draft_answer: str, tool_data: str) -> str | None:
    """Detect speculative claims in draft not grounded in tool data.

    Returns the matched marker if speculation found, else None.
    This PREVENTS the False-FAIL backstop from flipping a bare FAIL to PASS
    when the draft contains invented threat scenarios.
    """
    if not draft_answer or not tool_data:
        return None
    _draft_lower = draft_answer.lower()
    for marker in _SPECULATIVE_MARKERS:
        if marker in _draft_lower and marker.lower() not in tool_data.lower():
            return marker
    return None


def _apply_speculation_guard(
    draft_answer: str,
    tool_data: str,
    has_flaw: bool,
    logical_flaw_raw: str,
) -> tuple[bool, str]:
    """Apply speculation guard — returns (has_flaw_updated, logical_flaw_raw_updated).

    If speculation is detected and no real flaw was found, forces has_flaw=True
    to block the False-FAIL backstop from flipping a bare FAIL to PASS.
    """
    speculation = _detect_speculation(draft_answer, tool_data)
    if speculation and not has_flaw:
        import logging as _logging

        _logging.getLogger(__name__).warning(
            "[CRITIC] Speculation detected ('%s') — forcing flaw=True to block False-FAIL backstop.",
            speculation,
        )
        has_flaw = True
        if not logical_flaw_raw:
            logical_flaw_raw = f"Speculative claim not grounded in tool data: '{speculation}'"
    return has_flaw, logical_flaw_raw
