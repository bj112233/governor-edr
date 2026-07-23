# services/agent/routing/intent_routers.py
"""Deterministic intent routers — fast-path routing that bypasses LLM tool-selection.

Each router detects a specific intent pattern in the user query and returns a
routing decision (tool/skill + args). When a router matches, the agent skips
the LLM "which tool should I use?" step entirely — saving ReAct budget and
preventing the 4B model from picking the wrong tool.

Routers are PURE FUNCTIONS (no I/O, no side effects). Detection only.
The bypass dispatcher (_bypasses.py) consumes these to execute the fast-path.

Moved from osint_search.py: `_is_ioc_query` (canonical home is now here;
osint_search re-exports it for backward compat).
"""

import ipaddress
import logging
import re

logger = logging.getLogger(__name__)

__all__ = [
    "_is_ioc_query",
    "_is_cve_query",
    "_is_hash_query",
    "_is_file_path_query",
    "_is_process_query",
    "_is_yara_query",
    "_is_pcap_query",
    "_is_eml_query",
    "detect_intent",
]

# ── IOC detection (moved from osint_search.py) ──────────────────────────────
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$")


def _is_ioc_query(query: str) -> bool:
    """Detect if query is a pure IOC (IP, hash, bare domain).

    These should be routed to intel_enricher/leak_scanner, not web search.
    """
    q = query.strip()
    # Pure IP
    try:
        ipaddress.ip_address(q)
        return True
    except ValueError:
        pass
    # Pure hash (MD5/SHA1/SHA256)
    if _HASH_RE.fullmatch(q):
        return True
    # Bare domain (no spaces, no question words)
    if " " not in q and _DOMAIN_RE.match(q) and len(q) < 60:
        return True
    return False


# ── CVE detection ───────────────────────────────────────────────────────────
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)


def _is_cve_query(query: str) -> str | None:
    """Return the CVE ID if the query is a CVE lookup, else None.

    Routes CVE queries directly to osint_hunt (engine-in-engine) instead of
    letting the LLM pick web_search → wastes a ReAct step.
    """
    if not query:
        return None
    m = _CVE_RE.search(query)
    if m:
        return m.group(1).upper()
    return None


# ── Hash detection (standalone, for intel-skill hash command) ───────────────
_HASH_STANDALONE_RE = re.compile(r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")

# Keywords that indicate a hash lookup intent (vs. hash appearing incidentally)
_HASH_INTENT_KEYWORDS = frozenset(
    [
        "hash",
        "malware",
        "virus",
        "גיבוב",
        "נוזקה",
        "וירוס",
        "reputation",
        "מוניטין",
        "check",
        "בדוק",
        "lookup",
        "scan",
        "סרוק",
        "threat",
        "איום",
    ]
)


def _is_hash_query(query: str) -> str | None:
    """Return the hash if the query is a hash lookup, else None.

    Only triggers when a hash pattern co-occurs with an intent keyword —
    prevents false positives on hashes appearing in file paths or logs.
    """
    if not query or len(query) > 300:
        return None
    q_lower = query.lower()
    has_intent = any(kw in q_lower for kw in _HASH_INTENT_KEYWORDS)
    # Bare hash (no other words) also counts as intent
    stripped = query.strip()
    if _HASH_RE.fullmatch(stripped):
        has_intent = True
    if not has_intent:
        return None
    m = _HASH_STANDALONE_RE.search(query)
    if m:
        return m.group(1).lower()
    return None


# ── File path detection (for file-analyst skill) ────────────────────────────
# Windows path: C:\... or \\server\share or relative path with extension
_WIN_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s\"'<>|]+?\.[a-zA-Z0-9]{1,6})")
_UNIX_PATH_RE = re.compile(r"(/[^\s\"'<>|]+?\.[a-zA-Z0-9]{1,6})")
_REL_PATH_RE = re.compile(r"([\w./\\-]+\.[a-zA-Z0-9]{1,6})")

# File-analyst supported extensions (from SKILL.md)
_FA_EXTENSIONS = frozenset(
    [
        "pdf",
        "docx",
        "doc",
        "csv",
        "xlsx",
        "xls",
        "txt",
        "json",
        "md",
        "jpg",
        "jpeg",
        "png",
        "webp",
        "bmp",
        "tiff",
        "tif",
    ]
)

# Keywords indicating file-analyst intent (vs. file path mentioned incidentally)
_FILE_INTENT_KEYWORDS = frozenset(
    [
        "summarize",
        "סכם",
        "תמצת",
        "analyze",
        "נתח",
        "extract",
        "חלץ",
        "read",
        "קרא",
        "ocr",
        "contract",
        "חוזה",
        "datasheet",
        "datasheet",
        "convert",
        "המר",
        "file",
        "קובץ",
        "document",
        "מסמך",
    ]
)


_OCR_IMAGE_EXTS = frozenset(("jpg", "jpeg", "png", "webp", "bmp", "tiff", "tif"))

# Action dispatch table: (keywords, action) — first match wins.
# OCR is handled separately (keyword OR image extension).
_ACTION_TABLE: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset(("contract", "חוזה")), "contract"),
    (frozenset(("datasheet",)), "datasheet"),
    (frozenset(("summarize", "סכם", "תמצת")), "summarize"),
    (frozenset(("extract", "חלץ")), "extract"),
    (frozenset(("convert", "המר")), "convert"),
)


def _detect_file_action(q_lower: str, ext: str) -> str:
    """Determine file-analyst action from query keywords + file extension."""
    if "ocr" in q_lower or "תמונה" in q_lower or ext in _OCR_IMAGE_EXTS:
        return "ocr"
    for keywords, action in _ACTION_TABLE:
        if any(kw in q_lower for kw in keywords):
            return action
    return "analyze"


def _is_file_path_query(query: str) -> tuple[str, str] | None:
    """Return (path, action) if the query is a file-analyst request, else None.

    action is one of: summarize, ocr, contract, datasheet, analyze, extract, read.
    Detects Windows/Unix/relative paths with supported extensions + intent keyword.
    """
    if not query or len(query) > 500:
        return None
    q_lower = query.lower()
    has_intent = any(kw in q_lower for kw in _FILE_INTENT_KEYWORDS)
    if not has_intent:
        return None

    # Try Windows path first (most specific)
    for pattern in (_WIN_PATH_RE, _UNIX_PATH_RE, _REL_PATH_RE):
        m = pattern.search(query)
        if m:
            path = m.group(1)
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in _FA_EXTENSIONS:
                action = _detect_file_action(q_lower, ext)
                return (path, action)
    return None


# ── Process query detection (for get_process_list / terminate_process) ──────
_PID_RE = re.compile(r"\bPID\s*(\d{2,8})\b", re.IGNORECASE)
_PID_BARE_RE = re.compile(r"\b(\d{3,8})\b")

_PROCESS_INTENT_KEYWORDS = frozenset(
    [
        "process",
        "תהליך",
        "processes",
        "תהליכים",
        "kill",
        "הרוג",
        "terminate",
        "סיים",
        "running",
        "רצים",
        "task",
        "משימה",
    ]
)

_KILL_KEYWORDS = frozenset(["kill", "הרוג", "terminate", "סיים", "end", "עצור"])


def _is_process_query(query: str) -> tuple[str, int | None] | None:
    """Return (action, pid_or_none) if the query is a process request, else None.

    action is "list" (get_process_list) or "kill" (terminate_process).
    pid is None for list queries, int for kill queries.
    """
    if not query or len(query) > 300:
        return None
    q_lower = query.lower()
    if not any(kw in q_lower for kw in _PROCESS_INTENT_KEYWORDS):
        return None

    # Kill intent → need a PID
    if any(kw in q_lower for kw in _KILL_KEYWORDS):
        m = _PID_RE.search(query) or _PID_BARE_RE.search(query)
        if m:
            pid = int(m.group(1))
            if 1 <= pid <= 4194304:  # max PID on Windows
                return ("kill", pid)
        return None

    # List intent
    return ("list", None)


# ── YARA scan detection (for scan_file_yara tool) ───────────────────────────
_YARA_KEYWORDS = frozenset(["yara", "סריקת yara", "yara scan", "yara סריקה"])


def _is_yara_query(query: str) -> str | None:
    """Return the file path if the query is a YARA scan request, else None.

    Requires both a YARA keyword AND a file path with an extension.
    """
    if not query or len(query) > 500:
        return None
    q_lower = query.lower()
    if not any(kw in q_lower for kw in _YARA_KEYWORDS):
        return None
    # Reuse file path detection (any extension — YARA scans any binary)
    for pattern in (_WIN_PATH_RE, _UNIX_PATH_RE, _REL_PATH_RE):
        m = pattern.search(query)
        if m:
            return m.group(1)
    return None


# ── PCAP detection (for pcap-analyst skill) ─────────────────────────────────
_PCAP_EXTENSIONS = frozenset(["pcap", "pcapng"])


def _is_pcap_query(query: str) -> tuple[str, str] | None:
    """Return (path, command) if the query references a .pcap/.pcapng file, else None.

    Deterministic bypass: any file path ending in .pcap or .pcapng routes
    directly to pcap-analyst without LLM semantic matching.
    command defaults to "analyze" (full IOC extraction).
    """
    if not query:
        return None
    for pattern in (_WIN_PATH_RE, _UNIX_PATH_RE, _REL_PATH_RE):
        m = pattern.search(query)
        if m:
            path = m.group(1)
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in _PCAP_EXTENSIONS:
                # Detect sub-command keywords
                q_lower = query.lower()
                if "dns" in q_lower or "dns" in query:
                    return (path, "dns")
                if "sni" in q_lower or "sni" in query:
                    return (path, "sni")
                if "ioc" in q_lower or "ioc" in query:
                    return (path, "iocs")
                return (path, "analyze")
    return None


# ── EML detection (for email-forensics skill) ──────────────────────────────
_EML_EXTENSIONS = frozenset(["eml", "msg"])


def _is_eml_query(query: str) -> tuple[str, str] | None:
    """Return (path, command) if the query references a .eml/.msg file, else None.

    Deterministic bypass: any file path ending in .eml or .msg routes
    directly to email-forensics without LLM semantic matching.
    command defaults to "full" (headers + auth + route + URLs).
    """
    if not query:
        return None
    for pattern in (_WIN_PATH_RE, _UNIX_PATH_RE, _REL_PATH_RE):
        m = pattern.search(query)
        if m:
            path = m.group(1)
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            if ext in _EML_EXTENSIONS:
                q_lower = query.lower()
                if "header" in q_lower or "כותרות" in query:
                    return (path, "headers")
                if "auth" in q_lower or "spf" in q_lower or "dmarc" in q_lower:
                    return (path, "auth")
                if "route" in q_lower or "מסלול" in query:
                    return (path, "route")
                if "url" in q_lower or "קישור" in query:
                    return (path, "urls")
                return (path, "full")
    return None


# ── Unified intent detector ─────────────────────────────────────────────────


def detect_intent(query: str) -> dict | None:
    """Run all routers in priority order. Return first match as a routing decision.

    Returns dict: {"intent": str, "tool": str, "args": dict} or None.
    Priority: IOC > CVE > hash > yara > file_path > process.
    """
    if not query:
        return None

    # 1. IOC (pure IP/hash/domain) → intel-skill
    if _is_ioc_query(query):
        stripped = query.strip()
        try:
            ipaddress.ip_address(stripped)
            return {"intent": "ioc", "tool": "skill_intel-skill", "args": {"command": "ip", "target": stripped}}
        except ValueError:
            pass
        if _HASH_RE.fullmatch(stripped):
            return {
                "intent": "ioc",
                "tool": "skill_intel-skill",
                "args": {"command": "hash", "target": stripped.lower()},
            }
        if " " not in stripped and _DOMAIN_RE.match(stripped):
            return {"intent": "ioc", "tool": "skill_intel-skill", "args": {"command": "domain", "target": stripped}}

    # 2. CVE → osint_hunt
    cve = _is_cve_query(query)
    if cve:
        return {"intent": "cve", "tool": "osint_hunt", "args": {"topic": cve}}

    # 3. Hash with intent keyword → intel-skill hash
    h = _is_hash_query(query)
    if h:
        return {"intent": "hash", "tool": "skill_intel-skill", "args": {"command": "hash", "target": h}}

    # 4. YARA scan → scan_file_yara
    yara_path = _is_yara_query(query)
    if yara_path:
        return {"intent": "yara", "tool": "scan_file_yara", "args": {"filepath": yara_path}}

    # 5. PCAP → pcap-analyst skill (before file_path — specific ext beats generic)
    pcap = _is_pcap_query(query)
    if pcap:
        path, command = pcap
        return {"intent": "pcap", "tool": "skill_pcap-analyst", "args": {"command": command, "path": path}}

    # 5b. EML → email-forensics skill (before file_path — specific ext beats generic)
    eml = _is_eml_query(query)
    if eml:
        path, command = eml
        return {"intent": "eml", "tool": "skill_email-forensics", "args": {"command": command, "path": path}}

    # 6. File path → file-analyst skill
    fa = _is_file_path_query(query)
    if fa:
        path, action = fa
        return {"intent": "file", "tool": "skill_file-analyst", "args": {"command": action, "path": path}}

    # 7. Process → get_process_list or terminate_process
    proc = _is_process_query(query)
    if proc:
        action, pid = proc
        if action == "kill" and pid is not None:
            return {"intent": "process_kill", "tool": "terminate_process", "args": {"pid": pid}}
        return {"intent": "process_list", "tool": "get_process_list", "args": {}}

    return None
