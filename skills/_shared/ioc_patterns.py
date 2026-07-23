# skills/_shared/ioc_patterns.py
"""Single Source of Truth for IOC regex patterns — Pure Python, zero dependencies.

Importable from both services/ (main process) and skills/ (subprocess sandbox).
Only imports `re` (stdlib) — no Pydantic, httpx, or services imports.

Pre-compiled at module load for O(1) reuse across thousands of scans.
"""

import re

__all__ = [
    "IPV4_RE",
    "IPV6_RE",
    "DOMAIN_RE",
    "HASH_RE",
    "CVE_RE",
    "URL_RE",
    "CIDR_RE",
    "ASN_RE",
    "EMAIL_RE",
    "URL_TRAILING_PUNCT",
    "BAD_DOMAINS",
]

# ── Pre-compiled regexes (module-level, O(1) reuse) ──

# IPv4: strict 4 octets, 0-255 per octet
IPV4_RE = re.compile(
    r"\b(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\."
    r"(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\."
    r"(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\."
    r"(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\b"
)

# IPv6: compressed or full, with/without brackets.
# Order matters: longer patterns (trailing group) before shorter (trailing :).
IPV6_RE = re.compile(
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"
    r"::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}:(?:\d{1,3}\.){3}\d{1,3}"
)

# Domains: excludes common false positives (file extensions, protocol prefixes)
# Allow punycode (xn--) and subdomains
DOMAIN_RE = re.compile(
    r"\b(?:xn--[a-zA-Z0-9-]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.(?:xn--[a-zA-Z0-9-]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))+\b"
)

# MD5 (32), SHA1 (40), SHA256 (64)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

# CVE format: CVE-YYYY-NNNN(+)  e.g. CVE-2024-1234 or CVE-2024-12345
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# URLs — keep query/fragment/params. Trailing punctuation stripped post-match.
URL_RE = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^\s]*)?")

# CIDR a.b.c.d/prefix — validated to 0<=prefix<=32 in caller
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")

# ASN — AS + 1..6 digits (case-insensitive)
ASN_RE = re.compile(r"\bAS\d{1,6}\b", re.IGNORECASE)

# Email — local@domain (RFC 5322 lite)
EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

# Trailing chars commonly glued to URLs in prose — strip after match
URL_TRAILING_PUNCT = ".,;:!?)\"'"

# False-positive domains (file extensions that look like TLDs).
# NOTE: Do NOT include real TLDs (com, net, org, io, etc.) — those are valid
# domain suffixes and filtering them would drop legitimate IOCs like "evil.com".
BAD_DOMAINS = frozenset(
    [
        "html",
        "htm",
        "xml",
        "json",
        "pdf",
        "jpg",
        "jpeg",
        "png",
        "gif",
        "css",
        "js",
        "php",
        "asp",
        "aspx",
        "jsp",
        "exe",
        "dll",
        "zip",
        "rar",
        "tar",
        "gz",
        "txt",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
    ]
)
