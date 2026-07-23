# services/credential_patterns.py
"""Credential pattern detection — pure regex, no I/O.

5 families + generic API keys. Used by credential_monitor.py.
Separated for SRP (Single Responsibility Principle).
"""

import re

# ── 5 Credential Regex Families ──────────────────────────────────

# 1. Email:password pairs (most common leak format)
_EMAIL_PASS_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[:\s|,;]+[^\s|,;]{4,64}",
    re.IGNORECASE,
)

# 2. AWS Access Keys
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")

# 3. Private keys (RSA, EC, OPENSSH, DSA)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
)

# 4. JWT tokens
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

# 5. Database connection strings
_DB_CONN_RE = re.compile(
    r"(?:mysql|postgresql|mongodb|redis|mssql)://[^\s:]+:[^\s@]+@[^\s/]+",
    re.IGNORECASE,
)

# Bonus: generic API key markers (high-signal)
_API_KEY_RE = re.compile(
    r"(?:api[_-]?key|sk[_-]|Bearer|token)[\"\s:=]+([A-Za-z0-9_-]{20,64})",
    re.IGNORECASE,
)


def extract_credentials(text: str) -> dict[str, list[str]]:
    """Extract credential patterns from text. Returns dict of type → matches.

    5 families + generic API keys. All non-overlapping, deduplicated.
    """
    if not text:
        return {}

    results: dict[str, list[str]] = {}

    def _dedup(matches: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                out.append(m)
        return out

    email_pass = _EMAIL_PASS_RE.findall(text)
    if email_pass:
        results["email_password"] = _dedup(email_pass)[:20]

    aws_keys = _AWS_KEY_RE.findall(text)
    if aws_keys:
        results["aws_access_key"] = _dedup(aws_keys)[:10]

    priv_keys = _PRIVATE_KEY_RE.findall(text)
    if priv_keys:
        results["private_key"] = _dedup(priv_keys)[:5]

    jwts = _JWT_RE.findall(text)
    if jwts:
        results["jwt_token"] = _dedup(jwts)[:10]

    db_conns = _DB_CONN_RE.findall(text)
    if db_conns:
        results["db_connection"] = _dedup(db_conns)[:10]

    api_key_matches = _API_KEY_RE.findall(text)
    if api_key_matches:
        results["api_key"] = _dedup(api_key_matches)[:10]

    return results


def mask_credential(value: str) -> str:
    """Mask credential value for safe display. Shows first 4 + last 4 chars."""
    if len(value) <= 12:
        return value[:2] + "***" + value[-2:] if len(value) > 4 else "***"
    return value[:4] + "..." + value[-4:]
