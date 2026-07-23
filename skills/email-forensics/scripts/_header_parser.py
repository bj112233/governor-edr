"""Email header parser — Received chain + SPF/DKIM/DMARC analysis.

Parses the Authentication-Results header (already verified by the receiving
server) rather than re-verifying DKIM ourselves — the receiving MTA did the
work, we just extract the verdict.

Also extracts the Received chain (routing path: who→whom, hops, timestamps).
"""

from __future__ import annotations

import email
import email.policy
import re
from email.message import Message
from typing import Any

# Regexes for parsing Authentication-Results
_SPF_RE = re.compile(r"spf=(\w+)\s", re.IGNORECASE)
_DKIM_RE = re.compile(r"dkim=(\w+)\s", re.IGNORECASE)
_DMARC_RE = re.compile(r"dmarc=(\w+)\s", re.IGNORECASE)

# Received header field extractors
_RECEIVED_FROM_RE = re.compile(r"from\s+(.+?)\s+by\s+", re.IGNORECASE)
_RECEIVED_BY_RE = re.compile(r"by\s+(.+?)(?:\s+with|\s+for|$)", re.IGNORECASE)
_RECEIVED_FOR_RE = re.compile(r"for\s+<(.+?)>", re.IGNORECASE)
_RECEIVED_DATE_RE = re.compile(r";\s*(.+)$")


def load_message(path: str) -> Message:
    """Load an .eml file into an email.Message object (stdlib only)."""
    with open(path, "rb") as fh:
        return email.message_from_binary_file(fh, policy=email.policy.default)


def parse_auth_results(msg: Message) -> dict[str, Any]:
    """Extract SPF/DKIM/DMARC verdicts from Authentication-Results headers.

    Returns dict with keys: spf, dkim, dmarc (each: pass/fail/none/softfail/...).
    Falls back to 'none' if header absent (no auth performed / not recorded).
    """
    auth_headers = msg.get_all("Authentication-Results", [])
    combined = " ".join(auth_headers) if auth_headers else ""

    spf = _extract_verdict(_SPF_RE, combined)
    dkim = _extract_verdict(_DKIM_RE, combined)
    dmarc = _extract_verdict(_DMARC_RE, combined)

    # Fallback: check standalone SPF/DKIM result headers
    if spf == "none":
        received_spf = msg.get("Received-SPF", "")
        if received_spf:
            spf = received_spf.split()[0].lower() if received_spf.split() else "none"

    return {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "raw": combined[:500] if combined else "(no Authentication-Results header)",
    }


def _extract_verdict(regex: re.Pattern, text: str) -> str:
    """Extract first match from regex, return 'none' if not found."""
    m = regex.search(text)
    return m.group(1).lower() if m else "none"


def parse_received_chain(msg: Message) -> list[dict[str, str]]:
    """Parse Received headers into a routing chain (bottom-up = oldest first).

    Each hop: {from, by, for, date, raw}
    """
    received_headers = msg.get_all("Received", [])
    hops: list[dict[str, str]] = []
    for raw in received_headers:
        hop = _parse_single_received(raw)
        hop["raw"] = raw[:200]
        hops.append(hop)
    # Reverse: Received headers are top-down (newest first); we want oldest first
    hops.reverse()
    return hops


def _parse_single_received(raw: str) -> dict[str, str]:
    """Parse a single Received header into structured fields."""
    from_match = _RECEIVED_FROM_RE.search(raw)
    by_match = _RECEIVED_BY_RE.search(raw)
    for_match = _RECEIVED_FOR_RE.search(raw)
    date_match = _RECEIVED_DATE_RE.search(raw)

    return {
        "from": from_match.group(1).strip() if from_match else "?",
        "by": by_match.group(1).strip() if by_match else "?",
        "for": for_match.group(1).strip() if for_match else "",
        "date": date_match.group(1).strip() if date_match else "?",
    }


def get_key_headers(msg: Message) -> dict[str, str]:
    """Extract the most forensically relevant headers (truncated for 16K budget)."""
    important = [
        "From", "To", "Cc", "Subject", "Date", "Message-ID",
        "Reply-To", "Return-Path", "Sender",
        "X-Mailer", "X-Originating-IP", "X-Spam-Status",
        "Authentication-Results", "Received-SPF",
    ]
    result: dict[str, str] = {}
    for header in important:
        value = msg.get(header)
        if value:
            result[header] = str(value)[:300]
    return result
