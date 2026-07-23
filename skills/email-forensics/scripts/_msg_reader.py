"""Outlook .msg reader — extracts headers + body from .msg files.

Uses extract-msg (optional dependency). Gracefully degrades if not installed.
"""

from __future__ import annotations

from typing import Any

try:
    import extract_msg  # type: ignore[import-not-found,unused-ignore]
    _EXTRACT_MSG_AVAILABLE = True
except ImportError:
    _EXTRACT_MSG_AVAILABLE = False


def is_msg_available() -> bool:
    """True if extract-msg is installed."""
    return _EXTRACT_MSG_AVAILABLE


def load_msg(path: str) -> dict[str, Any]:
    """Load a .msg file and return headers + body as a dict.

    Returns dict with: subject, sender, to, date, body, headers (dict).
    Raises RuntimeError if extract-msg not installed.
    """
    if not _EXTRACT_MSG_AVAILABLE:
        return {
            "error": (
                "❌ .msg support requires 'extract-msg' package. "
                "Install: pip install extract-msg"
            )
        }

    msg = extract_msg.Message(path)
    try:
        headers: dict[str, str] = {}
        # extract-msg exposes header dict
        if hasattr(msg, "header"):
            raw_headers = msg.header
            if isinstance(raw_headers, str):
                # Parse raw header string into dict
                for line in raw_headers.split("\r\n"):
                    if ":" in line:
                        key, _, value = line.partition(":")
                        headers[key.strip()] = value.strip()
            elif isinstance(raw_headers, dict):
                headers = {k: str(v) for k, v in raw_headers.items()}

        return {
            "subject": msg.subject or "",
            "sender": msg.sender or "",
            "to": msg.to or "",
            "date": msg.date or "",
            "body": msg.body or "",
            "headers": headers,
        }
    finally:
        msg.close()
