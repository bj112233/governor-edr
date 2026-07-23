"""Email body extractor — text/html parts + URL/IP extraction.

Handles multipart MIME (text/plain + text/html). Extracts URLs and IPs
from both text and HTML bodies. Uses html2text for HTML→text conversion.
"""

from __future__ import annotations

import ipaddress
import re
from email.message import Message
from typing import Any

try:
    import html2text
    _H2T = html2text.HTML2Text()
    _H2T.ignore_links = False
    _H2T.body_width = 0
    _HTML2TEXT_AVAILABLE = True
except ImportError:
    _HTML2TEXT_AVAILABLE = False

# IOC extraction regexes
_URL_RE = re.compile(
    r"https?://[^\s<>\"'\\]+",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Trailing chars to strip from URLs (HTML artifacts: ) ] , ; .)
_URL_TRAILING_CHARS = ")]},;.!\"'"


def extract_body(msg: Message) -> dict[str, str]:
    """Extract text and HTML body parts from a (possibly multipart) message.

    Returns {"text": str, "html": str, "html_as_text": str}.
    """
    text_parts: list[str] = []
    html_parts: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type == "text/plain":
                text_parts.append(_decode_part(part))
            elif content_type == "text/html":
                html_parts.append(_decode_part(part))
    else:
        ct = msg.get_content_type()
        body = _decode_part(msg)
        if ct == "text/html":
            html_parts.append(body)
        else:
            text_parts.append(body)

    text = "\n".join(text_parts)
    html = "\n".join(html_parts)
    html_as_text = ""
    if html and _HTML2TEXT_AVAILABLE:
        html_as_text = _H2T.handle(html)
    elif html:
        # Fallback: strip tags crudely
        html_as_text = re.sub(r"<[^>]+>", " ", html)

    return {"text": text, "html": html, "html_as_text": html_as_text}


def _decode_part(part: Message) -> str:
    """Decode a message part handling charset + transfer encoding."""
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    # get_payload(decode=True) returns bytes (or None); guard for type safety
    if not isinstance(payload, (bytes, bytearray)):
        return str(payload)
    charset = part.get_content_charset() or "utf-8"
    try:
        return bytes(payload).decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return bytes(payload).decode("utf-8", errors="replace")


def extract_urls_and_ips(text: str) -> dict[str, list[str]]:
    """Extract unique URLs, IPs, and email addresses from text.

    Returns {"urls": [...], "ips": [...], "emails": [...]} — all deduplicated.
    """
    urls = set(_clean_url(u) for u in _URL_RE.findall(text))
    ips = set()
    for ip_str in _IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(ip_str)
            ips.add(ip_str)
        except ValueError:
            pass
    emails = set(_EMAIL_RE.findall(text))

    # Filter out trivial/private IPs from the IOC list
    public_ips = sorted(ip for ip in ips if not _is_private(ip))

    return {
        "urls": sorted(urls),
        "ips": public_ips,
        "emails": sorted(emails),
    }


def _is_private(ip_str: str) -> bool:
    """True if IP is private/loopback/link-local (not a useful IOC)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return True


def _clean_url(url: str) -> str:
    """Strip trailing punctuation/artifacts from URL (HTML parsing residue)."""
    while url and url[-1] in _URL_TRAILING_CHARS:
        url = url[:-1]
    return url
