"""Hebrew-aware encoding detection and normalization for legacy sites."""

from __future__ import annotations

def _looks_like_hebrew_mojibake(text: str, sample_size: int = 2000) -> bool:
    """Detect if Hebrew text was decoded as cp1252/latin-1 (mojibake heuristic)."""
    if not text:
        return False
    sample = text[:sample_size]
    # Mojibake from cp1255 -> latin-1 produces high concentration of chars in 0xA0-0xFF range
    high_bytes = sum(1 for c in sample if 0xA0 <= ord(c) <= 0xFF)
    return high_bytes / max(len(sample), 1) > 0.10


def _normalize_hebrew_encoding(content: bytes, declared_encoding: str | None) -> str:
    """Decode response bytes preferring UTF-8, fallback to cp1255 for legacy Hebrew sites."""
    for enc in [declared_encoding, "utf-8", "cp1255", "windows-1255", "iso-8859-8"]:
        if not enc:
            continue
        try:
            decoded = content.decode(enc, errors="strict")
            if not _looks_like_hebrew_mojibake(decoded):
                return decoded
        except (UnicodeDecodeError, LookupError):
            continue
    return content.decode("utf-8", errors="replace")
