# services/_winutil.py
"""Shared Windows-specific utilities (single source of truth)."""

from __future__ import annotations


def _decode_oem(data: bytes) -> str:
    """Decode subprocess output — UTF-8 first, then Windows OEM fallback.

    Skills (Python scripts) write UTF-8; CMD native tools (wevtutil/
    schtasks/reg/netsh) use the OEM codepage. Trying UTF-8 first avoids
    Mojibake when a skill prints Hebrew, emoji, or other multi-byte chars.
    """
    if not data:
        return ""
    # 1. Try UTF-8 first — most skills write UTF-8
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    # 2. Fall back to Windows OEM codepages (CMD native tools)
    for enc in ("oem", "cp862", "cp1255"):
        try:
            return data.decode(enc)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")
