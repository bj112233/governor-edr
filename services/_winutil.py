# services/_winutil.py
"""Shared Windows-specific utilities (single source of truth)."""

from __future__ import annotations

import os
import sys
import sysconfig


def _bootstrap_pywin32_dlls() -> None:
    """Register pywin32 DLL directories so win32evtlog/win32api load in venv.

    pywin32's .pyd extensions (win32evtlog, win32api, etc.) depend on
    pywintypes3XX.dll and pythoncom3XX.dll in pywin32_system32/. In a venv,
    these are not on PATH and Python's DLL search doesn't find them without
    explicit registration via os.add_dll_directory() + sys.path insertion.

    Called once at import time of this module (imported early by services).
    """
    sp = sysconfig.get_paths().get("purelib", "")
    if not sp:
        return
    sys32 = os.path.join(sp, "pywin32_system32")
    win32_dir = os.path.join(sp, "win32")
    if os.path.isdir(sys32):
        try:
            os.add_dll_directory(sys32)
        except OSError:
            pass
    if os.path.isdir(win32_dir) and win32_dir not in sys.path:
        sys.path.insert(0, win32_dir)


_bootstrap_pywin32_dlls()


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
