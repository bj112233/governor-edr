"""
_ocr_constants.py — Shared OCR constants, helpers, and the engine Protocol.

Extracted from ocr_engines.py to honour the SRP / ≤300-line file rule.
Windows-service-safe: no heavy imports at module load time.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Protocol

_DEFAULT_OCR_LANG = "eng+heb+ara"


def _safe_print(msg: str) -> None:
    """Print to stderr; swallow Windows pipe errors (Errno 22)."""
    try:
        print(msg, flush=True, file=sys.stderr)
    except OSError:
        pass


def _find_tesseract_binary() -> str | None:
    """Locate tesseract binary across Windows/Linux/macOS."""
    candidates = [
        os.environ.get("TESSERACT_CMD"),
        shutil.which("tesseract"),
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract",
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


def _find_poppler_path() -> str | None:
    """Locate Poppler bin dir (needed by pdf2image on Windows)."""
    if env := os.environ.get("POPPLER_PATH"):
        if os.path.isdir(env):
            return env
    if shutil.which("pdftoppm"):
        return None
    for c in [
        r"C:\poppler\poppler-24.08.0\Library\bin",
        r"C:\Program Files\poppler\Library\bin",
    ]:
        if os.path.isdir(c):
            return c
    return None


class OCREngine(Protocol):
    """Common interface for OCR backends."""

    def ocr_image(self, path: str, lang: str = _DEFAULT_OCR_LANG) -> str: ...

    def ocr_images(
        self, paths: list[str], lang: str = _DEFAULT_OCR_LANG
    ) -> list[str]: ...

    def available(self) -> bool: ...

    def name(self) -> str: ...
