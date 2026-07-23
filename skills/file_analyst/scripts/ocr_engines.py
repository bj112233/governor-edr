"""
ocr_engines.py — Abstraction over OCR backends (facade).

Sentinel runs a single OCR backend: Tesseract 5.x (CPU-only, requires the
external tesseract binary, ships heb_best.traineddata for Hebrew). EasyOCR
was removed — abandoned upstream, no Hebrew model, and its PyTorch
dependency competed with the LLM for the 6GB VRAM budget.

This module is a thin facade re-exporting the split sub-modules so existing
call sites (`from ocr_engines import ...`) keep working unchanged:
    _ocr_constants   — constants, helpers, OCREngine Protocol
    _ocr_tesseract   — TesseractEngine
    _ocr_factory     — get_engine
    _ocr_pdf_pages   — ocr_pdf_pages
"""

from __future__ import annotations

from _ocr_constants import (
    OCREngine,
    _DEFAULT_OCR_LANG,
    _find_poppler_path,
    _find_tesseract_binary,
    _safe_print,
)
from _ocr_factory import get_engine
from _ocr_pdf_pages import ocr_pdf_pages
from _ocr_tesseract import TesseractEngine

__all__ = [
    "OCREngine",
    "TesseractEngine",
    "get_engine",
    "ocr_pdf_pages",
    "_DEFAULT_OCR_LANG",
    "_find_poppler_path",
    "_find_tesseract_binary",
    "_safe_print",
]
