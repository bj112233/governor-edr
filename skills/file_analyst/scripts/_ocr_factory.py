"""
_ocr_factory.py — OCR engine selection logic.

Sentinel runs a single OCR backend: Tesseract 5.x. EasyOCR was removed
(abandoned Sept 2024, no Hebrew model, pulled PyTorch into a 6GB VRAM
budget competing with the LLM). Tesseract handles both Hebrew
(heb_best.traineddata) and LTR langs on CPU, leaving the GPU free for
the LLM.

`preferred` is retained for backward CLI compatibility (`--ocr-engine
auto`, `--ocr-engine tesseract`, and the legacy `--ocr-engine easyocr`
all resolve to Tesseract).
"""

from __future__ import annotations

from _ocr_constants import OCREngine, _DEFAULT_OCR_LANG, _safe_print
from _ocr_tesseract import TesseractEngine

# Module-level singleton — avoids rebuilding TesseractEngine (and
# re-scanning PATH / candidate binaries) on every OCR call.
_engine: TesseractEngine | None = None


def get_engine(preferred: str = "auto", lang: str = _DEFAULT_OCR_LANG) -> OCREngine:
    """Return the (memoized) Tesseract OCR engine.

    Args:
        preferred: accepted for CLI compatibility ('auto' | 'tesseract'
            | 'easyocr'). 'easyocr' logs a deprecation notice and falls
            back to Tesseract — never raises on a legacy value.
        lang: Tesseract language string (e.g. 'eng+heb+ara'). Currently
            unused for engine selection (single backend) but retained
            for API stability.
    """
    global _engine
    if preferred not in ("auto", "tesseract"):
        _safe_print(
            f"[OCR] Engine '{preferred}' is no longer supported; "
            "Sentinel is Tesseract-only. Falling back to tesseract."
        )
    if _engine is not None and _engine.available():
        return _engine
    tess = TesseractEngine()
    if tess.available():
        _engine = tess
        _safe_print(f"[OCR] Selected engine: {tess.name()}")
        return tess
    # Distinguish "binary missing" from "pytesseract package missing" so
    # the error message points the user at the right fix.
    try:
        import pytesseract  # noqa: F401
    except ImportError:
        raise RuntimeError(
            "OCR unavailable: the 'pytesseract' Python package is not "
            "installed. Run: pip install pytesseract Pillow"
        )
    raise RuntimeError(
        "OCR unavailable: Tesseract binary not found. Install Tesseract 5.x "
        "and ensure it is on PATH or at one of the standard locations "
        "(see _find_tesseract_binary in _ocr_constants.py)."
    )
