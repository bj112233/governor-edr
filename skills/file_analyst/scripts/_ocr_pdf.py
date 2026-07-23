"""
OCR PDF — scanned PDF detection and OCR fallback.
"""

import os

from _text_utils import _clean_ocr_hebrew

_MAX_PDF_BYTES = int(
    os.getenv("SENTINEL_PDF_MAX_BYTES", str(50 * 1024 * 1024))
)  # 50 MB
_MAX_PDF_PAGES = int(os.getenv("SENTINEL_PDF_MAX_PAGES", "1000"))


def _ocr_pdf(
    path: str,
    pages: int = 0,
    lang: str = "eng+heb+ara",
    engine_name: str = "auto",
) -> str:
    """OCR fallback for scanned PDFs via Tesseract 5.x (Sentinel's sole OCR backend)."""
    # DEBUG MARKER
    try:
        import sys
        print("[OCR] DEBUG: _ocr_pdf v2026-06-18-f35091e loaded", flush=True, file=sys.stderr)
    except Exception:
        pass
    try:
        from ocr_engines import get_engine, ocr_pdf_pages
    except ImportError:
        return "❌ ocr_engines module not found."
    try:
        engine = get_engine(preferred=engine_name, lang=lang)
    except RuntimeError as e:
        return f"❌ {e}"
    raw = ocr_pdf_pages(path, pages=pages, lang=lang, engine=engine)
    if raw.startswith("❌") or raw.startswith("⚠️"):
        return raw

    # Fallback: if Hebrew was requested but OCR produced no Hebrew Unicode,
    # retry with 'heb' only.  Multi-language models (eng+heb+ara) sometimes
    # prioritize Latin over Hebrew on low-quality scans.
    if (
        "heb" in lang
        and lang != "heb"
        and not any("\u0590" <= c <= "\u05ff" for c in raw)
    ):
        print(
            "[OCR] No Hebrew Unicode found with multi-lang model, retrying with 'heb' only...",
            flush=True, file=sys.stderr,
        )
        raw_heb = ocr_pdf_pages(path, pages=pages, lang="heb", engine=engine)
        if raw_heb and not raw_heb.startswith("❌") and any(
            "\u0590" <= c <= "\u05ff" for c in raw_heb
        ):
            print("[OCR] Hebrew-only model succeeded.", flush=True, file=sys.stderr)
            return _clean_ocr_hebrew(raw_heb)
        print("[OCR] Hebrew-only model also failed, keeping original.", flush=True, file=sys.stderr)

    # NOTE: _fix_custom_font_encoding is intentionally NOT applied here.
    # It is designed for PDF extractors (PyMuPDF/pdfplumber) where custom
    # fonts map Hebrew glyphs to Latin character codes.  Tesseract already
    # returns real Unicode Hebrew; applying the fix would corrupt English
    # drug names (e.g. FERROUS → פאררווס).
    if "heb" in lang:
        return _clean_ocr_hebrew(raw)
    return raw


def _looks_like_scanned_pdf(
    text: str, expected_min_chars_per_page: int = 50, num_pages: int = 1, image_ratio: float | None = None
) -> bool:
    """Detect if a PDF is likely scanned (image-only).

    Uses two signals:
      1. Text density (chars per page).
      2. Image-to-page ratio from pdfplumber (if provided).

    image_ratio dominates: if ≥50% of pages contain images, the PDF is
    almost certainly scanned regardless of how much metadata/form-field
    text pdfplumber managed to extract.
    """
    if not text or not text.strip():
        return True
    # Image-heavy documents are ALWAYS scanned, even if some text was
    # extracted from form fields or annotations.
    if image_ratio is not None and image_ratio > 0.5:
        return True
    avg_chars = len(text.strip()) / max(num_pages, 1)
    if avg_chars < expected_min_chars_per_page:
        if avg_chars < 10:
            return True
        # Borderline: likely a cover page / sparse slide — don't force OCR
        return False
    return False


def ocr_pdf_force(path: str, pages: int = 0, engine_name: str = "auto") -> str:
    """Force-run OCR on every page of a PDF (bypasses scanned-PDF heuristic)."""
    if not os.path.isfile(path):
        return f"❌ File not found: {path}"
    if os.path.getsize(path) > _MAX_PDF_BYTES:
        return f"❌ PDF גדול מדי ל-OCR ({os.path.getsize(path):,} bytes)."
    raw = _ocr_pdf(path, pages or 0, engine_name=engine_name)
    if raw.startswith("❌"):
        return raw
    return raw
