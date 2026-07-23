"""PDF extraction backends — PyMuPDF, pdfplumber, PyPDF2, OCR fallback.

Extracted from _file_readers.py. read_pdf was F(81) CC — split into
4 focused extractor functions.
"""
import os
import sys

from _hebrew_fix import _fix_custom_font_encoding
from _ocr_pdf import _MAX_PDF_BYTES, _MAX_PDF_PAGES, _looks_like_scanned_pdf, _ocr_pdf
from _text_utils import _DEFAULT_OCR_LANG, _fix_rtl_text

_FINAL_FORMS = "םןץףך"


def _safe_print(msg: str) -> None:
    try:
        print(msg, flush=True, file=sys.stderr)
    except OSError:
        pass


def _has_hebrew(text: str) -> bool:
    return any("\u0590" <= c <= "\u05ff" for c in text)


def _count_visual_order_bad_words(text: str) -> int:
    return sum(
        1 for w in text.split()
        if _has_hebrew(w) and any(c in _FINAL_FORMS for c in w[:2])
    )


def _check_pdf_size(path: str) -> str | None:
    """Return error string if PDF too large, else None."""
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return f"❌ File not accessible: {e}"
    if size > _MAX_PDF_BYTES:
        return (
            f"❌ PDF גדול מדי: {size:,} bytes > מגבלה {_MAX_PDF_BYTES:,}. "
            "הגדל דרך SENTINEL_PDF_MAX_BYTES או חתוך את הקובץ."
        )
    return None


def _extract_pymupdf(path: str, pages: int, lang: str, aggressive_clean: bool) -> str | None:
    """PyMuPDF (fitz) extractor. Returns text or None to fall through."""
    try:
        import fitz
        text = []
        doc = fitz.open(path)
        total = len(doc)
        end = pages or total
        actual_pages = min(end, total, _MAX_PDF_PAGES)
        for idx in range(actual_pages):
            page = doc.load_page(idx)
            text.append(page.get_text())
        doc.close()
        full_text = "\n".join(text).strip()
        print(f"[PDF-DEBUG] PyMuPDF extracted {len(full_text)} chars", flush=True, file=sys.stderr)
        if not full_text:
            return None

        _safe_print(f"[PDF] PyMuPDF extracted {len(full_text)} chars")
        fixed = _fix_custom_font_encoding(full_text, lang=lang)
        print(f"[PDF-DEBUG] Font fix: before={len(full_text)} after={len(fixed)} same={fixed==full_text}", flush=True, file=sys.stderr)
        if fixed != full_text:
            _safe_print("[PDF] PyMuPDF output passed font encoding fix")
            return _fix_rtl_text(fixed) if aggressive_clean else fixed

        if "heb" in lang:
            fixed_rtl = _fix_rtl_text(full_text)
            if fixed_rtl != full_text:
                orig_bad = _count_visual_order_bad_words(full_text)
                fix_bad = _count_visual_order_bad_words(fixed_rtl)
                if fix_bad < orig_bad:
                    _safe_print("[PDF] PyMuPDF output auto-fixed RTL (visual → logical)")
                    return fixed_rtl

        if "heb" in lang and not _has_hebrew(full_text):
            _safe_print("[PDF] PyMuPDF text has no Hebrew Unicode — falling through")
            return None
        if aggressive_clean and "heb" in lang:
            return _fix_rtl_text(full_text)
        return full_text
    except Exception as e:
        _safe_print(f"[PDF] PyMuPDF failed: {e}")
        return None


def _pdfplumber_extract_text(path: str, pages: int) -> tuple[str, int, float] | None:
    """Extract text via pdfplumber. Returns (raw_text, actual_pages, image_ratio) or None."""
    try:
        import pdfplumber
    except ImportError:
        return None
    try:
        pdf_texts: list[str] = []
        actual_pages = 0
        image_ratio = 0.0
        with pdfplumber.open(path) as pdf:
            total = len(pdf.pages)
            end = pages or total
            actual_pages = min(end, total, _MAX_PDF_PAGES)
            for i in range(actual_pages):
                page = pdf.pages[i]
                page_text = page.extract_text() or ""
                lines = page_text.split("\n")
                cleaned_lines = []
                for line in lines:
                    line = " ".join(line.split())
                    if len(line) > 3:
                        cleaned_lines.append(line)
                pdf_texts.append("\n".join(cleaned_lines))
            try:
                total_images = sum(len(page.images or []) for page in pdf.pages[:actual_pages])
                image_ratio = total_images / max(actual_pages, 1)
            except Exception:
                pass
        raw = "\n\n".join(pdf_texts)
        print(f"[PDF-DEBUG] pdfplumber extracted {len(raw)} chars, image_ratio={image_ratio}", flush=True, file=sys.stderr)
        return (raw, actual_pages, image_ratio)
    except FileNotFoundError:
        return f"❌ File not found: {path}"
    except Exception as e:
        print(f"[PDF-DEBUG] pdfplumber extract exception: {type(e).__name__}: {e}", flush=True, file=sys.stderr)
        msg = str(e).lower()
        if "encrypted" in msg or "password" in msg:
            return f"❌ PDF מוצפן/מוגן בסיסמה: {path}"
        if "utf-8" in msg or "codec" in msg:
            return "❌ שגיאת קידוד בקריאת PDF: הקובץ עלול להיות פגום. נסה לפתוח אותו בקורא PDF חיצוני."
        return None


def _try_ocr_scanned(
    path: str, pages: int, lang: str, engine_name: str,
    ocr: bool, auto_ocr: bool, looks_scanned: bool,
) -> str | None:
    """Try OCR if PDF looks scanned and OCR is enabled. Returns OCR text or None."""
    if not ((ocr or auto_ocr) and looks_scanned):
        if looks_scanned and not ocr and not auto_ocr:
            _safe_print("[PDF] Hint: PDF looks scanned. Use --ocr to force OCR")
        return None
    print("[PDF-DEBUG] Entering OCR path", flush=True, file=sys.stderr)
    _safe_print(f"[PDF] Triggering OCR for scanned/image-only PDF: {path}")
    try:
        ocr_result = _ocr_pdf(path, pages, lang, engine_name=engine_name)
        print(f"[PDF-DEBUG] OCR returned: len={len(ocr_result)} starts_with_error={ocr_result.startswith('❌') if ocr_result else 'N/A'}", flush=True, file=sys.stderr)
    except Exception as ocr_e:
        print(f"[PDF-DEBUG] OCR EXCEPTION: {type(ocr_e).__name__}: {ocr_e}", flush=True, file=sys.stderr)
        ocr_result = f"❌ OCR failed: {ocr_e}"
    _safe_print(f"[PDF] OCR result: {ocr_result[:100] if ocr_result else 'None'}...")
    if ocr_result and not ocr_result.startswith("❌"):
        _safe_print(f"[PDF] OCR succeeded: {len(ocr_result)} chars")
        return ocr_result
    _safe_print("[PDF] OCR failed, using best extraction")
    print("[PDF-DEBUG] OCR returned error, continuing", flush=True, file=sys.stderr)
    return None


def _try_hebrew_ocr_fallback(
    path: str, pages: int, lang: str, engine_name: str,
    auto_ocr: bool, best: str,
) -> str | None:
    """Force OCR when Hebrew requested but no Unicode Hebrew found. Returns text or None.

    Only triggers when the extracted text is sparse (<200 chars/page) — a PDF
    with 67042 chars of clean English is NOT a Hebrew scan and should NOT be
    OCR'd. The purpose of this fallback is for PDFs where the text extractor
    returns Latin-encoded Hebrew (custom font) or near-empty output.
    """
    if not (auto_ocr and "heb" in lang and not _has_hebrew(best)):
        return None
    # Guard: if we already have substantial text, it's a real non-Hebrew document
    # (English, Arabic, etc.). Don't waste 20+ seconds OCR-ing it into garbage.
    if len(best) > 200:
        _safe_print(
            f"[PDF] No Hebrew Unicode but text is substantial ({len(best)} chars) "
            "— likely non-Hebrew document, skipping Hebrew OCR fallback"
        )
        return None
    _safe_print("[PDF] Hebrew requested but no Unicode Hebrew found — forcing OCR")
    ocr_result = _ocr_pdf(path, pages, lang, engine_name=engine_name)
    if ocr_result and not ocr_result.startswith("❌"):
        _safe_print(f"[PDF] OCR fallback succeeded: {len(ocr_result)} chars")
        return ocr_result
    _safe_print("[PDF] OCR fallback failed, continuing with extraction")
    return None


def _apply_font_fix_or_rtl(best: str, lang: str, aggressive_clean: bool) -> str:
    """Apply custom font encoding fix and/or RTL fix as last resort."""
    fixed = _fix_custom_font_encoding(best, lang=lang)
    _safe_print(f"[PDF-DEBUG] Last-resort font fix: same={fixed==best} len_before={len(best)} len_after={len(fixed)}")
    if fixed != best:
        _safe_print(f"[PDF] Applied font encoding fix: {len(fixed)} chars")
        return _fix_rtl_text(fixed) if aggressive_clean else fixed
    if aggressive_clean and "heb" in lang:
        return _fix_rtl_text(best)
    return best


def _extract_pdfplumber(
    path: str, pages: int, lang: str, aggressive_clean: bool,
    ocr: bool, auto_ocr: bool, engine_name: str,
) -> str | None:
    """pdfplumber extractor with OCR fallback. Returns text or None to fall through."""
    result = _pdfplumber_extract_text(path, pages)
    if result is None:
        return None
    if isinstance(result, str):  # error string from _pdfplumber_extract_text
        return result

    raw, actual_pages, image_ratio = result
    best = raw

    looks_scanned = _looks_like_scanned_pdf(best, num_pages=actual_pages, image_ratio=image_ratio)
    _safe_print(f"[PDF] _looks_like_scanned_pdf(best)={looks_scanned}")
    print(f"[PDF-DEBUG] Decision: ocr={ocr} auto_ocr={auto_ocr} looks_scanned={looks_scanned}", flush=True, file=sys.stderr)

    ocr_text = _try_ocr_scanned(path, pages, lang, engine_name, ocr, auto_ocr, looks_scanned)
    if ocr_text is not None:
        return ocr_text

    hebrew_ocr = _try_hebrew_ocr_fallback(path, pages, lang, engine_name, auto_ocr, best)
    if hebrew_ocr is not None:
        return hebrew_ocr

    return _apply_font_fix_or_rtl(best, lang, aggressive_clean)


def _extract_pypdf2(path: str, pages: int, aggressive_clean: bool, ocr: bool, auto_ocr: bool) -> str:
    """pypdf last-resort extractor (migrated from deprecated PyPDF2)."""
    print("[PDF-DEBUG] Entering pypdf fallback path", flush=True, file=sys.stderr)
    try:
        import pypdf
    except ImportError:
        return "❌ No PDF library installed (pip install pdfplumber pypdf)."
    try:
        text = []
        with open(path, "rb") as f:
            reader = pypdf.PdfReader(f)
            if reader.is_encrypted:
                return f"❌ PDF מוצפן: {path}"
            total = len(reader.pages)
            end = pages or total
            for i in range(min(end, total, _MAX_PDF_PAGES)):
                page = reader.pages[i]
                page_text = page.extract_text() or ""
                page_text = page_text.replace("\x00", "")
                lines = page_text.split("\n")
                cleaned_lines = []
                for line in lines:
                    line = " ".join(line.split())
                    if len(line) > 3:
                        cleaned_lines.append(line)
                text.append("\n".join(cleaned_lines))
        raw = "\n\n".join(text)
        print(f"[PDF-DEBUG] pypdf extracted {len(raw)} chars", flush=True, file=sys.stderr)
        if _looks_like_scanned_pdf(raw, num_pages=min(pages or total, total)):
            if ocr or auto_ocr:
                ocr_result = _ocr_pdf(path, pages)
                if ocr_result and not ocr_result.startswith("❌"):
                    return ocr_result
            return (
                "⚠️ PDF ללא טקסט הניתן לחילוץ — ייתכן שמדובר במסמך סרוק. "
                "נסה שוב עם --ocr (auto-OCR נכשל או לא זמין)."
            )
        return _fix_rtl_text(raw) if aggressive_clean else raw
    except FileNotFoundError:
        return f"❌ File not found: {path}"
    except Exception as e:
        return f"❌ PDF read error: {e}"
