"""
_ocr_pdf_pages.py — PDF → images → OCR pipeline.

Extracted from ocr_engines.py. Handles pdf2image conversion, Hebrew-specific
preprocessing, and delegation to the selected OCR engine.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from _ocr_constants import (
    OCREngine,
    _DEFAULT_OCR_LANG,
    _find_poppler_path,
    _safe_print,
)


def _preprocess_image(img):
    """Grayscale → contrast → sharpen → mild denoise (Hebrew OCR quality)."""
    from PIL import ImageEnhance, ImageFilter

    gray = img.convert("L")
    # Increase contrast
    enhancer = ImageEnhance.Contrast(gray)
    gray = enhancer.enhance(2.0)
    # Sharpen
    gray = gray.filter(ImageFilter.SHARPEN)
    # Mild denoise
    gray = gray.filter(ImageFilter.MedianFilter(size=3))
    return gray


def _convert_pdf_to_images(path: str, kwargs: dict):
    """Run pdf2image conversion, returning error string on failure."""
    from pdf2image import convert_from_path  # type: ignore

    try:
        return convert_from_path(path, **kwargs)
    except Exception as e:
        return f"❌ PDF conversion failed: {e}"


def _save_page_images(images, tmp_dir: str, max_pages: int, lang: str) -> list[str]:
    """Persist page images to disk, applying Hebrew preprocessing when needed."""
    image_paths: list[str] = []
    for i, img in enumerate(images[:max_pages]):
        img_path = Path(tmp_dir) / f"page_{i:04d}.png"
        proc = _preprocess_image(img) if "heb" in lang else img
        proc.save(img_path)
        image_paths.append(str(img_path))
    return image_paths


def ocr_pdf_pages(
    path: str,
    pages: int = 0,
    lang: str = _DEFAULT_OCR_LANG,
    engine: OCREngine | None = None,
    dpi: int = 300,
    timeout: int = 30,
) -> str:
    """Convert PDF → images → OCR with chosen engine."""
    try:
        from pdf2image import convert_from_path  # noqa: F401  # type: ignore
    except ImportError:
        return (
            "❌ OCR לא זמין. התקן: pip install pdf2image\n"
            "   ודא שמותקן Poppler (pdf2image requirement)."
        )

    if engine is None:
        try:
            from _ocr_factory import get_engine

            engine = get_engine()
        except RuntimeError as e:
            return f"❌ {e}"

    # Use 400 DPI for Hebrew medical scans — significantly improves
    # Tesseract accuracy on small/blurry text.
    effective_dpi = max(dpi, 400) if "heb" in lang else dpi
    max_pages = pages if pages else 5
    kwargs: dict = {"last_page": max_pages, "dpi": effective_dpi}
    poppler = _find_poppler_path()
    if poppler:
        kwargs["poppler_path"] = poppler

    _safe_print(
        f"[OCR] Converting PDF to images (dpi={effective_dpi}, max_pages={max_pages})..."
    )

    # Direct synchronous call — no ThreadPoolExecutor (caused shutdown deadlock).
    # `timeout` arg kept for API compatibility but not enforced here.
    images = _convert_pdf_to_images(path, kwargs)
    if isinstance(images, str):
        return images

    _safe_print(f"[OCR] Got {len(images)} images, preprocessing...")

    # TemporaryDirectory guarantees cleanup even on OCR failure / KeyboardInterrupt.
    with tempfile.TemporaryDirectory(prefix="ocr_pdf_") as tmp_dir:
        image_paths = _save_page_images(images, tmp_dir, max_pages, lang)
        texts = engine.ocr_images(image_paths, lang=lang)

    raw = "\n\n".join(t.strip() for t in texts if t.strip())
    if not raw:
        return "⚠️ OCR לא חילץ טקסט."
    _safe_print(
        f"[OCR] Total: {len(raw)} chars from {len(texts)} pages (engine={engine.name()})"
    )
    return raw
