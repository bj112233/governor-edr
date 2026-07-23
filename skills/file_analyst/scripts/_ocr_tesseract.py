"""
_ocr_tesseract.py — Tesseract backend via pytesseract (CPU).

Extracted from ocr_engines.py. Sentinel's sole OCR backend. Requires the
external tesseract binary (located via _find_tesseract_binary, which covers
per-user installs under %LOCALAPPDATA% that the old _configure_tesseract
path list missed).
"""

from __future__ import annotations

from _ocr_constants import _DEFAULT_OCR_LANG, _find_tesseract_binary


class TesseractEngine:
    """Tesseract via pytesseract — Sentinel's sole OCR backend."""

    def __init__(self) -> None:
        self._tess_cmd: str | None = None
        self._tessdata_configured: bool = False

    def name(self) -> str:
        return "tesseract"

    def available(self) -> bool:
        try:
            import pytesseract  # noqa: F401

            return self._find_cmd() is not None
        except Exception:
            return False

    def _find_cmd(self) -> str | None:
        if self._tess_cmd is not None:
            return self._tess_cmd
        self._tess_cmd = _find_tesseract_binary()
        return self._tess_cmd

    def _configure(self) -> None:
        """Set pytesseract binary path + TESSDATA_PREFIX (once per instance)."""
        import pytesseract

        cmd = self._find_cmd()
        if cmd:
            pytesseract.pytesseract.tesseract_cmd = cmd
        # Resolve TESSDATA_PREFIX once — critical for finding heb.traineddata
        # on NSSM/SERVICE deployments where per-user env vars are absent.
        if not self._tessdata_configured:
            from _ocr_core import _configure_tesseract

            _configure_tesseract()
            self._tessdata_configured = True

    def ocr_image(
        self,
        path: str,
        lang: str = _DEFAULT_OCR_LANG,
        psm: int = 3,
        oem: int = 3,
        preprocess: bool = True,
    ) -> str:
        """Run Tesseract on a single image file path.

        Accepts the same psm/oem/preprocess params as ocr_image() in
        _ocr_core, so the image and PDF paths share one implementation.
        Preprocessing (grayscale + autocontrast + median denoise) is
        applied via PIL when preprocess=True.
        """
        import pytesseract
        from PIL import Image

        self._configure()
        with Image.open(path) as img:
            work = _preprocess_image(img) if preprocess else img
            cfg = f"--psm {int(psm)} --oem {int(oem)}"
            return pytesseract.image_to_string(work, lang=lang, config=cfg)

    def ocr_images(
        self,
        paths: list[str],
        lang: str = _DEFAULT_OCR_LANG,
        psm: int = 3,
        oem: int = 3,
        preprocess: bool = True,
    ) -> list[str]:
        return [self.ocr_image(p, lang, psm, oem, preprocess) for p in paths]


def _preprocess_image(img):
    """Grayscale + autocontrast + median denoise (non-destructive).

    Mirrors _ocr_core._preprocess_image so the engine is self-contained
    for the PDF path (which calls engine.ocr_images directly).
    """
    try:
        from PIL import ImageFilter, ImageOps

        g = img.convert("L")
        g = ImageOps.autocontrast(g, cutoff=2)
        g = g.filter(ImageFilter.MedianFilter(size=3))
        return g
    except Exception:
        return img
