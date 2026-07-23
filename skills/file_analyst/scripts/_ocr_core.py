"""
OCR core — image OCR, preprocessing, Tesseract config, cache.
"""

import os
import shutil
import sys
import threading
from pathlib import Path

# Module-level lock guarding OCR cache read/update/write critical section
# against concurrent worker threads (Telegram async handlers, batch mode).
_CACHE_LOCK = threading.Lock()

from _hebrew_fix import _fix_custom_font_encoding
from _text_utils import _clean_ocr_hebrew


def _configure_tesseract() -> None:
    """Configure pytesseract binary path AND tessdata location (Windows
    service safety). Critical when running under NSSM as SYSTEM, where
    per-user env vars (TESSDATA_PREFIX) are absent and language packs
    installed under %LOCALAPPDATA% would not be found.

    Binary detection delegates to _find_tesseract_binary (the same 8-path
    list used by TesseractEngine.available), so a per-user install under
    %LOCALAPPDATA%\\Programs\\Tesseract-OCR is found here too — not just
    in the availability probe. Before this fix, available() passed but
    image OCR failed with TesseractNotFoundError on per-user installs.
    """
    import pytesseract

    from _ocr_constants import _find_tesseract_binary

    cmd = _find_tesseract_binary()
    if cmd:
        pytesseract.pytesseract.tesseract_cmd = cmd

    # Resolve tessdata directory. Local skill tessdata takes highest priority —
    # it ships with heb.traineddata (5.4 MB legacy v3) and is always present.
    # The TESSDATA_PREFIX env var (if set) typically points to AppData which
    # contains a minimal 961 KB stub that produces poor Hebrew OCR quality.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local_tessdata = os.path.abspath(os.path.join(script_dir, "..", "tessdata"))
    env_prefix = os.environ.get("TESSDATA_PREFIX")
    candidates = [
        local_tessdata,  # skill-local (5.4 MB) — highest priority
        r"C:\Program Files\Tesseract-OCR\tessdata",  # system install
        r"C:\ProgramData\tessdata",
    ]
    if env_prefix:
        candidates.append(env_prefix)  # env var last — avoids 961 KB AppData stub
    print(
        f"[OCR] TESSDATA_PREFIX candidates: {candidates}", flush=True, file=sys.stderr
    )
    for d in candidates:
        heb_path = os.path.join(d, "heb.traineddata")
        if d and os.path.isfile(heb_path):
            os.environ["TESSDATA_PREFIX"] = d
            print(f"[OCR] Using TESSDATA_PREFIX: {d}", flush=True, file=sys.stderr)
            return
    print(
        "[OCR] WARNING: No heb.traineddata found in any candidate directory",
        flush=True,
        file=sys.stderr,
    )


def _ocr_cache_path(
    file_path: str, lang: str, psm: int, oem: int, preprocess: bool,
    engine_name: str = "auto"
) -> Path | None:
    """Return cache file path keyed by (file sha256, ocr params) or None on error."""
    try:
        import hashlib

        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        base = os.getenv("SENTINEL_STATE_DIR")
        root = Path(base) if base else Path(__file__).resolve().parents[3] / "state"
        cache_dir = root / "skills" / "ocr_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        # Normalize engine_name: 'auto' and 'tesseract' both run Tesseract,
        # so collapse to 'tesseract' to avoid duplicate cache entries across
        # entry points (Telegram sends 'tesseract', CLI default is 'auto').
        norm_engine = "tesseract" if engine_name in ("auto", "tesseract") else engine_name
        # 'v2' suffix invalidates stale EasyOCR-era cache entries that were
        # written under the old dual-engine factory with engine_name='auto'.
        key = f"{digest}_{norm_engine}_v2_{lang}_psm{psm}_oem{oem}_pre{int(preprocess)}.txt"
        return cache_dir / key
    except Exception:
        return None


def _preprocess_image(img):
    """Improve OCR accuracy: grayscale + auto-contrast + median denoise (non-destructive)."""
    try:
        from PIL import ImageFilter, ImageOps

        g = img.convert("L")
        g = ImageOps.autocontrast(g, cutoff=2)
        g = g.filter(ImageFilter.MedianFilter(size=3))
        # No hard binarization: a fixed global threshold destroys text on
        # colored backgrounds (infographics) and stylized fonts. Grayscale +
        # autocontrast + median denoise is engine-agnostic and non-destructive.
        return g
    except Exception:
        return img


def _read_ocr_cache(cache: Path | None) -> str | None:
    """Read cached OCR result. Returns None on miss or corrupt entry."""
    if not cache or not cache.is_file():
        return None
    with _CACHE_LOCK:
        try:
            return cache.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"[OCR-cache] read failed ({e}); resetting entry.", file=sys.stderr, flush=True)
            try:
                cache.unlink()
            except OSError:
                pass
        except Exception as e:
            print(f"[OCR-cache] unexpected read error: {e}", file=sys.stderr, flush=True)
    return None


def _write_ocr_cache(cache: Path | None, text: str) -> None:
    """Atomic write of OCR result to cache (temp file + rename)."""
    if not cache:
        return
    with _CACHE_LOCK:
        try:
            tmp = cache.with_suffix(cache.suffix + ".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, cache)
        except OSError as e:
            print(f"[OCR-cache] write failed ({e}); skipping cache.", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[OCR-cache] unexpected write error: {e}", file=sys.stderr, flush=True)


def _get_ocr_engine(engine_name: str, lang: str):
    """Import and get OCR engine — returns (engine, error_str)."""
    try:
        from ocr_engines import get_engine
    except ImportError:
        return None, "❌ ocr_engines module not found."
    try:
        return get_engine(preferred=engine_name, lang=lang), None
    except RuntimeError as e:
        return None, f"❌ {e}"


def _run_ocr(engine, path: str, lang: str, psm: int, oem: int, preprocess: bool) -> str:
    """Execute OCR via engine — returns text or error string."""
    try:
        return engine.ocr_image(path, lang=lang, psm=psm, oem=oem, preprocess=preprocess)
    except ImportError as e:
        return f"❌ OCR libs missing: {e}. Run: pip install pytesseract Pillow"
    except Exception as e:
        return f"❌ OCR failed: {e}"


def _postprocess_ocr_text(text: str, lang: str) -> str:
    """Hebrew post-processing: garbled check + font fix + RTL clean."""
    _has_heb = any("\u0590" <= c <= "\u05ff" for c in text)
    _looks_garbled = ("heb" in lang) and not _has_heb and len(text) > 40
    if _looks_garbled:
        return (
            "⚠️ OCR לא חילץ טקסט עברי. ייתכן ש-language data חסר. "
            f"\n\nתוצאה גולמית:\n{text[:300]}"
        )
    if "heb" in lang:
        text = _fix_custom_font_encoding(text, lang=lang)
        return _clean_ocr_hebrew(text)
    return text


def ocr_image(
    path: str,
    lang: str = "eng+heb+ara",
    psm: int = 3,
    oem: int = 3,
    preprocess: bool = True,
    use_cache: bool = True,
    engine_name: str = "auto",
) -> str:
    """Run OCR on an image file via Tesseract 5.x (Sentinel's sole OCR backend).

    Args:
        psm: Page Segmentation Mode (3=auto, 6=block, 11=sparse).
        oem: OCR Engine Mode (3=default LSTM+legacy, 1=LSTM only).
        preprocess: grayscale+autocontrast+threshold (helps phone photos).
        use_cache: read/write cached result keyed by sha256(file)+params.
        engine_name: accepted for CLI compatibility ('auto' | 'tesseract').
    """
    if use_cache:
        cache = _ocr_cache_path(path, lang, psm, oem, preprocess, engine_name)
        cached = _read_ocr_cache(cache)
        if cached is not None:
            return cached

    engine, err = _get_ocr_engine(engine_name, lang)
    if err:
        return err

    text = _run_ocr(engine, path, lang, psm, oem, preprocess).strip()

    _has_heb = any("\u0590" <= c <= "\u05ff" for c in text)
    _looks_garbled = ("heb" in lang) and not _has_heb and len(text) > 40

    if use_cache and text and not text.startswith("❌") and not _looks_garbled:
        _write_ocr_cache(_ocr_cache_path(path, lang, psm, oem, preprocess, engine_name), text)

    return _postprocess_ocr_text(text, lang)
