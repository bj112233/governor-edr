"""
OCR translate — image OCR with automatic translation.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from _ocr_core import ocr_image
from _text_utils import _DEFAULT_OCR_LANG, _robust_translate

_INLINE_CHUNK_CHARS = 4000


def ocr_translate_image(
    path: str,
    target: str = "he",
    lang: str = _DEFAULT_OCR_LANG,
    psm: int = 3,
    oem: int = 3,
    preprocess: bool = True,
    output_format: str = "markdown",
    engine_name: str = "auto",
) -> str:
    """OCR an image then translate; structured JSON or Markdown output."""
    if output_format not in ("markdown", "json"):
        output_format = "markdown"

    text = ocr_image(
        path, lang=lang, psm=psm, oem=oem, preprocess=preprocess,
        engine_name=engine_name,
    )
    if text.startswith("❌"):
        return text
    if not text:
        return "❌ OCR לא זיהה טקסט בתמונה."

    translated = _robust_translate(text, target)

    if output_format == "json":
        payload = {
            "source_text": text,
            "translated": translated,
            "target_lang": target,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    # UX: long output → file export so it actually reaches the user via Telegram
    if translated and len(translated) > 3000:
        BOT_ROOT = Path(__file__).resolve().parents[3]
        out_dir = BOT_ROOT / "downloads" / "translations"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"ocr_translate_{ts}.md"
        out_path.write_text(
            f"# OCR + Translation ({target})\n\n"
            f"## 📝 Source\n\n{text}\n\n## 🌐 Translation\n\n{translated}\n",
            encoding="utf-8",
        )
        print(f"[FILE_EXPORT: {out_path}]")
        return f"📝 תרגום ארוך יוצא כקובץ: {out_path.name}"

    # Telegram reply: translation only. The raw English OCR source is noise
    # for the user (wastes tokens); keep it in the JSON output for callers.
    return f"🌐 תרגום ({target}):\n{translated}"


def _inline_chunked_translate(text: str, target: str) -> tuple[str | None, str | None]:
    """Standalone fallback translator.

    Originally used deep-translator (Google Translate web scraper). Removed
    because the PyPI package was compromised (PYSEC-2022-252) and has no safe
    version. Keeps the function signature for backward compatibility, but now
    returns None and reports the removal.
    """
    return None, "online translator unavailable (deep-translator removed due to PyPI compromise)"


def _translate_extracted_text(
    text: str, target: str = "he", output_format: str = "markdown"
) -> str:
    """Translate already-extracted text (PDF or other source).

    Strategy:
      1. Primary path → `_robust_translate` (paragraph-aware chunking +
         exponential backoff).
      2. If `_robust_translate` raises an unexpected exception, fall back
         to `_inline_chunked_translate` which performs the same chunking inline.
    """
    translated: str | None = None
    error: str | None = None

    try:
        translated = _robust_translate(text, target)
    except Exception as e:
        error = f"_robust_translate failed: {e}"
        print(f"[translate] {error}", file=sys.stderr, flush=True)
        translated = None

    # Fallback path if primary returned nothing / raised.
    if not translated:
        translated, fb_err = _inline_chunked_translate(text, target)
        if fb_err:
            error = f"{error}; fallback: {fb_err}" if error else fb_err

    if output_format == "json":
        payload = {
            "source_text": text,
            "translated": translated,
            "target_lang": target,
            "translate_error": error,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    if translated is None:
        return f"📝 טקסט מקור:\n{text}\n\n❌ תרגום נכשל: {error}"
    return f"🌐 תרגום ({target}):\n{translated}"
