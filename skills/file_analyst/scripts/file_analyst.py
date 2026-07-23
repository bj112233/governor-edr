"""
File Analyst — read and summarize PDF, DOCX, CSV, XLSX, JSON, TXT.

Public API facade. Implementation lives in the ``_cli_*`` and ``_*``
sub-modules; this module re-exports the public surface and the CLI
entry point (``main``).
"""

import sys
from pathlib import Path

# Ensure imports work both as package and direct execution
_scripts_dir = Path(__file__).parent
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

# Sub-module imports — pure relative (Sprint 2 refactor)
from _hebrew_fix import _fix_custom_font_encoding, _looks_like_encoded_hebrew
from _ocr_core import _configure_tesseract, ocr_image
from _ocr_pdf import (
    _MAX_PDF_BYTES,
    _MAX_PDF_PAGES,
    _looks_like_scanned_pdf,
    _ocr_pdf,
    ocr_pdf_force,
)
from _ocr_translate import (
    _inline_chunked_translate,
    _translate_extracted_text,
    ocr_translate_image,
)
from _text_utils import (
    _clean_ocr_hebrew,
    _cosine_similarity,
    _DEFAULT_OCR_LANG,
    _embed_texts,
    _fix_rtl_text,
    _robust_translate,
)
from _data_utils import (
    chart_csv,
    file_integrity_check,
    xlsx_integrity,
)
from _redaction import extract_pdf_tables, redact_pdf
from _file_readers import (
    read_csv, read_docx, read_json, read_pdf, read_txt, read_xlsx,
    _IMAGE_EXTS,
)
from _analyzers import (
    analyze_contract,
    analyze_datasheet,
    analyze_with_profile,
    pdf_to_markdown,
    smart_summarize,
)

from ocr_engines import _find_poppler_path  # noqa: F401
from ocr_engines import _find_tesseract_binary as _find_tesseract  # noqa: F401

__all__ = [
    "read_pdf",
    "read_docx",
    "read_csv",
    "read_xlsx",
    "read_json",
    "read_txt",
    "analyze_contract",
    "analyze_datasheet",
    "analyze_with_profile",
    "smart_summarize",
    "ocr_image",
    "ocr_pdf_force",
    "ocr_translate_image",
    "chart_csv",
    "xlsx_integrity",
    "file_integrity_check",
    "redact_pdf",
    "extract_pdf_tables",
]

# Import profile loader for dynamic profile loading
try:
    from profile_loader import (
        detect_profile,
        get_profile_category,
        load_category,
        load_profile,
    )
except ImportError:
    # Fallback if profile_loader not available
    def load_profile(_name: str) -> None:
        return None

    def load_category(_category: str) -> dict:
        return {}

    def detect_profile(_text: str, _filename: str = "") -> None:
        return None

    def get_profile_category(_name: str) -> str | None:
        return None

# CLI entry point — implemented in _cli_main (Sprint 2 SRP split)
from _cli_main import main  # noqa: E402, F401

if __name__ == "__main__":
    main()
