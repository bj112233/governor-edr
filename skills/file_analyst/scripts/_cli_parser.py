"""
CLI argument parser — build the argparse.ArgumentParser for file_analyst.
"""

import argparse

from _text_utils import _DEFAULT_OCR_LANG

# Actions that operate on a single file.
FILE_ACTIONS = (
    "summarize",
    "extract",
    "convert",
    "stats",
    "contract",
    "analyze",
    "datasheet",
    "chart",
    "check",
    "scan",
    "ocr",
    "ocr_translate",
    "ocr_pdf",
    "redact",
    "extract_tables",
    "pdf_to_md",
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser for the file_analyst CLI."""
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=(*FILE_ACTIONS, "batch"))
    parser.add_argument("--path")
    parser.add_argument("--dir")
    parser.add_argument("--pattern", default="*")
    parser.add_argument("--pages", type=int, default=0)
    parser.add_argument("--query", default="")
    parser.add_argument("--format", default="markdown", choices=["markdown", "json"])
    parser.add_argument("--lines", type=int, default=10)
    parser.add_argument("--output")
    parser.add_argument("--to", default="he", help="Target language for ocr_translate")
    parser.add_argument(
        "--lang",
        default=_DEFAULT_OCR_LANG,
        help="Tesseract language(s) for OCR",
    )
    parser.add_argument(
        "--psm",
        type=int,
        default=3,
        help="Tesseract Page Segmentation Mode (3=auto, 6=block, 11=sparse)",
    )
    parser.add_argument(
        "--oem",
        type=int,
        default=3,
        help="Tesseract OCR Engine Mode (3=default LSTM+legacy, 1=LSTM only)",
    )
    parser.add_argument(
        "--no-preprocess",
        action="store_true",
        help="Disable image preprocessing (grayscale+threshold) before OCR",
    )
    parser.add_argument(
        "--no-ocr-cache",
        action="store_true",
        help="Bypass OCR result cache",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        help="Return JSON for ocr_translate (source_text + translated)",
    )
    parser.add_argument(
        "--ocr-engine",
        "--ocr_engine",
        dest="ocr_engine",
        default="auto",
        choices=["auto", "tesseract", "easyocr"],
        help="OCR backend (default: auto = Tesseract 5.x; 'easyocr' is "
             "accepted as a legacy alias and maps to tesseract)",
    )
    parser.add_argument(
        "--md-engine",
        "--md_engine",
        dest="md_engine",
        default="auto",
        choices=["auto", "markitdown"],
        help="PDF→Markdown engine (default: auto = MarkItDown)",
    )
    parser.add_argument(
        "--ocr",
        action="store_true",
        help="Enable OCR fallback for scanned PDFs (requires pytesseract+pdf2image)",
    )
    parser.add_argument(
        "--no-auto-ocr",
        action="store_true",
        help="Disable automatic OCR detection for scanned PDFs (F2)",
    )
    parser.add_argument(
        "--aggressive-clean",
        dest="aggressive_clean",
        action="store_true",
        help=(
            "Enable legacy heuristic Hebrew RTL fix + double-letter dedup "
            "(_fix_rtl_text / _dedup_word). Use only for visual-order PDFs; "
            "by default raw pdfplumber output is preserved."
        ),
    )
    # F3 chart args
    parser.add_argument("--x-col", "--x_col", default="", help="X-axis column (for action=chart)")
    parser.add_argument(
        "--y-cols",
        "--y_cols",
        default="",
        help="Y-axis columns, comma-separated (chart)",
    )
    parser.add_argument(
        "--kind",
        default="line",
        choices=["line", "bar", "scatter"],
        help="Chart kind (F3)",
    )
    parser.add_argument("--title", default="", help="Chart title")
    parser.add_argument(
        "--batch-action",
        "--batch_action",
        dest="batch_action",
        choices=FILE_ACTIONS,
        default="summarize",
        help="Per-file action when running 'batch' (default: summarize)",
    )
    parser.add_argument(
        "--cluster",
        action="store_true",
        help="Group batch results by semantic similarity (embeddings via local LLM)",
    )
    parser.add_argument(
        "--cluster-threshold",
        type=float,
        default=0.80,
        help="Cosine similarity threshold for document clustering (default: 0.80)",
    )
    return parser
