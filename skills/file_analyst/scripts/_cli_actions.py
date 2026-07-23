"""
CLI action dispatch — process a single file according to the effective action.

Extracted from the original monolithic ``main()`` to honor the SRP and the
≤300-line / ≤C-CC project thresholds.
"""

from pathlib import Path

from _analyzers import analyze_datasheet, analyze_with_profile, pdf_to_markdown, smart_summarize
from _data_utils import chart_csv, file_integrity_check, xlsx_integrity
from _file_readers import (
    _IMAGE_EXTS,
    read_csv,
    read_docx,
    read_json,
    read_pdf,
    read_txt,
    read_xlsx,
)
from _ocr_core import ocr_image
from _ocr_pdf import ocr_pdf_force
from _ocr_translate import _translate_extracted_text, ocr_translate_image
from _redaction import extract_pdf_tables, redact_pdf

# Text-extraction actions that should auto-route image files to OCR.
_TEXT_ACTIONS = {"summarize", "extract", "stats", "contract", "datasheet"}

# YARA rules directory (project root / rules / yara)
# __file__ = skills/file_analyst/scripts/_cli_actions.py → 4 parents up = project root
_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules" / "yara"


def _yara_scan(filepath: str) -> str:
    """Scan a file with YARA rules and return formatted results."""
    try:
        import yara
    except ImportError:
        return "❌ yara-python not installed. Run: pip install yara-python"

    if not _RULES_DIR.exists() or not list(_RULES_DIR.glob("*.yar")):
        return f"❌ No YARA rules found in {_RULES_DIR}"

    yar_files = {f.stem: str(f) for f in _RULES_DIR.glob("*.yar")}
    try:
        rules = yara.compile(filepaths=yar_files)
    except Exception as exc:
        return f"❌ YARA compile error: {exc}"

    matches = rules.match(filepath)
    if not matches:
        return f"✅ No YARA matches for {Path(filepath).name}"

    lines = [f"🚨 YARA Matches for {Path(filepath).name}:"]
    for m in matches:
        meta = dict(m.meta) if hasattr(m, "meta") else {}
        severity = meta.get("severity", "unknown")
        mitre = meta.get("mitre", "")
        desc = meta.get("description", "")
        lines.append(f"  [{severity.upper()}] {m.rule}: {desc}")
        if mitre:
            lines.append(f"    MITRE: {mitre}")
    return "\n".join(lines)


def _process_ocr_action(args, p: str, ext: str):
    """Handle the ``ocr`` action for PDF and image files."""
    if ext == ".pdf":
        return read_pdf(
            p,
            ocr=True,
            auto_ocr=True,
            lang=args.lang,
            engine_name=args.ocr_engine,
            aggressive_clean=args.aggressive_clean,
        )
    if ext in _IMAGE_EXTS:
        return ocr_image(
            p,
            lang=args.lang,
            psm=args.psm,
            oem=args.oem,
            preprocess=not args.no_preprocess,
            use_cache=not args.no_ocr_cache,
            engine_name=args.ocr_engine,
        )
    return f"❌ ocr action requires an image file or PDF, got {ext}"


def _process_ocr_translate_action(args, p: str, ext: str):
    """Handle the ``ocr_translate`` action for PDF and image files."""
    if ext == ".pdf":
        text = read_pdf(
            p,
            auto_ocr=True,
            lang=args.lang,
            engine_name=args.ocr_engine,
            aggressive_clean=args.aggressive_clean,
        )
        if text.startswith("❌"):
            return text
        if not text.strip():
            return "❌ לא נמצא טקסט ב-PDF."
        return _translate_extracted_text(
            text,
            target=args.to,
            output_format="json" if args.json_output else "markdown",
        )
    if ext not in _IMAGE_EXTS:
        return f"❌ ocr_translate requires an image or PDF file, got {ext}"
    return ocr_translate_image(
        p,
        target=args.to,
        lang=args.lang,
        psm=args.psm,
        oem=args.oem,
        preprocess=not args.no_preprocess,
        output_format="json" if args.json_output else "markdown",
        engine_name=args.ocr_engine,
    )


_PDF_ONLY_ACTIONS = {"ocr_pdf", "extract_tables", "pdf_to_md", "redact"}


def _process_pdf_only_action(effective_action: str, args, p: str, ext: str):
    """Handle actions that only apply to ``.pdf`` files.

    Returns None for non-PDF-only actions so they fall through to
    the text-extraction pipeline.
    """
    if effective_action not in _PDF_ONLY_ACTIONS:
        return None
    if ext != ".pdf":
        return f"❌ {effective_action} requires a .pdf file, got {ext or 'no extension'}"
    if effective_action == "ocr_pdf":
        return ocr_pdf_force(p, args.pages, engine_name=args.ocr_engine)
    if effective_action == "extract_tables":
        return extract_pdf_tables(p, args.pages)
    if effective_action == "pdf_to_md":
        return pdf_to_markdown(p, engine=args.md_engine)
    if effective_action == "redact":
        return redact_pdf(
            p,
            pattern=args.pattern,
            output_path=str(args.output) if args.output else "",
        )
    return None


def _extract_text(args, effective_action: str, p: str, ext: str):
    """Extract text from a file, auto-routing images to OCR when needed."""
    # Auto-route image files for text-extraction actions to OCR. Without
    # this, `summarize`/`extract`/`stats`/`contract`/`datasheet` on a
    # .jpg/.png would return "❌ Unsupported: .jpg" and the LLM would
    # treat it as a hard failure.
    if ext in _IMAGE_EXTS and effective_action in _TEXT_ACTIONS:
        text = ocr_image(
            p,
            lang=args.lang,
            psm=args.psm,
            oem=args.oem,
            preprocess=not args.no_preprocess,
            use_cache=not args.no_ocr_cache,
            engine_name=args.ocr_engine,
        )
        if text.startswith("❌") or text.startswith("⚠️"):
            return text
        return text
    if ext == ".pdf":
        import sys as _sys

        print(
            f"[DEBUG] Before read_pdf: ocr={args.ocr} auto_ocr={not args.no_auto_ocr} lang={args.lang}",
            flush=True,
            file=_sys.stderr,
        )
        text = read_pdf(
            p,
            args.pages,
            ocr=args.ocr,
            auto_ocr=not args.no_auto_ocr,
            lang=args.lang,
            engine_name=args.ocr_engine,
            aggressive_clean=args.aggressive_clean,
        )
        print(
            f"[DEBUG] After read_pdf: len={len(text)} heb_unicode={any(chr(0x0590) <= c <= chr(0x05FF) for c in text)}",
            flush=True,
            file=_sys.stderr,
        )
        return text
    if ext == ".docx":
        return read_docx(p, as_markdown=(effective_action == "convert"))
    if ext == ".csv":
        return read_csv(p, args.query)
    if ext in (".xlsx", ".xls"):
        return read_xlsx(p, args.query)
    if ext == ".json":
        return read_json(p)
    if ext in (".txt", ".md"):
        return read_txt(p)
    return f"❌ Unsupported: {ext}"


def _apply_text_action(effective_action: str, args, text: str, p: str):
    """Apply a text-consuming action to already-extracted ``text``."""
    if effective_action == "summarize":
        return smart_summarize(text, args.lines)
    if effective_action == "extract":
        return text[:3000]
    if effective_action == "stats":
        words = len(text.split())
        return f"Words: {words}\nChars: {len(text)}\nLines: {text.count(chr(10))}"
    if effective_action in ("contract", "analyze"):
        return analyze_with_profile(text, Path(p).name)
    if effective_action == "datasheet":
        return analyze_datasheet(text, Path(p).name)
    if effective_action == "convert":
        if args.format == "markdown":
            return f"# {Path(p).name}\n\n{text}"
        return text
    return text


def process_file(args, effective_action: str, p) -> str:
    """Process a single file and return its result string.

    Dispatches to the appropriate reader/analyzer based on the file
    extension and the effective action. ``args`` is the parsed argparse
    namespace; ``effective_action`` is the resolved action (batch_action
    when ``args.action == "batch"``).
    """
    p = str(p).strip("\"'")
    ext = Path(p).suffix.lower()

    # F3/F4: chart and check don't need text extraction
    if effective_action == "chart":
        return chart_csv(p, args.x_col, args.y_cols, args.kind, args.title, args.output or "")
    if effective_action == "check":
        if ext in (".xlsx", ".xls"):
            return xlsx_integrity(p)
        return file_integrity_check(p, ext)
    if effective_action == "scan":
        return _yara_scan(p)
    if effective_action == "ocr":
        return _process_ocr_action(args, p, ext)
    if effective_action == "ocr_translate":
        return _process_ocr_translate_action(args, p, ext)

    pdf_only = _process_pdf_only_action(effective_action, args, p, ext)
    if pdf_only is not None:
        return pdf_only

    text = _extract_text(args, effective_action, p, ext)
    if isinstance(text, str) and text.startswith("❌"):
        return text
    return _apply_text_action(effective_action, args, text, p)
