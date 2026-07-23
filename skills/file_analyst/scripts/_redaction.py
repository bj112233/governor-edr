"""
PDF redaction and table extraction.
"""

import os
import re
from pathlib import Path


def redact_pdf(input_path: str, pattern: str, output_path: str) -> str:
    """Physically redact a PDF in-place using PyMuPDF (`fitz`).

    Steps (per design contract):
      1. Compile `pattern` as a Python regex.
      2. Open `input_path` with fitz.
      3. For each page: extract text, find regex matches, locate bounding
         boxes via `page.search_for(matched_string)`.
      4. Add a black-fill redaction annotation for each rect.
      5. Call `page.apply_redactions()` — this permanently destroys the
         underlying text glyphs (not just visually covers them).
      6. Save to `output_path` (enforced `.pdf` suffix). Returns a status
         line; never returns the source text.
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        return "❌ PyMuPDF not installed. Run: pip install pymupdf"

    if not pattern or pattern == "*":
        return (
            "❌ redact requires a regex pattern. "
            'Example: --pattern "\\d{3}-\\d{2}-\\d{4}"'
        )

    try:
        regex = re.compile(pattern)
    except re.error as e:
        return f"❌ Invalid regex pattern: {e}"

    in_path = Path(input_path)
    if not in_path.is_file():
        return f"❌ File not found: {input_path}"
    if in_path.suffix.lower() != ".pdf":
        return f"❌ redact requires a .pdf input, got {in_path.suffix}"

    out_path = (
        Path(output_path)
        if output_path
        else in_path.with_name(f"{in_path.stem}.redacted.pdf")
    )
    if out_path.suffix.lower() != ".pdf":
        out_path = out_path.with_suffix(".pdf")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        doc = fitz.open(str(in_path))
    except Exception as e:
        return f"❌ Failed to open PDF: {e}"

    total_matches = 0
    pages_with_matches = 0
    try:
        for page in doc.pages():
            page_text = page.get_text()
            if not page_text:
                continue
            # Deduplicate matched strings per page to avoid redundant search_for calls.
            matched_strings: set[str] = {m.group(0) for m in regex.finditer(page_text)}
            if not matched_strings:
                continue
            page_match_count = 0
            for needle in matched_strings:
                if not needle.strip():
                    continue
                for rect in page.search_for(needle):
                    page.add_redact_annot(rect, fill=(0, 0, 0))
                    page_match_count += 1
            if page_match_count:
                page.apply_redactions()
                total_matches += page_match_count
                pages_with_matches += 1

        if total_matches == 0:
            doc.close()
            return f"⚠️ No matches for pattern `{pattern}` in {in_path.name}."

        doc.save(str(out_path), garbage=4, deflate=True, clean=True)
    finally:
        doc.close()

    return (
        f"✅ Redacted {total_matches} occurrence(s) across {pages_with_matches} page(s)\n"
        f"   Pattern: {pattern}\n"
        f"   Output:  {out_path}\n"
        f"[FILE_EXPORT: {out_path}]"
    )


def extract_pdf_tables(path: str, pages: int = 0) -> str:
    """Extract every detected table in a PDF as Markdown."""
    try:
        import pdfplumber
    except ImportError:
        return "❌ pdfplumber not installed."
    try:
        size = os.path.getsize(path)
    except OSError as e:
        return f"❌ {e}"

    _MAX_PDF_BYTES = int(os.getenv("SENTINEL_PDF_MAX_BYTES", str(50 * 1024 * 1024)))
    _MAX_PDF_PAGES = int(os.getenv("SENTINEL_PDF_MAX_PAGES", "1000"))

    if size > _MAX_PDF_BYTES:
        return f"❌ PDF גדול מדי לעיבוד טבלאות ({size:,} bytes)"
    try:
        out: list[str] = []
        with pdfplumber.open(path) as pdf:
            total = len(pdf.pages)
            limit = min(pages or total, total, _MAX_PDF_PAGES)
            for idx in range(limit):
                page = pdf.pages[idx]
                tables = page.extract_tables() or []
                for t_idx, table in enumerate(tables):
                    if not table or not any(any(cell for cell in row) for row in table):
                        continue
                    cleaned = [
                        [(cell or "").strip().replace("\n", " ") for cell in row]
                        for row in table
                    ]
                    width = max(len(r) for r in cleaned)
                    cleaned = [r + [""] * (width - len(r)) for r in cleaned]
                    out.append(f"## עמוד {idx + 1} — טבלה {t_idx + 1}\n")
                    out.append("| " + " | ".join(cleaned[0]) + " |")
                    out.append("| " + " | ".join(["---"] * width) + " |")
                    for row in cleaned[1:]:
                        out.append("| " + " | ".join(row) + " |")
                    out.append("")
        if not out:
            return "📭 לא נמצאו טבלאות במסמך."
        return "\n".join(out)
    except Exception as e:
        return f"❌ extract_tables error: {e}"
