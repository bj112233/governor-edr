"""Translation utilities — text processing for chunking, OCR normalization, noise stripping."""

import re

# Patterns for document noise that destroys summarization quality on OCR-extracted datasheets
_TI_DOC_HEADER_RE = re.compile(r"^[A-Z]{3,}[A-Z0-9]*[–\-—].*\d{4}", re.IGNORECASE)
_URL_LINE_RE = re.compile(r"^\s*(https?://|www\.)", re.IGNORECASE)
_PAGE_NUM_LINE_RE = re.compile(r"^\s*\d{1,3}\s*$")
_DOT_LEADER_MIN_DOTS = 4
_DOT_LEADER_MIN_RATIO = 0.15
_TOC_NUMERIC_PREFIX_RE = re.compile(r"^\s*\d{1,2}(\.\d{1,2})?\s+\S")


def split_for_translation(text: str, chunk_chars: int) -> list[str]:
    """Paragraph-aware splitter; falls back to fixed-size slicing if a single
    paragraph exceeds the chunk budget. Preserves order and word boundaries."""
    text = text.strip()
    if len(text) <= chunk_chars:
        return [text] if text else []
    paragraphs = text.split("\n\n")
    chunks: list[str] = []
    buf = ""
    for p in paragraphs:
        if len(p) > chunk_chars:
            if buf:
                chunks.append(buf)
                buf = ""
            for i in range(0, len(p), chunk_chars):
                chunks.append(p[i : i + chunk_chars])
            continue
        candidate = f"{buf}\n\n{p}" if buf else p
        if len(candidate) > chunk_chars:
            chunks.append(buf)
            buf = p
        else:
            buf = candidate
    if buf:
        chunks.append(buf)
    return chunks


def is_dot_leader_line(stripped: str) -> bool:
    """True if the line's non-whitespace content is dot-dominated."""
    if len(stripped) < 8:
        return False
    no_space = re.sub(r"\s", "", stripped)
    if not no_space:
        return False
    dots = no_space.count(".")
    if dots < _DOT_LEADER_MIN_DOTS:
        return False
    return (dots / len(no_space)) >= _DOT_LEADER_MIN_RATIO


def _is_ocr_fragmented(text: str) -> tuple[bool, list[str]]:
    """Check if text is OCR-fragmented (one token per line).

    Returns (is_fragmented, raw_lines).
    """
    if not text or "\n" not in text:
        return False, []
    raw_lines = text.split("\n")
    non_empty = [ln for ln in raw_lines if ln.strip()]
    if len(non_empty) < 8:
        return False, raw_lines
    avg_len = sum(len(ln) for ln in non_empty) / len(non_empty)
    return avg_len < 30, raw_lines


def _rebuild_ocr_prose(raw_lines: list[str]) -> str:
    """Rebuild prose from OCR-fragmented lines."""
    out: list[str] = []
    blank_run = 0
    paragraph_pending = False
    for line in raw_lines:
        if not line.strip():
            blank_run += 1
            if blank_run >= 3:
                paragraph_pending = True
            continue
        blank_run = 0
        if paragraph_pending and out:
            out.append("\n\n")
            paragraph_pending = False
        elif out and not out[-1].endswith(("\n", " ")):
            out.append(" ")
        out.append(line.strip())
    return "".join(out)


def normalize_ocr_text(text: str) -> str:
    """Collapse OCR-style per-word newlines back into prose.

    Some PDF extractors emit one token per line. When the average non-empty line
    is very short, we treat any \\n run < 3 as a word separator and only \\n{3,}
    as a real paragraph break.
    """
    is_fragmented, raw_lines = _is_ocr_fragmented(text)
    if not is_fragmented:
        return text
    return _rebuild_ocr_prose(raw_lines)


def _prune_toc(text: str) -> str:
    """Heuristic TOC pruning around a 'Table of Contents' anchor."""
    toc_anchors = ("תוכן העניינים", "תוכן עניינים", "Table of Contents")
    for anchor in toc_anchors:
        idx = text.find(anchor)
        if idx == -1:
            continue
        after = text[idx + len(anchor) :]
        paragraphs = re.split(r"\n{2,}", after)
        for offset, para in enumerate(paragraphs):
            stripped = para.strip()
            if len(stripped) >= 120 and not is_dot_leader_line(stripped) and not _TOC_NUMERIC_PREFIX_RE.match(stripped):
                return text[:idx].rstrip() + "\n\n" + "\n\n".join(paragraphs[offset:])
        return text[:idx].rstrip()
    return text


def _filter_noise_lines(text: str) -> str:
    """Drop dot-leader lines, TI doc headers, URLs, and page numbers."""
    out_lines: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            out_lines.append("")
            continue
        if is_dot_leader_line(s) or _TI_DOC_HEADER_RE.match(s) or _URL_LINE_RE.match(s) or _PAGE_NUM_LINE_RE.match(s):
            continue
        out_lines.append(line)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(out_lines)).strip()


def strip_document_noise(text: str) -> str:
    """Drop TOC entries and document-level metadata that produce zero
    semantic value during summarization.

    Pipeline:
      1. OCR-normalize (only when fragmentation is detected).
      2. Drop dot-leader lines via density check.
      3. Drop common metadata (TI doc headers, URLs, page numbers).
      4. Heuristic TOC pruning around a "Table of Contents" anchor.
    """
    if not text:
        return text
    text = normalize_ocr_text(text)
    text = _prune_toc(text)
    return _filter_noise_lines(text)
