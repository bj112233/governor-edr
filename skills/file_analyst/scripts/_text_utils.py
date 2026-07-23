"""
Text utilities for file_analyst — RTL fixes, Hebrew OCR cleaning,
encoding detection, and translation helpers.
"""

import os
import sys
from typing import List

import requests

_LLM_API_BASE = os.getenv("LLM_API_BASE", "http://127.0.0.1:5001/v1")


def _embed_texts(
    texts: list[str],
    model: str = os.getenv(
        "EMBEDDING_MODEL", "text-embedding-multilingual-e5-large-instruct"
    ),
) -> list[list[float]] | None:
    """Compute embeddings via local LLM endpoint. Returns None on failure."""
    try:
        url = f"{_LLM_API_BASE}/embeddings"
        prefixed = ["passage: " + t for t in texts]
        r = requests.post(
            url,
            json={"model": model, "input": prefixed},
            timeout=15,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()
        data = r.json()
        return [d["embedding"] for d in data.get("data", [])]
    except Exception:
        return None


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity (-1..1)."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = sum(x * x for x in a) ** 0.5
    norm_b = sum(x * x for x in b) ** 0.5
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


_HEBREW_RANGE = ("\u0590", "\u05ff")


def _has_hebrew(s: str) -> bool:
    """Check if string contains any Hebrew character."""
    return any(_HEBREW_RANGE[0] <= c <= _HEBREW_RANGE[1] for c in s)


def _dedup_word(w: str, force: bool = False) -> str:
    """Remove consecutive duplicate chars caused by PDF extraction artifacts."""
    if len(w) < 4 or not _has_hebrew(w):
        return w
    if not force:
        dupes = sum(1 for i in range(len(w) - 1) if w[i] == w[i + 1])
        if dupes / len(w) < 0.25:
            return w
    result = [w[0]]
    for c in w[1:]:
        if c != result[-1]:
            result.append(c)
    return "".join(result)


def _collapse_letter_spacing(tokens: list[str]) -> list[tuple[str, bool]]:
    """Merge runs of single-char Hebrew tokens (PDF letter-spacing artifact).

    When a PDF header uses tracking/letter-spacing, extraction yields each
    Hebrew glyph as its own whitespace-separated token (e.g. 'ב י ק ו ר ת').
    Heuristic: if a line contains >=3 single-char Hebrew tokens, merge every
    run of adjacent Hebrew tokens into one. Returns list of (token, merged)
    tuples so callers can force dedup on merged tokens.
    """
    single_heb = sum(1 for t in tokens if len(t) == 1 and _has_hebrew(t))
    if single_heb < 3:
        return [(t, False) for t in tokens]
    merged: list[tuple[str, bool]] = []
    buf = ""
    for t in tokens:
        if _has_hebrew(t):
            buf += t
        else:
            if buf:
                merged.append((buf, True))
                buf = ""
            merged.append((t, False))
    if buf:
        merged.append((buf, True))
    return merged


def _fix_hebrew_word(w: str, was_merged: bool) -> str:
    """Reverse Hebrew word characters, preserving trailing punctuation."""
    w = _dedup_word(w, force=was_merged)
    stripped = w.rstrip(".,;:!?")
    trailing = w[len(stripped) :]
    return stripped[::-1] + trailing


def _fix_rtl_text(text: str) -> str:
    """Fix mirrored Hebrew text from PDF extraction.

    PDF stores text in visual left-to-right order. When extracted, Hebrew text
    appears with reversed characters within each word and reversed word order
    within each line. This function restores correct Hebrew by reversing both.
    """
    lines = []
    for line in text.splitlines():
        words = line.split()
        if not words or not any(_has_hebrew(w) for w in words):
            lines.append(line)
            continue

        tagged = _collapse_letter_spacing(words)
        fixed_words = [
            _fix_hebrew_word(w, merged) if _has_hebrew(w) else w
            for w, merged in tagged
        ]
        lines.append(" ".join(reversed(fixed_words)))

    return "\n".join(lines)


def _clean_ocr_hebrew(text: str) -> str:
    """Deterministic, structural normalization of Hebrew OCR output.

    Scope is intentionally minimal — only safe, reversible transformations:
      * Strip Unicode bidi / joiner controls that corrupt display
        (LRM, RLM, ZWNJ, ZWJ, LRE, RLE, PDF, LRO, RLO).
      * Drop non-printable C0/C1 control codes (except TAB/LF).
      * Collapse runs of spaces and excessive blank lines.

    Any lexical correction (token-level spell-fix, domain glossaries) MUST be
    performed by a separate post-processing layer downstream — this function
    is OCR-agnostic and must never alter character content.
    """
    import re

    if not text:
        return text

    # 1. Strip directional formatting & joiners that corrupt RTL display.
    _BIDI_CONTROLS = (
        "\u200e"  # LRM
        "\u200f"  # RLM
        "\u200c"  # ZWNJ
        "\u200d"  # ZWJ
        "\u202a"  # LRE
        "\u202b"  # RLE
        "\u202c"  # PDF
        "\u202d"  # LRO
        "\u202e"  # RLO
    )
    text = text.translate({ord(c): None for c in _BIDI_CONTROLS})

    # 2. Drop C0/C1 control codes except TAB (\t) and LF (\n).
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", text)

    # 3. Collapse whitespace conservatively.
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


_DEFAULT_OCR_LANG = "eng+heb+ara"


def _robust_translate(text: str, target: str) -> str:
    """Chunk-aware translator with offline opus-mt backend.

    Tries the offline opus-mt backend first (en↔he only, MIT, best Hebrew
    BLEU). On unsupported pair or failure, returns the original text so the
    user does not lose data. The deep-translator fallback was removed because
    the PyPI package was compromised (PYSEC-2022-252) and has no safe version.

    Splits text by paragraphs (\n\n) into chunks < 4500 chars.
    """
    if not text:
        return text

    # ── Primary: offline opus-mt (en↔he only) ─────────────────────────────
    # Lazy import — keeps file_analyst importable when translator-skill is
    # absent or when transformers/torch are not installed.
    try:
        import importlib
        import os

        _ts_scripts = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "translator-skill", "scripts",
        )
        if _ts_scripts not in sys.path:
            sys.path.insert(0, os.path.abspath(_ts_scripts))
        opus_mod = importlib.import_module("opus_mt_backend")
        backend = opus_mod.OpusMTBackend()
        try:
            result = backend.translate(text, source="auto", target=target)
            if result and result.strip():
                return result
        except NotImplementedError:
            pass  # pair not en↔he → return original text
        except Exception as e:
            sys.stderr.write(f"[translate] opus-mt failed: {e}; returning original\n")
    except ImportError:
        pass  # translator-skill not available → return original text

    return text
