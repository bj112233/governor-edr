"""Translator Skill — shared config, constants, and language utilities.

Extracted from translator.py (SRP). Holds the cross-cutting state used by both
the backend implementations and the orchestrator:

- Tuning constants (chunk size, retries, parallel workers)
- LibreTranslate public instance list
- Google Translate legacy ISO 639-1 language aliases
- langdetect bootstrap (optional dependency)
- The shared SemanticChunker instance used in the hot path
- ``_normalize_lang`` and the legacy ``chunk_text`` helper
"""

from __future__ import annotations

from chunker import SemanticChunker

CHUNK_SIZE = 4500  # ~5000 char limit on most free backends
MAX_CHUNK_RETRIES = 3
MAX_WORKERS = 3

# Semantic, character-aware chunker (replaces raw chunk_text in the hot path).
_chunker = SemanticChunker(CHUNK_SIZE)

# LibreTranslate public instances (no API key required for low volume)
# NOTE: translate.argosopentech.com is dead (DNS failure) — removed 2026-05-17
LIBRE_INSTANCES = [
    "https://libretranslate.de",
    "https://libretranslate.com",
]

# Google Translate legacy ISO 639-1 codes (kept for compatibility with any
# future Google-Translate-based backend, but no longer required by deep-translator).
LANG_ALIASES = {
    "he": "iw",
    "yi": "ji",
    "jv": "jw",
}

# ── langdetect (optional dependency) ──
try:
    from langdetect import DetectorFactory, detect, detect_langs

    DetectorFactory.seed = 0
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False
    detect = None  # type: ignore[assignment]
    detect_langs = None  # type: ignore[assignment]
    DetectorFactory = None  # type: ignore[assignment]


def _normalize_lang(code: str) -> str:
    if not code:
        return code
    return LANG_ALIASES.get(code.lower(), code.lower())


def chunk_text(text: str, size: int = CHUNK_SIZE) -> list[str]:
    """Split text into chunks at line boundaries when possible."""
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    cur = ""
    for line in text.splitlines(keepends=True):
        if len(cur) + len(line) > size and cur:
            chunks.append(cur)
            cur = line
        else:
            cur += line
    if cur:
        chunks.append(cur)
    return chunks
