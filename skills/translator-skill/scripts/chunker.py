"""Translator Skill — Semantic, character-aware chunker.

The translation backends (MyMemory / LibreTranslate)
are classic web APIs whose hard limit is **characters**, not LLM tokens. This
chunker splits on semantic boundaries (paragraphs → sentences) and only falls
back to a hard character cut for pathological input (e.g. a giant Base64 blob
with no whitespace). This prevents both API rejections (413 / 5000-char limits)
and mid-sentence semantic breaks that produce robotic, gender-mismatched output.
"""

from __future__ import annotations

import re

# Sentence boundary: period / question / exclamation / Hebrew sof-pasuq, then whitespace.
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?\u05c3])\s+")


class SemanticChunker:
    """Splits text into <= max_chars chunks, respecting semantic boundaries."""

    def __init__(self, max_chars: int = 4500):
        if max_chars < 1:
            raise ValueError("max_chars must be >= 1")
        self.max_chars = max_chars

    def chunk(self, text: str) -> list[str]:
        if not text:
            return []

        # Level 1 — macro semantics: paragraphs (line boundaries).
        paragraphs = text.split("\n")
        chunks: list[str] = []
        current: list[str] = []
        current_len = 0

        for p in paragraphs:
            p_len = len(p) + 1  # +1 for the newline rejoin

            # Edge case: a single paragraph exceeds the limit on its own.
            if p_len > self.max_chars:
                if current:
                    chunks.append("\n".join(current))
                    current = []
                    current_len = 0
                chunks.extend(self._fallback_sentences(p))
                continue

            # Flush the current chunk if adding this paragraph would overflow.
            if current_len + p_len > self.max_chars and current:
                chunks.append("\n".join(current))
                current = [p]
                current_len = p_len
            else:
                current.append(p)
                current_len += p_len

        if current:
            chunks.append("\n".join(current))

        return chunks

    def _fallback_sentences(self, text: str) -> list[str]:
        """Level 2 — split an oversized paragraph on sentence boundaries."""
        sentences = _SENTENCE_SPLIT.split(text)
        chunks: list[str] = []
        current: list[str] = []
        current_len = 0

        for s in sentences:
            s_len = len(s) + 1  # +1 for the space rejoin

            # A single sentence exceeds the limit (no punctuation / huge blob).
            if s_len > self.max_chars:
                if current:
                    chunks.append(" ".join(current))
                    current = []
                    current_len = 0
                chunks.extend(self._fallback_hard(s))
                continue

            if current_len + s_len > self.max_chars and current:
                chunks.append(" ".join(current))
                current = [s]
                current_len = s_len
            else:
                current.append(s)
                current_len += s_len

        if current:
            chunks.append(" ".join(current))

        return chunks

    def _fallback_hard(self, text: str) -> list[str]:
        """Level 3 (terminal) — brutal fixed-width cut. Last resort only."""
        return [
            text[i : i + self.max_chars]
            for i in range(0, len(text), self.max_chars)
        ]
