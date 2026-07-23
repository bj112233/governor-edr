"""Offline unit tests for the translator SemanticChunker (no network)."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "translator-skill" / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from chunker import SemanticChunker  # noqa: E402


def test_empty_returns_empty_list():
    assert SemanticChunker(100).chunk("") == []


def test_short_text_single_chunk_unchanged():
    text = "Hello world."
    assert SemanticChunker(100).chunk(text) == [text]


def test_invariant_no_chunk_exceeds_max_chars():
    text = "\n".join(f"Paragraph number {i} with some words." for i in range(50))
    chunker = SemanticChunker(40)
    for c in chunker.chunk(text):
        assert len(c) <= 40


def test_oversized_paragraph_falls_back_to_sentences():
    para = "First sentence here. Second sentence here. Third one is also present."
    chunker = SemanticChunker(25)
    chunks = chunker.chunk(para)
    assert len(chunks) > 1
    for c in chunks:
        assert len(c) <= 25


def test_pathological_blob_hard_fallback():
    blob = "A" * 1000  # no whitespace, no punctuation
    chunker = SemanticChunker(100)
    chunks = chunker.chunk(blob)
    assert len(chunks) == 10
    assert all(len(c) <= 100 for c in chunks)
    assert "".join(chunks) == blob


def test_semantic_boundaries_preserved_for_paragraphs():
    text = "Line one.\nLine two.\nLine three."
    chunks = SemanticChunker(100).chunk(text)
    # Fits in one chunk; paragraph newlines preserved verbatim.
    assert chunks == [text]
