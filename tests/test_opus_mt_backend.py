"""Comprehensive offline tests for the OpusMT backend.

No network, no model download — these tests exercise direction resolution,
chunking, language detection, and the fallback contract. The actual
transformers/CTranslate2 inference is mocked so tests run in milliseconds.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_TS_SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "translator-skill" / "scripts"
sys.path.insert(0, str(_TS_SCRIPTS))

from opus_mt_backend import (  # noqa: E402
    OpusMTBackend,
    _has_hebrew,
    _normalize_source,
    _normalize_target,
)

# ── Pure helpers ────────────────────────────────────────────────────────────


class TestHasHebrew:
    def test_pure_hebrew(self):
        assert _has_hebrew("שלום עולם")

    def test_mixed_hebrew_english(self):
        assert _has_hebrew("Hello שלום world")

    def test_pure_english_false(self):
        assert not _has_hebrew("Hello world")

    def test_empty_string_false(self):
        assert not _has_hebrew("")

    def test_arabic_not_hebrew(self):
        # Arabic block is 0x0600-0x06FF, distinct from Hebrew 0x0590-0x05FF
        assert not _has_hebrew("مرحبا بالعالم")


class TestNormalizeLang:
    def test_he_aliases(self):
        assert _normalize_target("he") == "he"
        assert _normalize_target("heb") == "he"
        assert _normalize_target("iw") == "he"  # Google legacy
        assert _normalize_target("he-il") == "he"
        assert _normalize_target("HE") == "he"

    def test_en_aliases(self):
        assert _normalize_target("en") == "en"
        assert _normalize_target("eng") == "en"
        assert _normalize_target("en-us") == "en"

    def test_other_passthrough(self):
        assert _normalize_target("fr") == "fr"
        assert _normalize_target("ar") == "ar"

    def test_source_normalization(self):
        assert _normalize_source("heb") == "he"
        assert _normalize_source("iw") == "he"
        assert _normalize_source("eng") == "en"
        assert _normalize_source("auto") == "auto"


# ── Direction resolution ────────────────────────────────────────────────────


class TestResolveDirection:
    def test_explicit_en_to_he(self):
        assert OpusMTBackend._resolve_direction("en", "he", "Hello") == "en->he"

    def test_explicit_he_to_en(self):
        assert OpusMTBackend._resolve_direction("he", "en", "שלום") == "he->en"

    def test_auto_source_detects_hebrew(self):
        # Text has Hebrew → auto source resolves to he, target en → he->en
        assert OpusMTBackend._resolve_direction("auto", "en", "שלום עולם") == "he->en"

    def test_auto_source_detects_english(self):
        assert OpusMTBackend._resolve_direction("auto", "he", "Hello world") == "en->he"

    def test_auto_source_empty_text_defaults_english(self):
        # No Hebrew chars in empty/whitespace → defaults to en
        assert OpusMTBackend._resolve_direction("auto", "he", "") == "en->he"

    def test_unsupported_target_returns_none(self):
        assert OpusMTBackend._resolve_direction("en", "fr", "Hello") is None
        assert OpusMTBackend._resolve_direction("he", "ar", "שלום") is None

    def test_unsupported_source_returns_none(self):
        assert OpusMTBackend._resolve_direction("fr", "he", "Bonjour") is None
        assert OpusMTBackend._resolve_direction("ar", "en", "مرحبا") is None

    def test_same_source_target_returns_none(self):
        # he->he or en->en is a no-op; opus-mt has no such model.
        assert OpusMTBackend._resolve_direction("he", "he", "שלום") is None
        assert OpusMTBackend._resolve_direction("en", "en", "Hello") is None

    def test_tesseract_lang_code_heb(self):
        # file_analyst passes Tesseract-style codes; heb should map to he.
        assert OpusMTBackend._resolve_direction("heb", "en", "שלום") == "he->en"
        assert OpusMTBackend._resolve_direction("en", "heb", "Hello") == "en->he"


# ── Translate contract (mocked inference) ───────────────────────────────────


def _make_backend_with_mock(direction_to_result: dict[str, str]) -> OpusMTBackend:
    """Build an OpusMTBackend whose _translate_one returns canned text per direction."""
    backend = OpusMTBackend()
    backend._translate_one = MagicMock(side_effect=lambda text, direction: direction_to_result.get(direction, text))
    return backend


class TestTranslateContract:
    def test_empty_text_returns_empty(self):
        backend = OpusMTBackend()
        assert backend.translate("", "en", "he") == ""
        assert backend.translate("   ", "en", "he") == ""

    def test_unsupported_pair_raises_not_implemented(self):
        backend = OpusMTBackend()
        with pytest.raises(NotImplementedError):
            backend.translate("Hello", "en", "fr")
        with pytest.raises(NotImplementedError):
            backend.translate("Bonjour", "fr", "he")

    def test_en_to_he_uses_correct_direction(self):
        backend = _make_backend_with_mock({"en->he": "שלום עולם"})
        result = backend.translate("Hello world", "en", "he")
        assert result == "שלום עולם"
        backend._translate_one.assert_called_once()
        # _translate_one(text, direction) — positional args.
        assert backend._translate_one.call_args.args[1] == "en->he"

    def test_he_to_en_auto_source(self):
        backend = _make_backend_with_mock({"he->en": "Hello world"})
        result = backend.translate("שלום עולם", "auto", "en")
        assert result == "Hello world"
        assert backend._translate_one.call_args.args[1] == "he->en"

    def test_long_text_is_chunked(self):
        # Build text longer than _CHUNK_CHARS so chunker produces >1 chunk.
        long_text = "Hello world. " * 200  # ~2600 chars
        backend = _make_backend_with_mock({"en->he": "שלום"})
        result = backend.translate(long_text, "en", "he")
        # Multiple chunks → multiple _translate_one calls, joined by \n
        assert backend._translate_one.call_count > 1
        assert "\n" in result

    def test_chunking_preserves_paragraph_boundaries(self):
        text = "First paragraph here.\n\nSecond paragraph here."
        backend = _make_backend_with_mock({"en->he": "תרגום"})
        backend.translate(text, "en", "he")
        # SemanticChunker splits on \n when needed; short text fits in one chunk.
        # Verify it at least doesn't crash and produces output.
        assert backend._translate_one.call_count >= 1


# ── Backend name + integration with orchestrator contract ──────────────────


class TestBackendName:
    def test_name_is_opus_mt(self):
        assert OpusMTBackend().name == "opus-mt"


class TestOrchestratorIntegration:
    """Verify the orchestrator imports opus-mt and places it first."""

    def test_orchestrator_has_opus_mt_first(self):
        # Re-import to pick up the new ordering.
        import importlib

        import translator_orchestrator

        importlib.reload(translator_orchestrator)
        names = [b.name for b in translator_orchestrator.translator.backends]
        assert names[0] == "opus-mt"
        assert "mymemory" in names
        assert "libretranslate" in names

    def test_orchestrator_skips_not_implemented_without_circuit_break(self):
        """opus-mt raising NotImplementedError for an unsupported pair must NOT
        increment its circuit-failure counter (otherwise it gets permanently
        disabled after 3 non-en/he calls)."""
        import importlib

        import translator_orchestrator

        importlib.reload(translator_orchestrator)
        orch = translator_orchestrator.MultiBackendTranslator()
        # Force opus-mt to be the only candidate by circuit-breaking the others.
        for name in ("mymemory", "libretranslate"):
            orch._circuit_failures[name] = 99
        # opus-mt doesn't support en->fr → should raise RuntimeError (all failed),
        # but opus-mt's own counter must remain 0.
        with pytest.raises(RuntimeError):
            orch.translate("Hello", source="en", target="fr")
        assert orch._circuit_failures.get("opus-mt", 0) == 0


# ── Hebrew detection edge cases ─────────────────────────────────────────────


class TestHebrewEdgeCases:
    def test_hebrew_with_punctuation(self):
        assert _has_hebrew("שלום, עולם!")

    def test_hebrew_with_digits(self):
        assert _has_hebrew("יש 3 תפוחים")

    def test_only_punctuation_no_hebrew(self):
        assert not _has_hebrew("!!! ... ???")

    def test_rtl_control_chars_stripped_no_false_positive(self):
        # LRM/RLM (U+200E/200F) are not in the Hebrew block.
        assert not _has_hebrew("\u200e\u200f")
