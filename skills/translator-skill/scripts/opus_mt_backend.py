"""OpusMT backend — offline Helsinki-NLP/opus-mt translation via CTranslate2 or transformers.

Free (MIT code + CC-BY 4.0 models), self-hostable, no API key, no rate limit.
Primary backend for Hebrew ↔ English in the orchestrator fallback chain.

Supported pairs (the only ones with proven high BLEU on Hebrew):
    en → he  : Helsinki-NLP/opus-mt-en-he             (BLEU 40.1, chr-F 0.609)
    he → en  : Helsinki-NLP/opus-mt-tc-big-he-en      (BLEU 53.8, chr-F 0.686)

For any other language pair this backend raises NotImplementedError so the
orchestrator falls through to MyMemory / LibreTranslate.

Design:
- CTranslate2 path (4-6x faster, int8) is used when a converted model directory
  is present locally under ``_OPUS_CT2_DIR``. Conversion is a one-time offline
  step (``ct2-opus-mt-converter``); not done automatically here to avoid
  surprising multi-GB downloads.
- Otherwise the transformers ``pipeline`` is used (auto-downloads from HF Hub on
  first call, cached afterwards via ``HF_HOME`` / ``TRANSFORMERS_CACHE``).
- Models load lazily on first ``translate()`` call and are cached at module
  level under a threading.Lock so concurrent Telegram workers share one
  instance.
- Long input is chunked by the shared SemanticChunker at ~480 chars (safe under
  the 512-token opus-mt limit) and translated in order.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Any

from translator_backends import TranslationBackend

# ── Model identifiers ──────────────────────────────────────────────────────
_MODEL_EN_HE = "Helsinki-NLP/opus-mt-en-he"
_MODEL_HE_EN = "Helsinki-NLP/opus-mt-tc-big-he-en"

# Optional local CTranslate2 model dirs. Set via env to enable the fast path:
#   OPUS_CT2_EN_HE=/path/to/converted-en-he
#   OPUS_CT2_HE_EN=/path/to/converted-he-en
_CT2_EN_HE_DIR = os.environ.get("OPUS_CT2_EN_HE")
_CT2_HE_EN_DIR = os.environ.get("OPUS_CT2_HE_EN")

# Chunk size for opus-mt — models cap at ~512 BPE tokens. 480 chars is a
# conservative bound that keeps most sentences under the limit even for
# Hebrew (which tokenizes denser than English).
_CHUNK_CHARS = 480

# Hebrew Unicode block — used to pick the direction when source is "auto".
_HEBREW_LO, _HEBREW_HI = 0x0590, 0x05FF


def _has_hebrew(text: str) -> bool:
    return any(_HEBREW_LO <= ord(c) <= _HEBREW_HI for c in text)


def _normalize_target(target: str) -> str:
    """Normalize target lang code to canonical ISO 639-1."""
    t = (target or "").lower().strip()
    # Accept "iw" (Google legacy) and "heb" (Tesseract) as Hebrew.
    if t in ("he", "heb", "iw", "he-il"):
        return "he"
    if t in ("en", "eng", "en-us"):
        return "en"
    return t


def _normalize_source(source: str) -> str:
    s = (source or "").lower().strip()
    if s in ("heb", "iw", "he-il"):
        return "he"
    if s in ("eng", "en-us"):
        return "en"
    return s


class OpusMTBackend(TranslationBackend):
    """Offline Helsinki-NLP/opus-mt translator (en↔he only)."""

    name = "opus-mt"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Lazy caches: direction -> loaded artifact
        self._ct2: dict[str, Any] = {}      # direction -> ctranslate2.Translator
        self._sp: dict[str, Any] = {}       # direction -> SentencePieceProcessor
        self._pipe: dict[str, Any] = {}     # direction -> transformers pipeline
        self._backend_kind: dict[str, str] = {}  # direction -> "ct2" | "transformers"

    # ── TranslationBackend API ─────────────────────────────────────────────
    def translate(self, text: str, source: str, target: str) -> str:
        if not text or not text.strip():
            return ""
        direction = self._resolve_direction(source, target, text)
        if direction is None:
            raise NotImplementedError(
                f"opus-mt only supports en↔he; got source={source!r} target={target!r}"
            )
        return self._translate_chunked(text, direction)

    # ── Direction resolution ───────────────────────────────────────────────
    @staticmethod
    def _resolve_direction(
        source: str, target: str, text: str
    ) -> str | None:
        """Return 'en->he' | 'he->en' | None (unsupported)."""
        tgt = _normalize_target(target)
        src = _normalize_source(source)
        if tgt not in ("he", "en"):
            return None
        # Resolve source when auto-detect requested.
        if src in ("auto", ""):
            src = "he" if _has_hebrew(text) else "en"
        if src == tgt:
            # No-op direction — only valid if we can still serve it (e.g. he->he
            # is a passthrough; but opus-mt has no he->he model). Signal
            # unsupported so the orchestrator can short-circuit or fall through.
            return None
        if src == "en" and tgt == "he":
            return "en->he"
        if src == "he" and tgt == "en":
            return "he->en"
        return None

    # ── Chunked translation ────────────────────────────────────────────────
    def _translate_chunked(self, text: str, direction: str) -> str:
        # Local import to avoid pulling SemanticChunker at module import time
        # (it lives in the same scripts dir; keeps the import graph lazy).
        from chunker import SemanticChunker

        chunker = SemanticChunker(_CHUNK_CHARS)
        chunks = chunker.chunk(text)
        if not chunks:
            return ""
        out = [self._translate_one(c, direction) for c in chunks]
        # Chunks split on paragraph boundaries → rejoin with \n to preserve
        # structure (matches MultiBackendTranslator._translate_chunks_parallel).
        return "\n".join(out)

    def _translate_one(self, text: str, direction: str) -> str:
        kind = self._ensure_loaded(direction)
        if kind == "ct2":
            return self._translate_ct2(text, direction)
        return self._translate_transformers(text, direction)

    # ── Lazy loading ───────────────────────────────────────────────────────
    def _ensure_loaded(self, direction: str) -> str:
        if direction in self._backend_kind:
            return self._backend_kind[direction]
        with self._lock:
            # Double-checked locking — another worker may have loaded it.
            if direction in self._backend_kind:
                return self._backend_kind[direction]
            kind = self._load(direction)
            self._backend_kind[direction] = kind
            return kind

    def _load(self, direction: str) -> str:
        """Load the model for one direction. Returns 'ct2' or 'transformers'."""
        ct2_dir = _CT2_EN_HE_DIR if direction == "en->he" else _CT2_HE_EN_DIR
        if ct2_dir and os.path.isdir(ct2_dir):
            try:
                self._load_ct2(direction, ct2_dir)
                print(
                    f"[opus-mt] loaded CTranslate2 model for {direction} from {ct2_dir}",
                    file=sys.stderr,
                    flush=True,
                )
                return "ct2"
            except Exception as e:
                print(
                    f"[opus-mt] CTranslate2 load failed for {direction}: {e}; "
                    "falling back to transformers",
                    file=sys.stderr,
                    flush=True,
                )
        # transformers fallback (auto-downloads on first call).
        self._load_transformers(direction)
        print(
            f"[opus-mt] loaded transformers pipeline for {direction}",
            file=sys.stderr,
            flush=True,
        )
        return "transformers"

    def _load_ct2(self, direction: str, model_dir: str) -> None:
        import ctranslate2
        import sentencepiece as spm

        device = "cpu"  # CPU-first; GPU via env override if needed.
        self._ct2[direction] = ctranslate2.Translator(
            model_dir, device=device, compute_type="int8"
        )
        sp_path = os.path.join(model_dir, "source.spm")
        self._sp[direction] = spm.SentencePieceProcessor()
        self._sp[direction].load(sp_path)

    def _load_transformers(self, direction: str) -> None:
        from transformers import AutoTokenizer, pipeline

        model_id = _MODEL_EN_HE if direction == "en->he" else _MODEL_HE_EN
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        # device=-1 → CPU. transformers pipeline returns a list[dict] for batch
        # input; we feed one string at a time.
        self._pipe[direction] = pipeline(
            "translation",
            model=model_id,
            tokenizer=tokenizer,
            device=-1,
            max_length=512,
        )

    # ── Inference ──────────────────────────────────────────────────────────
    def _translate_ct2(self, text: str, direction: str) -> str:
        translator = self._ct2[direction]
        sp = self._sp[direction]
        tokens = sp.encode(text, out_type=str)
        results = translator.translate_batch([tokens])
        if not results or not results[0].hypotheses:
            return text
        decoded = sp.decode(results[0].hypotheses[0])
        return decoded or text

    def _translate_transformers(self, text: str, direction: str) -> str:
        pipe = self._pipe[direction]
        out = pipe(text)
        if isinstance(out, list) and out:
            return out[0].get("translation_text", text)
        if isinstance(out, dict):
            return out.get("translation_text", text)
        return text
