"""Translator Skill — multi-backend orchestration with fallback chain.

Extracted from translator.py (SRP). ``MultiBackendTranslator`` orchestrates the
fallback across the backends defined in ``translator_backends.py``:

  opus-mt (offline, en↔he) → MyMemory → LibreTranslate

The opus-mt backend is tried first because it is fully offline, MIT-licensed,
and has the highest Hebrew BLEU score of any free option. It only serves
en↔he; for any other pair it raises NotImplementedError and the orchestrator
falls through to the online backends.

Responsibilities:
- Circuit-breaker per backend (skip after N consecutive failures)
- Parallel chunk translation via a thread pool
- Language detection (langdetect → LibreTranslate → heuristic)
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from opus_mt_backend import OpusMTBackend
from translator_backends import (
    LibreTranslateBackend,
    MyMemoryBackend,
    TranslationBackend,
)
from translator_config import (
    LANGDETECT_AVAILABLE,
    MAX_WORKERS,
    _chunker,
    detect,
    detect_langs,
)


class MultiBackendTranslator:
    """Orchestrates fallback across multiple backends."""

    def __init__(self) -> None:
        # Ordered by reliability for free/no-key usage.
        # opus-mt is first: offline, MIT, best Hebrew BLEU. Only serves en↔he;
        # for other pairs it raises NotImplementedError and we fall through.
        self.backends: list[TranslationBackend] = [
            OpusMTBackend(),
            MyMemoryBackend(),
            LibreTranslateBackend(),
        ]
        self._circuit_failures: dict[str, int] = {}
        self._circuit_threshold = 3

    def translate(
        self,
        text: str,
        source: str = "auto",
        target: str = "he",
        force_backend: str | None = None,
    ) -> tuple[str, str]:
        """Returns (translated_text, backend_name). Raises RuntimeError if all fail."""
        if not text or not text.strip():
            return ("", "none")

        chunks = _chunker.chunk(text)

        # Pick ordered list of backends to try
        if force_backend:
            candidates = [b for b in self.backends if b.name == force_backend]
            if not candidates:
                raise ValueError(f"Unknown backend: {force_backend}")
        else:
            candidates = [
                b
                for b in self.backends
                if self._circuit_failures.get(b.name, 0) < self._circuit_threshold
            ]

        last_err: Exception | None = None
        for backend in candidates:
            try:
                if len(chunks) == 1:
                    result = backend.translate(chunks[0], source, target)
                else:
                    result = self._translate_chunks_parallel(
                        backend, chunks, source, target
                    )
                self._circuit_failures[backend.name] = 0
                return (result, backend.name)
            except NotImplementedError:
                # Backend does not serve this language pair (e.g. opus-mt for
                # non-en/he). Skip without penalizing the circuit breaker —
                # the backend is still healthy for its supported pairs.
                continue
            except Exception as e:
                self._circuit_failures[backend.name] = (
                    self._circuit_failures.get(backend.name, 0) + 1
                )
                last_err = e
                time.sleep(0.5)

        raise RuntimeError(f"All translation backends failed. Last error: {last_err}")

    def _translate_chunks_parallel(
        self, backend: TranslationBackend, chunks: list[str], source: str, target: str
    ) -> str:
        out = [""] * len(chunks)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(backend.translate, chunk, source, target): idx
                for idx, chunk in enumerate(chunks)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                out[idx] = fut.result()
        # Chunks are split on paragraph (\n) boundaries → rejoin with \n to
        # restore the original paragraph structure across chunks.
        return "\n".join(out)

    def detect_language(self, text: str) -> dict[str, Any]:
        sample = (text or "").strip()[:500]
        if not sample:
            return {"language": None, "confidence": 0.0}

        # Method 1: langdetect
        if LANGDETECT_AVAILABLE:
            try:
                detected = detect(sample)
                probabilities = detect_langs(sample)
                confidence = probabilities[0].prob if probabilities else 1.0
                return {
                    "language": detected,
                    "confidence": confidence,
                    "method": "langdetect",
                    "sample": sample[:120],
                }
            except Exception:
                pass

        # Method 2: LibreTranslate detect
        for backend in self.backends:
            if isinstance(backend, LibreTranslateBackend):
                try:
                    info = backend.detect_language(text)
                    if info:
                        return info
                except Exception:
                    pass

        # Method 3: heuristic
        return self._detect_heuristic(sample)

    @staticmethod
    def _detect_heuristic(sample: str) -> dict[str, Any]:
        ranges = {
            "he": (0x0590, 0x05FF),
            "ar": (0x0600, 0x06FF),
            "ru": (0x0400, 0x04FF),
            "el": (0x0370, 0x03FF),
            "zh": (0x4E00, 0x9FFF),
            "ja": (0x3040, 0x30FF),
            "ko": (0xAC00, 0xD7AF),
        }
        counts = {k: 0 for k in ranges}
        for ch in sample:
            o = ord(ch)
            for code, (lo, hi) in ranges.items():
                if lo <= o <= hi:
                    counts[code] += 1
        guess = max(counts, key=counts.get) if any(counts.values()) else "en"
        return {
            "language": guess,
            "confidence": 0.5,
            "method": "heuristic",
            "fallback": True,
        }


# Global translator instance
translator = MultiBackendTranslator()
