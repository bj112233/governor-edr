"""Translator Skill — translation backend implementations.

Extracted from translator.py (SRP). Defines the ``TranslationBackend`` ABC and
the three concrete backends used in the fallback chain:

- ``MyMemoryBackend``        — free, no signup, 50+ languages (no auto-detect)
- ``LibreTranslateBackend``  — LibreTranslate public API, 100+ languages

All backends are free, require no API key, and (where supported) auto-detect the
source language.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Any

from translator_config import (
    LANGDETECT_AVAILABLE,
    LIBRE_INSTANCES,
    _normalize_lang,
    detect,
)

_USER_AGENT = "Mozilla/5.0 (compatible; translator-bot/1.0)"


class TranslationBackend(ABC):
    """Abstract translation backend."""

    name: str = ""

    @abstractmethod
    def translate(self, text: str, source: str, target: str) -> str: ...

    def detect_language(self, text: str) -> dict[str, Any] | None:
        return None


class LibreTranslateBackend(TranslationBackend):
    """LibreTranslate public API — free, no key, 100+ languages."""

    name = "libretranslate"
    _last_working_index = 0

    def _request(self, instance: str, text: str, source: str, target: str) -> str:
        url = f"{instance}/translate"
        data = {
            "q": text,
            "source": source if source != "auto" else "auto",
            "target": target,
            "format": "text",
        }
        payload = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": _USER_AGENT,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read())
        return body["translatedText"]

    def translate(self, text: str, source: str, target: str) -> str:
        if not text or not text.strip():
            return ""
        errors = []
        for offset in range(len(LIBRE_INSTANCES)):
            idx = (self._last_working_index + offset) % len(LIBRE_INSTANCES)
            instance = LIBRE_INSTANCES[idx]
            try:
                result = self._request(instance, text, source, target)
                self._last_working_index = idx
                return result
            except Exception as e:
                errors.append(f"{instance}: {e}")
        raise RuntimeError(
            f"LibreTranslate failed on all {len(LIBRE_INSTANCES)} instances: {'; '.join(errors)}"
        )

    def detect_language(self, text: str) -> dict[str, Any] | None:
        sample = (text or "").strip()[:300]
        if not sample:
            return None
        for offset in range(len(LIBRE_INSTANCES)):
            idx = (self._last_working_index + offset) % len(LIBRE_INSTANCES)
            instance = LIBRE_INSTANCES[idx]
            try:
                url = f"{instance}/detect"
                payload = urllib.parse.urlencode({"q": sample}).encode()
                req = urllib.request.Request(
                    url,
                    data=payload,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                        "User-Agent": _USER_AGENT,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=20) as resp:
                    body = json.loads(resp.read())
                if body and len(body) > 0:
                    best = max(body, key=lambda x: x.get("confidence", 0))
                    self._last_working_index = idx
                    return {
                        "language": best.get("language"),
                        "confidence": best.get("confidence", 0.0),
                        "method": "libretranslate",
                        "sample": sample[:120],
                    }
            except Exception:
                continue
        return None


class MyMemoryBackend(TranslationBackend):
    """MyMemory — free, no signup, 1000 words/day anonymous, 50+ languages."""

    name = "mymemory"

    def translate(self, text: str, source: str, target: str) -> str:
        if not text or not text.strip():
            return ""
        if source == "auto":
            # MyMemory does not support auto-detect; fallback to langdetect/heuristic
            sample = text.strip()[:300]
            detected = "en"
            if LANGDETECT_AVAILABLE:
                try:
                    detected = detect(sample)
                except Exception:
                    pass
            else:
                # quick heuristic
                for ch in sample:
                    o = ord(ch)
                    if 0x0590 <= o <= 0x05FF:
                        detected = "he"
                        break
                    if 0x0600 <= o <= 0x06FF:
                        detected = "ar"
                        break
                    if 0x0400 <= o <= 0x04FF:
                        detected = "ru"
                        break
            source = detected
        pair = f"{_normalize_lang(source)}|{_normalize_lang(target)}"
        params = {"q": text, "langpair": pair}
        url = "https://api.mymemory.translated.net/get?" + urllib.parse.urlencode(
            params
        )
        req = urllib.request.Request(
            url, headers={"User-Agent": _USER_AGENT}
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read())
        if body.get("responseStatus") != 200:
            raise RuntimeError(
                f"MyMemory error {body.get('responseStatus')}: {body.get('responseDetails')}"
            )
        return body["responseData"]["translatedText"]


