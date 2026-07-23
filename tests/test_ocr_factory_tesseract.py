"""Tests for _ocr_factory.get_engine (Tesseract-only, post-EasyOCR removal).

Covers the two live branches:
  1. Tesseract available  -> returns memoized TesseractEngine.
  2. Tesseract unavailable -> RuntimeError with accurate message.
Also verifies legacy 'easyocr' preference falls back to Tesseract without
raising, and that the singleton is memoized (same instance on repeat calls).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "file_analyst" / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import _ocr_factory  # noqa: E402
from _ocr_tesseract import TesseractEngine  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the module-level singleton between tests."""
    _ocr_factory._engine = None
    yield
    _ocr_factory._engine = None


class TestGetEngineAvailable:
    def test_auto_returns_tesseract(self):
        with patch.object(TesseractEngine, "available", return_value=True):
            eng = _ocr_factory.get_engine(preferred="auto", lang="eng+heb+ara")
        assert eng.name() == "tesseract"

    def test_explicit_tesseract(self):
        with patch.object(TesseractEngine, "available", return_value=True):
            eng = _ocr_factory.get_engine(preferred="tesseract", lang="heb")
        assert eng.name() == "tesseract"

    def test_legacy_easyocr_falls_back_without_raising(self):
        with patch.object(TesseractEngine, "available", return_value=True):
            eng = _ocr_factory.get_engine(preferred="easyocr", lang="eng")
        assert eng.name() == "tesseract"

    def test_singleton_is_memoized(self):
        with patch.object(TesseractEngine, "available", return_value=True):
            eng1 = _ocr_factory.get_engine(preferred="auto")
            eng2 = _ocr_factory.get_engine(preferred="auto")
        assert eng1 is eng2


class TestGetEngineUnavailable:
    def test_runtime_error_when_binary_missing(self):
        with (
            patch.object(TesseractEngine, "available", return_value=False),
            patch("builtins.__import__", side_effect=_import_no_pytesseract),
        ):
            with pytest.raises(RuntimeError, match="pytesseract"):
                _ocr_factory.get_engine(preferred="auto", lang="eng")

    def test_runtime_error_when_package_missing(self):
        # pytesseract importable but binary not found -> "binary not found"
        with patch.object(TesseractEngine, "available", return_value=False):
            with pytest.raises(RuntimeError, match="binary not found"):
                _ocr_factory.get_engine(preferred="auto", lang="eng")

    def test_legacy_easyocr_still_raises_when_no_engine(self):
        with (
            patch.object(TesseractEngine, "available", return_value=False),
            patch("builtins.__import__", side_effect=_import_no_pytesseract),
        ):
            with pytest.raises(RuntimeError):
                _ocr_factory.get_engine(preferred="easyocr", lang="eng")


def _import_no_pytesseract(name, *args, **kwargs):
    """Custom __import__ that blocks only 'pytesseract'."""
    if name == "pytesseract":
        raise ImportError("no pytesseract")
    import builtins

    return builtins.__import__(name, *args, **kwargs)
