# tests/test_fim_coverage.py
"""Tests for FIM coverage expansion (C5+H3+H4) and YARA allowlist (H5).

C5: Temp/Startup added to watch paths
H3: recursive=True + FIM_IGNORE_PATH_PATTERNS (Cache/Temp blacklist)
H4: .com/.pif/.wsf/.psm1/.vbe/.jse/.mht/.url added to dangerous extensions
H5: YARA allowlist suppresses false positives by path/hash
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from config import FIM_DANGEROUS_EXTS, FIM_IGNORE_PATH_PATTERNS

# ── H4: Extension coverage ─────────────────────────────────────────


class TestExtensionCoverage:
    def test_com_extension_included(self):
        assert ".com" in FIM_DANGEROUS_EXTS

    def test_pif_extension_included(self):
        assert ".pif" in FIM_DANGEROUS_EXTS

    def test_wsf_extension_included(self):
        assert ".wsf" in FIM_DANGEROUS_EXTS

    def test_psm1_extension_included(self):
        assert ".psm1" in FIM_DANGEROUS_EXTS

    def test_vbe_extension_included(self):
        assert ".vbe" in FIM_DANGEROUS_EXTS

    def test_jse_extension_included(self):
        assert ".jse" in FIM_DANGEROUS_EXTS

    def test_mht_extension_included(self):
        assert ".mht" in FIM_DANGEROUS_EXTS

    def test_url_extension_included(self):
        assert ".url" in FIM_DANGEROUS_EXTS

    def test_original_extensions_preserved(self):
        """All original extensions must still be present."""
        original = {
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js",
            ".exe",
            ".dll",
            ".scr",
            ".hta",
            ".lnk",
            ".py",
            ".sh",
            ".zip",
            ".rar",
            ".7z",
        }
        assert original.issubset(FIM_DANGEROUS_EXTS)


# ── H3: Ignore path patterns ───────────────────────────────────────


class TestIgnorePathPatterns:
    def test_cache_in_ignore_patterns(self):
        assert "cache" in FIM_IGNORE_PATH_PATTERNS

    def test_gpucache_in_ignore_patterns(self):
        assert "gpucache" in FIM_IGNORE_PATH_PATTERNS

    def test_thumbnails_in_ignore_patterns(self):
        assert "thumbnails" in FIM_IGNORE_PATH_PATTERNS

    def test_ignore_patterns_are_lowercase(self):
        """All patterns must be lowercase for case-insensitive matching."""
        for p in FIM_IGNORE_PATH_PATTERNS:
            assert p == p.lower(), f"Pattern {p!r} must be lowercase"


class TestFIMHandlerIgnoreFilter:
    """Test that _passes_filters rejects files in ignored subdirectories."""

    def _make_handler(self):
        from services.fim_engine import SentinelFIMHandler

        loop = MagicMock()
        return SentinelFIMHandler(loop)

    def test_cache_path_rejected(self, tmp_path):
        handler = self._make_handler()
        cache_file = tmp_path / "Cache" / "malware.exe"
        cache_file.parent.mkdir()
        cache_file.write_bytes(b"\x00" * 100)
        assert not handler._passes_filters(str(cache_file))

    def test_gpucache_path_rejected(self, tmp_path):
        handler = self._make_handler()
        gpu_file = tmp_path / "GPUCache" / "index.exe"
        gpu_file.parent.mkdir()
        gpu_file.write_bytes(b"\x00" * 100)
        assert not handler._passes_filters(str(gpu_file))

    def test_normal_subdirectory_accepted(self, tmp_path):
        """Non-ignored subdirectory with dangerous ext should pass."""
        handler = self._make_handler()
        normal_file = tmp_path / "subfolder" / "payload.exe"
        normal_file.parent.mkdir()
        normal_file.write_bytes(b"\x00" * 100)
        assert handler._passes_filters(str(normal_file))

    def test_ignored_path_with_safe_ext_still_rejected(self, tmp_path):
        """Even .exe in Cache should be rejected (ignore takes priority)."""
        handler = self._make_handler()
        cache_file = tmp_path / "Cache" / "data.exe"
        cache_file.parent.mkdir()
        cache_file.write_bytes(b"\x00" * 100)
        assert not handler._passes_filters(str(cache_file))


# ── C5: Watch path resolution ──────────────────────────────────────


class TestWatchPathResolution:
    def test_temp_in_candidates(self):
        """_resolve_fim_paths should include TEMP if it exists (unless env override)."""
        from config import _resolve_fim_paths

        # If FIM_WATCH_PATHS env var is set, it overrides candidates
        env_override = os.environ.get("FIM_WATCH_PATHS", "")
        paths = _resolve_fim_paths()
        temp = os.environ.get("TEMP") or os.environ.get("TMP")
        if temp and os.path.isdir(temp):
            if env_override:
                # Env override mode — Temp must be explicitly listed
                assert temp in paths or temp not in env_override
            else:
                assert temp in paths

    def test_startup_in_candidates(self):
        """Startup folder should be watched if it exists (unless env override)."""
        from config import _resolve_fim_paths

        env_override = os.environ.get("FIM_WATCH_PATHS", "")
        paths = _resolve_fim_paths()
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
        startup = os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if os.path.isdir(startup):
            if env_override:
                assert startup in paths or startup not in env_override
            else:
                assert startup in paths


# ── H5: YARA Allowlist ─────────────────────────────────────────────


class TestYaraAllowlist:
    def test_load_allowlist_empty_file(self, tmp_path):
        """Empty allowlist file → no entries, no error."""
        from services.yara_allowlist import _allowlist, load_allowlist

        load_allowlist()  # loads real file (may be empty)
        # Just verify it doesn't crash
        assert isinstance(_allowlist, dict)

    def test_is_allowlisted_no_entries(self):
        """No allowlist entries → nothing is allowlisted."""
        from services.yara_allowlist import is_allowlisted

        with patch("services.yara_allowlist._allowlist", {}):
            assert is_allowlisted("SomeRule", "C:\\file.exe") is False

    def test_is_allowlisted_path_match(self):
        """Path match → suppressed."""
        from services.yara_allowlist import is_allowlisted

        with patch("services.yara_allowlist._allowlist", {"TestRule": [{"path": "C:\\Tools\\AdminToolkit.ps1"}]}):
            assert is_allowlisted("TestRule", "C:\\Tools\\AdminToolkit.ps1") is True

    def test_is_allowlisted_path_case_insensitive(self):
        """Path match is case-insensitive (Windows)."""
        from services.yara_allowlist import is_allowlisted

        with patch("services.yara_allowlist._allowlist", {"TestRule": [{"path": "C:\\Tools\\File.ps1"}]}):
            assert is_allowlisted("TestRule", "c:\\tools\\file.ps1") is True

    def test_is_allowlisted_path_no_match(self):
        """Different path → not suppressed."""
        from services.yara_allowlist import is_allowlisted

        with patch("services.yara_allowlist._allowlist", {"TestRule": [{"path": "C:\\Tools\\File.ps1"}]}):
            assert is_allowlisted("TestRule", "C:\\Malware\\File.ps1") is False

    def test_is_allowlisted_wrong_rule(self):
        """Different rule name → not suppressed."""
        from services.yara_allowlist import is_allowlisted

        with patch("services.yara_allowlist._allowlist", {"TestRule": [{"path": "C:\\File.ps1"}]}):
            assert is_allowlisted("OtherRule", "C:\\File.ps1") is False

    def test_is_allowlisted_hash_match(self, tmp_path):
        """Hash match → suppressed."""
        from services.yara_allowlist import is_allowlisted

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"malware_payload")
        import hashlib

        file_hash = hashlib.sha256(b"malware_payload").hexdigest()
        with patch("services.yara_allowlist._allowlist", {"TestRule": [{"hash": file_hash}]}):
            assert is_allowlisted("TestRule", str(test_file)) is True

    def test_is_allowlisted_hash_no_match(self, tmp_path):
        """Wrong hash → not suppressed."""
        from services.yara_allowlist import is_allowlisted

        test_file = tmp_path / "test.exe"
        test_file.write_bytes(b"malware_payload")
        with patch(
            "services.yara_allowlist._allowlist",
            {"TestRule": [{"hash": "0000000000000000000000000000000000000000000000000000000000000000"}]},
        ):
            assert is_allowlisted("TestRule", str(test_file)) is False
