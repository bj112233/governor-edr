# tests/test_tier3_fim_provenance.py
"""Tests for Tier 3 Commit 3: M3 (cross-verification) + M10 (scan size) + M11 (stable-size).

M3: Provenance cross-verification — 2 trusted sources required (Byzantine tolerance)
M10: FIM scan size 10MB → 50MB (padded malware bypass)
M11: FIM stable-size check before YARA scan (race condition on partial write)
"""

import asyncio
import os
from unittest.mock import patch

import pytest

# ── M10: FIM scan size ──────────────────────────────────────────────


class TestFimScanSize:
    def test_default_scan_size_is_50mb(self):
        """M10: Default FIM_MAX_SCAN_SIZE should be 50MB (was 10MB)."""
        from config import FIM_MAX_SCAN_SIZE

        assert FIM_MAX_SCAN_SIZE == 50 * 1024 * 1024

    def test_50mb_file_passes_size_gate(self, tmp_path):
        """M10: A 49MB file should pass the size filter (was rejected at 10MB)."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        # Create a file just under 50MB — use mock for size
        test_file = tmp_path / "large.exe"
        test_file.write_bytes(b"\x00" * 100)  # small actual file
        with patch("os.path.getsize", return_value=49 * 1024 * 1024):
            assert handler._passes_filters(str(test_file)) is True

    def test_51mb_file_rejected(self, tmp_path):
        """M10: A 51MB file should still be rejected."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        test_file = tmp_path / "huge.exe"
        test_file.write_bytes(b"\x00" * 100)
        with patch("os.path.getsize", return_value=51 * 1024 * 1024):
            assert handler._passes_filters(str(test_file)) is False


# ── M11: Stable-size check ──────────────────────────────────────────


class TestStableSizeCheck:
    def test_stable_file_passes(self, tmp_path):
        """M11: File that doesn't change size → stable → scan proceeds."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        test_file = tmp_path / "stable.exe"
        test_file.write_bytes(b"\x00" * 1000)

        result = asyncio.run(handler._wait_for_stable_size(str(test_file)))
        assert result is True

    def test_growing_file_fails(self, tmp_path):
        """M11: File that keeps growing → unstable → scan skipped."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        test_file = tmp_path / "growing.exe"
        test_file.write_bytes(b"\x00" * 100)

        # Mock getsize to return increasing values
        sizes = iter([100, 200, 200, 300, 300, 400, 400])
        with patch("os.path.getsize", side_effect=lambda *a: next(sizes)):
            result = asyncio.run(handler._wait_for_stable_size(str(test_file), max_waits=3))
        assert result is False

    def test_nonexistent_file_fails(self, tmp_path):
        """M11: File that doesn't exist → fails."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        result = asyncio.run(handler._wait_for_stable_size(str(tmp_path / "nonexistent.exe")))
        assert result is False

    def test_zero_size_file_fails(self, tmp_path):
        """M11: Zero-size file → fails (still being written)."""
        from unittest.mock import MagicMock

        from services.fim_engine import SentinelFIMHandler

        handler = SentinelFIMHandler(MagicMock())
        test_file = tmp_path / "empty.exe"
        test_file.write_bytes(b"")
        with patch("os.path.getsize", return_value=0):
            result = asyncio.run(handler._wait_for_stable_size(str(test_file)))
        assert result is False


# ── M3: Cross-verification (additional tests) ──────────────────────


class TestM3CrossVerification:
    def test_two_trusted_no_taint_allowed(self):
        """M3: 2 trusted + 0 tainted → allowed (no taint to launder)."""
        from services.agent._provenance import ProvenanceRegistry

        reg = ProvenanceRegistry()
        reg.register("get_external_connections", "1.2.3.4")
        reg.register("get_process_list", "1.2.3.4 in PID 100")
        assert not reg.is_tainted_only("IP:1.2.3.4")

    def test_three_tainted_no_trusted_blocked(self):
        """M3: 3 tainted + 0 trusted → blocked."""
        from services.agent._provenance import ProvenanceRegistry

        reg = ProvenanceRegistry()
        reg.register("skill_news_monitor", "1.2.3.4")
        reg.register("skill_intel", "1.2.3.4")
        reg.register("web_search", "1.2.3.4")
        assert reg.is_tainted_only("IP:1.2.3.4")

    def test_two_trusted_one_tainted_allowed(self):
        """M3: 2 trusted + 1 tainted → cross-verified (Byzantine threshold met)."""
        from services.agent._provenance import ProvenanceRegistry

        reg = ProvenanceRegistry()
        reg.register("skill_intel", "5.5.5.5")
        reg.register("get_external_connections", "5.5.5.5")
        reg.register("get_process_list", "5.5.5.5 in PID 200")
        assert not reg.is_tainted_only("IP:5.5.5.5")
