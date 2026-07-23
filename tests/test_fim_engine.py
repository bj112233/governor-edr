"""Tests for FIM engine — filters, retry, thread-safe handoff."""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.fim_engine import SentinelFIMHandler, is_running, start_fim, stop_fim


class TestFIMFilters:
    """Test the 3-layer filter (extension + size + path)."""

    def test_dangerous_extension_passes(self):
        loop = asyncio.new_event_loop()
        handler = SentinelFIMHandler(loop)
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as f:
            f.write(b"powershell -enc test")
            path = f.name
        assert handler._passes_filters(path) is True
        Path(path).unlink()

    def test_safe_extension_filtered(self):
        loop = asyncio.new_event_loop()
        handler = SentinelFIMHandler(loop)
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"hello world")
            path = f.name
        assert handler._passes_filters(path) is False
        Path(path).unlink()

    def test_empty_file_filtered(self):
        loop = asyncio.new_event_loop()
        handler = SentinelFIMHandler(loop)
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as f:
            path = f.name
        assert handler._passes_filters(path) is False  # size == 0
        Path(path).unlink()

    def test_large_file_filtered(self):
        loop = asyncio.new_event_loop()
        handler = SentinelFIMHandler(loop)
        handler._max_size = 100  # tiny limit for test
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as f:
            f.write(b"A" * 200)
            path = f.name
        assert handler._passes_filters(path) is False  # > 100 bytes
        Path(path).unlink()

    def test_directory_event_skipped(self):
        loop = asyncio.new_event_loop()
        handler = SentinelFIMHandler(loop)
        event = MagicMock()
        event.is_directory = True
        event.src_path = "/some/dir"
        # Should not raise — just returns
        handler.on_created(event)


class TestFIMScanRetry:
    """Test exponential backoff for PermissionError."""

    @pytest.mark.asyncio
    async def test_scan_success_no_retry(self):
        loop = asyncio.get_running_loop()
        handler = SentinelFIMHandler(loop)
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as f:
            f.write("powershell.exe -enc SGVsbG8=")
            path = f.name
        with patch("services.yara_engine.match_with_retry", return_value=[]):
            await handler._scan_with_retry(path)
        Path(path).unlink()
        assert handler._stats["scanned"] == 1

    @pytest.mark.asyncio
    async def test_scan_with_match_emits_alert(self):
        loop = asyncio.get_running_loop()
        handler = SentinelFIMHandler(loop)
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False, mode="w") as f:
            f.write("powershell.exe -enc test")
            path = f.name
        fake_results = [{"rule": "powershell_encoded_command", "meta": {"mitre": "T1059.001", "severity": "high"}}]
        with patch("services.yara_engine.match_with_retry", return_value=fake_results):
            with patch("services.sentinel_events.event_bus.emit_alert", new_callable=AsyncMock):
                await handler._scan_with_retry(path)
        Path(path).unlink()
        assert handler._stats["matched"] == 1


class TestFIMLifecycle:
    """Test start/stop FIM observer."""

    def test_start_fim_with_no_paths(self):
        with patch("services.fim_engine.FIM_WATCH_PATHS", []):
            with patch("config._resolve_fim_paths", return_value=[]):
                result = start_fim(asyncio.new_event_loop())
                assert result is False

    def test_stop_fim_when_not_running(self):
        stop_fim()  # should not raise
        assert is_running() is False


# Helper for async mock
from unittest.mock import AsyncMock  # noqa: E402
