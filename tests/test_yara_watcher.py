"""Tests for YARA rules watcher + MCP reload endpoint."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services import yara_rules_watcher as watcher


class TestYaraRulesWatcher:
    @pytest.fixture(autouse=True)
    def _restore_state(self):
        old_observer = watcher._observer
        old_loop = watcher._main_loop
        old_timer = watcher._debounce_timer
        yield
        if watcher._observer is not None:
            watcher.stop_watcher()
        watcher._observer = old_observer
        watcher._main_loop = old_loop
        watcher._debounce_timer = old_timer

    def test_event_is_dir_on_real_dir(self):
        assert watcher.event_is_dir("C:/Windows") is True

    def test_event_is_dir_on_file(self, tmp_path):
        f = tmp_path / "test.yar"
        f.write_text("rule x { condition: true }")
        assert watcher.event_is_dir(str(f)) is False

    def test_event_is_dir_on_nonexistent(self):
        # Non-existent path returns False (not a dir)
        assert watcher.event_is_dir("C:/nonexistent/path/xyz") is False

    def test_start_watcher_success(self):
        loop = asyncio.new_event_loop()
        try:
            assert watcher.start_watcher(loop) is True
            assert watcher.is_running() is True
        finally:
            watcher.stop_watcher()
            loop.close()
        assert watcher.is_running() is False

    def test_start_watcher_no_rules_dir(self, monkeypatch):
        fake_dir = MagicMock()
        fake_dir.exists = MagicMock(return_value=False)
        monkeypatch.setattr(watcher, "_RULES_DIR", fake_dir)
        loop = asyncio.new_event_loop()
        try:
            assert watcher.start_watcher(loop) is False
        finally:
            loop.close()

    def test_handler_ignores_non_yar_files(self):
        handler = watcher._YaraRulesHandler()
        with patch.object(watcher, "_debounce_timer") as mock_timer:
            handler._maybe_reload("C:/some/file.txt")
            mock_timer.cancel.assert_not_called()

    def test_handler_ignores_directories(self):
        handler = watcher._YaraRulesHandler()
        with patch.object(watcher, "event_is_dir", return_value=True):
            with patch.object(watcher, "_debounce_timer") as mock_timer:
                handler._maybe_reload("C:/some/dir")
                mock_timer.cancel.assert_not_called()

    def test_handler_debounces_yar_files(self):
        handler = watcher._YaraRulesHandler()
        with patch.object(watcher, "event_is_dir", return_value=False):
            with patch("services.yara_rules_watcher.threading.Timer") as MockTimer:
                mock_instance = MagicMock()
                MockTimer.return_value = mock_instance
                handler._maybe_reload("C:/rules/new_rule.yar")
                MockTimer.assert_called_once()
                assert MockTimer.call_args[0][0] == watcher._DEBOUNCE_SECONDS
                mock_instance.start.assert_called_once()

    def test_fire_reload_no_loop(self):
        watcher._main_loop = None
        # Should not raise, just log warning
        watcher._fire_reload()

    def test_fire_reload_with_loop(self):
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = True
        watcher._main_loop = mock_loop
        with patch("services.yara_engine.reload_rules", new_callable=AsyncMock) as mock_reload:
            with patch("services.yara_rules_watcher.asyncio.run_coroutine_threadsafe") as mock_rts:
                watcher._fire_reload()
                mock_rts.assert_called_once()
                mock_reload.assert_called_once()


class TestMcpReloadYaraEndpoint:
    """Test the /mcp/reload_yara endpoint registration and auth."""

    def test_endpoint_registered(self):
        from services.local_mcp_server import app

        paths = [r.path for r in app.routes if hasattr(r, "path")]
        assert "/mcp/reload_yara" in paths

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "test-token")
    async def test_endpoint_calls_reload_rules(self):
        from services.local_mcp_server import reload_yara_rules

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        with patch("services.local_mcp_server._check_mcp_rate_limit", return_value=True):
            with patch("services.yara_engine.reload_rules", new_callable=AsyncMock) as mock_reload:
                mock_reload.return_value = {"files": 3, "rules": 42}
                result = await reload_yara_rules(mock_request)
                assert result["result"]["files"] == 3
                assert result["result"]["rules"] == 42
                mock_reload.assert_called_once()

    async def test_endpoint_rate_limited(self):
        from fastapi import HTTPException

        from services.local_mcp_server import reload_yara_rules

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        with patch("services.local_mcp_server._check_mcp_rate_limit", return_value=False):
            with pytest.raises(HTTPException) as exc:
                await reload_yara_rules(mock_request)
            assert exc.value.status_code == 429
