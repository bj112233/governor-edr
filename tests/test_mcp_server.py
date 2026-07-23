import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from services import local_mcp_server as mcp


class TestCheckMcpRateLimit:
    """Per-IP rate limiter tests."""

    def setup_method(self):
        # Isolate each test by clearing the global rate store.
        mcp._mcp_rate_store.clear()

    def test_first_call_within_limit(self):
        assert mcp._check_mcp_rate_limit("1.2.3.4") is True

    def test_rate_limit_blocks_after_threshold(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_RATE_LIMIT", 2)
        ip = "5.6.7.8"
        assert mcp._check_mcp_rate_limit(ip) is True
        assert mcp._check_mcp_rate_limit(ip) is True
        # 3rd call exceeds limit of 2
        assert mcp._check_mcp_rate_limit(ip) is False

    def test_different_ips_independent(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_RATE_LIMIT", 1)
        assert mcp._check_mcp_rate_limit("1.1.1.1") is True
        # Different IP should still be allowed
        assert mcp._check_mcp_rate_limit("2.2.2.2") is True

    def test_stale_entries_cleaned(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_RATE_EXPIRY", 1)  # 1 second expiry
        ip = "3.3.3.3"
        mcp._check_mcp_rate_limit(ip)
        # Manually set timestamp to be old
        mcp._mcp_rate_store[ip] = [time.time() - 10]
        # Next call should trigger cleanup and succeed
        assert mcp._check_mcp_rate_limit(ip) is True

    def test_window_prunes_old_entries(self, monkeypatch):
        monkeypatch.setattr(mcp, "_MCP_RATE_LIMIT", 1)
        ip = "4.4.4.4"
        mcp._check_mcp_rate_limit(ip)
        # Old entry still in window, so next call blocked
        assert mcp._check_mcp_rate_limit(ip) is False


class TestVerifyMcpAuth:
    """Bearer token authentication tests."""

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "")
    async def test_no_token_configured(self):
        req = MagicMock()
        req.headers = {}
        with pytest.raises(HTTPException) as exc:
            await mcp._verify_mcp_auth(req, None)
        assert exc.value.status_code == 503
        assert "not configured" in exc.value.detail

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "secret-token")
    async def test_missing_header(self):
        req = MagicMock()
        req.headers = {}
        with pytest.raises(HTTPException) as exc:
            await mcp._verify_mcp_auth(req, None)
        assert exc.value.status_code == 401
        assert "Missing" in exc.value.detail

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "secret-token")
    async def test_invalid_token(self):
        req = MagicMock()
        req.headers = {"Authorization": "Bearer wrong-token"}
        with pytest.raises(HTTPException) as exc:
            await mcp._verify_mcp_auth(req, None)
        assert exc.value.status_code == 403
        assert "Invalid" in exc.value.detail

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "secret-token")
    async def test_valid_token(self):
        req = MagicMock()
        req.headers = {"Authorization": "Bearer secret-token"}
        # Should not raise
        await mcp._verify_mcp_auth(req, None)

    @patch("services.local_mcp_server.MCP_AUTH_TOKEN", "secret-token")
    async def test_case_sensitive_token(self):
        req = MagicMock()
        req.headers = {"Authorization": "Bearer Secret-Token"}
        with pytest.raises(HTTPException) as exc:
            await mcp._verify_mcp_auth(req, None)
        assert exc.value.status_code == 403
