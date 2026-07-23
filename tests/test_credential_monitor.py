"""Tests for credential_monitor + credential_patterns."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.credential_monitor import (
    _to_raw_url,
    format_credential_results,
    scan_credential_leaks,
)
from services.credential_patterns import extract_credentials, mask_credential

# ── credential_patterns tests ──


class TestExtractCredentials:
    def test_email_password_pair(self):
        text = "user@example.com:password123 admin@site.com|admin123"
        creds = extract_credentials(text)
        assert "email_password" in creds
        assert len(creds["email_password"]) == 2

    def test_aws_access_key(self):
        text = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        creds = extract_credentials(text)
        assert "aws_access_key" in creds
        assert creds["aws_access_key"][0] == "AKIAIOSFODNN7EXAMPLE"

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        creds = extract_credentials(text)
        assert "private_key" in creds
        assert len(creds["private_key"]) == 1

    def test_jwt_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        creds = extract_credentials(text)
        assert "jwt_token" in creds

    def test_db_connection_string(self):
        text = "DATABASE_URL=mysql://root:secretpass@localhost:3306/db"
        creds = extract_credentials(text)
        assert "db_connection" in creds
        assert "secretpass" in creds["db_connection"][0]

    def test_api_key_generic(self):
        text = 'api_key = "sk-1234567890abcdef1234567890abcdef"'
        creds = extract_credentials(text)
        assert "api_key" in creds

    def test_empty_text(self):
        assert extract_credentials("") == {}
        assert extract_credentials("no credentials here") == {}

    def test_dedup(self):
        text = "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE"
        creds = extract_credentials(text)
        assert len(creds["aws_access_key"]) == 1

    def test_multiple_types(self):
        text = """
        user@admin.com:pass123
        AWS_KEY=AKIAIOSFODNN7EXAMPLE
        mysql://user:pass@host/db
        """
        creds = extract_credentials(text)
        assert "email_password" in creds
        assert "aws_access_key" in creds
        assert "db_connection" in creds


class TestMaskCredential:
    def test_long_value(self):
        masked = mask_credential("AKIAIOSFODNN7EXAMPLE1234567890")
        assert masked.startswith("AKIA")
        assert masked.endswith("7890")
        assert "..." in masked

    def test_short_value(self):
        masked = mask_credential("pass123")
        assert "***" in masked

    def test_very_short(self):
        assert mask_credential("ab") == "***"


# ── credential_monitor tests ──


class TestToRawUrl:
    def test_pastebin_conversion(self):
        assert _to_raw_url("https://pastebin.com/abc123") == "https://pastebin.com/raw/abc123"

    def test_pastebin_already_raw(self):
        assert _to_raw_url("https://pastebin.com/raw/abc123") == "https://pastebin.com/raw/abc123"

    def test_gist_conversion(self):
        url = "https://gist.github.com/user/abc123"
        raw = _to_raw_url(url)
        assert "gist.githubusercontent.com" in raw
        assert raw.endswith("/raw")

    def test_other_url_unchanged(self):
        assert _to_raw_url("https://example.com/page") == "https://example.com/page"


class TestScanCredentialLeaks:
    @pytest.mark.asyncio
    async def test_empty_query(self):
        results = await scan_credential_leaks("")
        assert results["total_hits"] == 0
        assert results["sources"] == {}

    @pytest.mark.asyncio
    async def test_orchestrator_aggregates_sources(self):
        with (
            patch("services.credential_monitor.search_paste_sites", new_callable=AsyncMock) as mock_paste,
            patch("services.credential_monitor.search_github_code", new_callable=AsyncMock) as mock_github,
        ):
            mock_paste.return_value = [
                {
                    "url": "https://pastebin.com/x",
                    "snippet": "",
                    "snippet_credentials": {"email_password": ["u@e.com:p1"]},
                    "raw_credentials": {},
                }
            ]
            mock_github.return_value = [{"url": "https://github.com/r/f", "snippet": "", "credentials": {}}]
            results = await scan_credential_leaks("test.com")
        assert "paste_sites" in results["sources"]
        assert "github_code" in results["sources"]
        assert results["total_hits"] == 1  # one email_password from paste

    @pytest.mark.asyncio
    async def test_exception_handling(self):
        with (
            patch(
                "services.credential_monitor.search_paste_sites",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch("services.credential_monitor.search_github_code", new_callable=AsyncMock, return_value=[]),
        ):
            results = await scan_credential_leaks("test.com")
        assert results["sources"]["paste_sites"]["error"] == "boom"
        assert results["sources"]["github_code"] == []


class TestFormatCredentialResults:
    def test_empty_results(self):
        out = format_credential_results({"query": "test", "sources": {}, "total_hits": 0})
        assert "No credential leaks found." in out or "Total credential hits: 0" in out

    def test_with_credentials(self):
        results = {
            "query": "test.com",
            "total_hits": 2,
            "sources": {
                "paste_sites": [
                    {
                        "url": "https://pastebin.com/abc",
                        "snippet": "leaked data",
                        "snippet_credentials": {"email_password": ["user@test.com:pass123"]},
                        "raw_credentials": {"aws_access_key": ["AKIAIOSFODNN7EXAMPLE"]},
                    }
                ],
                "github_code": [],
                "psbdmp": [],
            },
        }
        out = format_credential_results(results)
        assert "paste_sites" in out
        assert "email_password" in out
        assert "aws_access_key" in out
        assert "Credentials found" in out

    def test_error_source(self):
        results = {
            "query": "test",
            "total_hits": 0,
            "sources": {"paste_sites": {"error": "connection failed"}},
        }
        out = format_credential_results(results)
        assert "Error" in out
