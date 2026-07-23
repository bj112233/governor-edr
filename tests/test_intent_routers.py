# tests/test_intent_routers.py
"""Tests for deterministic intent routers in services/agent/routing/intent_routers.py.

Covers: IOC detection (moved from osint_search), CVE, hash, file-path,
process, YARA, and the unified detect_intent() dispatcher.
"""

import sys
from pathlib import Path

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.agent.routing.intent_routers import (
    _is_cve_query,
    _is_file_path_query,
    _is_hash_query,
    _is_ioc_query,
    _is_process_query,
    _is_yara_query,
    detect_intent,
)

# ── IOC detection (moved from osint_search — verify compat) ──


class TestIOCDetection:
    def test_pure_ipv4(self):
        assert _is_ioc_query("1.2.3.4") is True

    def test_pure_ipv6(self):
        assert _is_ioc_query("2001:db8::1") is True

    def test_hash_md5(self):
        assert _is_ioc_query("d41d8cd98f00b204e9800998ecf8427e") is True

    def test_hash_sha256(self):
        assert _is_ioc_query("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True

    def test_bare_domain(self):
        assert _is_ioc_query("evil.com") is True

    def test_cve_not_ioc(self):
        assert _is_ioc_query("CVE-2024-3094") is False

    def test_sentence_not_ioc(self):
        assert _is_ioc_query("what is xz utils backdoor") is False


# ── CVE detection ──


class TestCVEDetection:
    def test_standard_cve(self):
        assert _is_cve_query("CVE-2024-3094") == "CVE-2024-3094"

    def test_cve_in_sentence(self):
        assert _is_cve_query("מה זה CVE-2023-22515?") == "CVE-2023-22515"

    def test_cve_lowercase(self):
        assert _is_cve_query("cve-2024-12345") == "CVE-2024-12345"

    def test_no_cve(self):
        assert _is_cve_query("scan my network") is None

    def test_empty(self):
        assert _is_cve_query("") is None


# ── Hash detection ──


class TestHashDetection:
    def test_bare_md5(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        assert _is_hash_query(h) == h

    def test_bare_sha256(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _is_hash_query(h) == h

    def test_hash_with_intent_keyword(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        assert _is_hash_query(f"check this malware hash {h}") == h

    def test_hash_without_intent(self):
        """Hash appearing in a non-hash context should not trigger."""
        assert _is_hash_query("the file d41d8cd98f00b204e9800998ecf8427e is large") is None

    def test_empty(self):
        assert _is_hash_query("") is None


# ── File path detection ──


class TestFilePathDetection:
    def test_windows_path_summarize(self):
        result = _is_file_path_query("summarize C:\\Users\\test\\report.pdf")
        assert result is not None
        path, action = result
        assert "report.pdf" in path
        assert action == "summarize"

    def test_windows_path_ocr(self):
        result = _is_file_path_query("ocr C:\\Users\\test\\scan.jpg")
        assert result is not None
        path, action = result
        assert "scan.jpg" in path
        assert action == "ocr"

    def test_image_extension_defaults_to_ocr(self):
        result = _is_file_path_query("analyze C:\\pics\\photo.png")
        assert result is not None
        _, action = result
        assert action == "ocr"

    def test_contract_keyword(self):
        result = _is_file_path_query("analyze this contract C:\\Docs\\lease.pdf")
        assert result is not None
        _, action = result
        assert action == "contract"

    def test_no_intent_keyword(self):
        """File path without intent keyword should not trigger."""
        assert _is_file_path_query("C:\\Users\\test\\report.pdf") is None

    def test_unsupported_extension(self):
        assert _is_file_path_query("summarize C:\\test\\file.xyz") is None

    def test_empty(self):
        assert _is_file_path_query("") is None


# ── Process detection ──


class TestProcessDetection:
    def test_list_processes_en(self):
        result = _is_process_query("show running processes")
        assert result is not None
        action, pid = result
        assert action == "list"
        assert pid is None

    def test_list_processes_he(self):
        result = _is_process_query("הצג תהליכים רצים")
        assert result is not None
        assert result[0] == "list"

    def test_kill_with_pid(self):
        result = _is_process_query("kill PID 1234")
        assert result is not None
        action, pid = result
        assert action == "kill"
        assert pid == 1234

    def test_kill_he(self):
        result = _is_process_query("הרוג תהליך 5678")
        assert result is not None
        assert result[0] == "kill"
        assert result[1] == 5678

    def test_kill_without_pid(self):
        """Kill intent without a PID should not trigger."""
        assert _is_process_query("kill the hanging process") is None

    def test_no_process_keyword(self):
        assert _is_process_query("show me the network") is None

    def test_empty(self):
        assert _is_process_query("") is None


# ── YARA detection ──


class TestYARADetection:
    def test_yara_scan_en(self):
        result = _is_yara_query("yara scan C:\\malware\\sample.exe")
        assert result is not None
        assert "sample.exe" in result

    def test_yara_he(self):
        result = _is_yara_query("סריקת yara על C:\\test\\file.bin")
        assert result is not None
        assert "file.bin" in result

    def test_no_yara_keyword(self):
        assert _is_yara_query("scan C:\\malware\\sample.exe") is None

    def test_empty(self):
        assert _is_yara_query("") is None


# ── Unified detect_intent ──


class TestDetectIntent:
    def test_ioc_ip(self):
        result = detect_intent("8.8.8.8")
        assert result is not None
        assert result["intent"] == "ioc"
        assert result["tool"] == "skill_intel-skill"
        assert result["args"]["command"] == "ip"

    def test_ioc_hash(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = detect_intent(h)
        assert result["intent"] == "ioc"
        assert result["args"]["command"] == "hash"

    def test_ioc_domain(self):
        result = detect_intent("evil.com")
        assert result["intent"] == "ioc"
        assert result["args"]["command"] == "domain"

    def test_cve(self):
        result = detect_intent("CVE-2024-3094")
        assert result["intent"] == "cve"
        assert result["tool"] == "osint_hunt"
        assert result["args"]["topic"] == "CVE-2024-3094"

    def test_hash_with_keyword(self):
        h = "d41d8cd98f00b204e9800998ecf8427e"
        result = detect_intent(f"check malware hash {h}")
        assert result["intent"] == "hash"
        assert result["args"]["target"] == h

    def test_yara(self):
        result = detect_intent("yara scan C:\\test\\file.bin")
        assert result["intent"] == "yara"
        assert result["tool"] == "scan_file_yara"

    def test_file_path(self):
        result = detect_intent("summarize C:\\Docs\\report.pdf")
        assert result["intent"] == "file"
        assert result["tool"] == "skill_file-analyst"

    def test_process_list(self):
        result = detect_intent("show running processes")
        assert result["intent"] == "process_list"
        assert result["tool"] == "get_process_list"

    def test_process_kill(self):
        result = detect_intent("kill PID 1234")
        assert result["intent"] == "process_kill"
        assert result["tool"] == "terminate_process"
        assert result["args"]["pid"] == 1234

    def test_no_match(self):
        assert detect_intent("what is the weather today") is None

    def test_empty(self):
        assert detect_intent("") is None

    def test_priority_ioc_over_cve(self):
        """A pure IP should be IOC, not CVE (even if CVE appears in text)."""
        result = detect_intent("1.2.3.4")
        assert result["intent"] == "ioc"
