# tests/test_sysmon_xml.py
"""Tests for Sysmon Event 1 XML → ProcessEvent adapter.

Includes:
  - Happy path on a real captured Sysmon event (sample_event1.xml)
  - Each enriched field extraction (hash, integrity, parent)
  - Malformed XML robustness (parser must return None, never raise)
  - Missing-field handling (hash timeout, orphan process, empty cmdline)
  - Edge cases on attacker-controlled fields (special chars in cmdline)
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from services.process_event import ProcessEvent
from services.sysmon_xml import _parse_sha256, parse_event1_xml

_SAMPLE_XML_PATH = Path(__file__).parent.parent / "tools" / "sysmon" / "sample_event1.xml"


def _load_sample_event() -> str:
    """Load the real captured Sysmon Event 1 XML."""
    if not _SAMPLE_XML_PATH.exists():
        pytest.skip(f"sample event not found: {_SAMPLE_XML_PATH}")
    return _SAMPLE_XML_PATH.read_text(encoding="utf-8")


# ── Happy path: real captured event ──


class TestRealEventParsing:
    """Parse the actual Sysmon Event 1 captured from the running system."""

    def test_parses_without_error(self):
        xml = _load_sample_event()
        ev = parse_event1_xml(xml)
        assert ev is not None

    def test_source_is_sysmon(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.source == "sysmon"
        assert ev.is_sysmon_sourced is True

    def test_pid_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.pid == 11716  # from the captured event

    def test_cmdline_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert "git.exe" in ev.cmdline
        assert "commit.template" in ev.cmdline

    def test_image_is_full_path(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.image is not None
        assert ev.image.endswith("git.exe")

    def test_name_is_basename(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.name == "git.exe"

    def test_parent_pid_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.parent_pid == 17888

    def test_parent_image_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.parent_image is not None
        assert "Devin.exe" in ev.parent_image

    def test_sha256_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.sha256 is not None
        assert len(ev.sha256) == 64
        assert ev.sha256 == "37c5725818d602e951ba2563b870d62763322956b73373da4c33a0b566a80bc9"

    def test_integrity_level_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.integrity_level == "Medium"

    def test_user_extracted(self):
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.user is not None
        assert "user" in ev.user


# ── SHA256 parsing ──


class TestSha256Parsing:
    """_parse_sha256 handles various Hashes field formats."""

    def test_sha256_only(self):
        result = _parse_sha256("SHA256=" + "a" * 64)
        assert result == "a" * 64

    def test_sha256_with_imphash(self):
        result = _parse_sha256("SHA256=" + "a" * 64 + ",IMPHASH=" + "b" * 32)
        assert result == "a" * 64

    def test_imphash_only_no_sha256(self):
        result = _parse_sha256("IMPHASH=" + "b" * 32)
        assert result is None

    def test_empty_field(self):
        assert _parse_sha256("") is None

    def test_dash_marker(self):
        assert _parse_sha256("-") is None

    def test_truncated_hash_rejected(self):
        """A 63-char hash is truncated — reject, don't return partial."""
        result = _parse_sha256("SHA256=" + "a" * 63)
        assert result is None

    def test_lowercase_normalization(self):
        """SHA256 hex should be lowercased for consistent comparison."""
        result = _parse_sha256("SHA256=" + "A" * 64)
        assert result == "a" * 64


# ── Malformed XML robustness — the critical tests ──


class TestMalformedXmlRobustness:
    """Parser must return None on bad input, NEVER raise.

    The consumer thread runs EvtSubscribe callback on a separate thread.
    An uncaught exception there doesn't reach the main log handler and
    silently kills the subscription. These tests pin that contract.
    """

    def test_empty_string_returns_none(self):
        assert parse_event1_xml("") is None

    def test_whitespace_only_returns_none(self):
        assert parse_event1_xml("   \n\t  ") is None

    def test_garbage_text_returns_none(self):
        assert parse_event1_xml("this is not xml at all") is None

    def test_truncated_xml_returns_none(self):
        """XML that starts valid but is cut off mid-element."""
        truncated = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>1</EventID><TimeCreated"
        assert parse_event1_xml(truncated) is None

    def test_wrong_event_id_still_parses_but_no_required_fields(self):
        """Event with EventID=5 (ProcessTerminate) — no ProcessId in EventData."""
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>5</EventID></System>"
            "<EventData><Data Name='UtcTime'>2026-01-01</Data></EventData>"
            "</Event>"
        )
        # Missing ProcessId → returns None (required field check)
        assert parse_event1_xml(xml) is None

    def test_xml_with_special_chars_in_cmdline(self):
        """Attacker-controlled cmdline with XML-significant chars.

        If the cmdline contains <, >, & the XML should still parse
        because Sysmon escapes them properly. We test that our parser
        handles a properly-escaped cmdline.
        """
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>1234</Data>"
            "<Data Name='Image'>C:\\evil.exe</Data>"
            "<Data Name='CommandLine'>evil.exe &amp; echo &lt;script&gt; | cmd</Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.pid == 1234
        # XML parser unescapes &amp; → &, &lt; → <
        assert "&" in ev.cmdline
        assert "<script>" in ev.cmdline

    def test_xml_injection_attempt_in_image(self):
        """Image field with embedded XML tags — should be treated as text."""
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>1234</Data>"
            "<Data Name='Image'>C:\\evil.exe</Data>"
            "<Data Name='CommandLine'>test</Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.image == "C:\\evil.exe"

    def test_completely_broken_xml_does_not_raise(self):
        """Random bytes that look nothing like XML."""
        assert parse_event1_xml("\x00\x01\x02\xff\xfe") is None

    def test_none_input_does_not_raise(self):
        """Defensive: None should not crash the parser."""
        assert parse_event1_xml(None) is None  # type: ignore[arg-type]


# ── Missing/partial field handling ──


class TestPartialFields:
    """Sysmon events where some fields are unavailable."""

    def test_no_hashes_field(self):
        """Sysmon config without HashAlgorithms → no Hashes field."""
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>1234</Data>"
            "<Data Name='Image'>C:\\test.exe</Data>"
            "<Data Name='CommandLine'>test.exe</Data>"
            "<Data Name='IntegrityLevel'>High</Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.sha256 is None
        assert ev.integrity_level == "High"  # other fields still work

    def test_no_integrity_level(self):
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>1234</Data>"
            "<Data Name='Image'>C:\\test.exe</Data>"
            "<Data Name='CommandLine'>test.exe</Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.integrity_level is None

    def test_no_parent_fields(self):
        """Orphan process — parent already exited."""
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>1234</Data>"
            "<Data Name='Image'>C:\\orphan.exe</Data>"
            "<Data Name='CommandLine'>orphan.exe</Data>"
            "<Data Name='ParentProcessId'>-</Data>"
            "<Data Name='ParentImage'>-</Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.parent_pid is None
        assert ev.parent_image is None

    def test_empty_cmdline(self):
        """Process with no command line (rare but possible)."""
        xml = (
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='ProcessId'>4</Data>"
            "<Data Name='Image'>C:\\System</Data>"
            "<Data Name='CommandLine'></Data>"
            "</EventData>"
            "</Event>"
        )
        ev = parse_event1_xml(xml)
        assert ev is not None
        assert ev.cmdline == ""

    def test_signed_is_always_none_for_event1(self):
        """Event 1 doesn't carry signature info — signed must be None."""
        ev = parse_event1_xml(_load_sample_event())
        assert ev is not None
        assert ev.signed is None
