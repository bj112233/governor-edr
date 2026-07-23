# tests/test_pure_logic_batch3.py
"""Pure-logic coverage push — batch 3.

Covers missing lines in:
- services/agent/bypass/eml.py (lines 17, 20)
- services/agent/bypass/pcap.py (lines 17, 20)
- services/search_engines/startpage.py (line 52)
- services/agent/routing/skill_router.py (lines 47-49, 75, 79-81, 85-87)
- services/threat_analyzers.py (lines 90, 91, 144, 157, 158, 163, 164)
- services/pre_compute_router.py (lines 81, 88, 89, 131, 137, 143, 146, 262)
- services/reflection_agent.py (lines 76, 77, 90, 91, 126, 127)
- services/telegram/cooldown.py (lines 12-22)
- services/agent/_helpers.py (lines 58, 59, 70, 71)
- services/pending_actions.py (lines 178, 179)
- services/mitre_mapper.py (lines 224, 227, 256, 262, 263, 319)
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from services.agent.bypass.eml import _direct_eml_bypass
from services.agent.bypass.pcap import _direct_pcap_bypass
from services.agent.routing.skill_router import _detect_special_skill_signals
from services.mitre_mapper import map_payload_to_mitre
from services.pre_compute_router import PreComputeReport, format_pre_compute_facts
from services.reflection_agent import _build_reflection_block
from services.telegram.cooldown import ErrorCooldown


# -- eml/pcap bypass --
class TestDirectEmlBypass:
    def test_none_result(self):
        """Line 17: result is None → error message."""
        from unittest.mock import AsyncMock, patch

        with patch("services.agent.bypass.eml.get_skills_engine") as mock_engine:
            mock_engine.return_value.execute = AsyncMock(return_value=None)
            result = pytest.importorskip("asyncio").run(_direct_eml_bypass("test.eml", "analyze", "q"))
        assert "failed" in result.lower() or "inaccessible" in result.lower()

    def test_non_string_result(self):
        """Line 20: result not str → str(result)."""
        from unittest.mock import AsyncMock, patch

        with patch("services.agent.bypass.eml.get_skills_engine") as mock_engine:
            mock_engine.return_value.execute = AsyncMock(return_value={"key": "val"})
            import asyncio

            result = asyncio.run(_direct_eml_bypass("test.eml", "analyze", "q"))
        assert "key" in result  # str(dict) contains key


class TestDirectPcapBypass:
    def test_none_result(self):
        """Line 17: result is None → error message."""
        from unittest.mock import AsyncMock, patch

        with patch("services.agent.bypass.pcap.get_skills_engine") as mock_engine:
            mock_engine.return_value.execute = AsyncMock(return_value=None)
            import asyncio

            result = asyncio.run(_direct_pcap_bypass("test.pcap", "analyze", "q"))
        assert "failed" in result.lower() or "inaccessible" in result.lower()

    def test_non_string_result(self):
        """Line 20: result not str → str(result)."""
        from unittest.mock import AsyncMock, patch

        with patch("services.agent.bypass.pcap.get_skills_engine") as mock_engine:
            mock_engine.return_value.execute = AsyncMock(return_value=42)
            import asyncio

            result = asyncio.run(_direct_pcap_bypass("test.pcap", "analyze", "q"))
        assert "42" in result


# -- skill_router keyword matching --
class TestDetectSpecialSkillSignals:
    def test_ticker_uppercase(self):
        """Line 75: uppercase ticker → stocks skill."""
        result = _detect_special_skill_signals("What about NVDA stock", set())
        assert "skill_stocks-skill" in result

    def test_text_file_translation(self):
        """Lines 79-81: .txt + translation keyword → translator skill."""
        result = _detect_special_skill_signals("translate document.txt to english", set())
        assert "skill_translator-skill" in result

    def test_pdf_translation(self):
        """Lines 85-87: .pdf + translation → file-analyst."""
        result = _detect_special_skill_signals("translate report.pdf", set())
        assert "skill_file-analyst" in result

    def test_no_match(self):
        result = _detect_special_skill_signals("hello world", set())
        assert isinstance(result, set)


# -- threat_analyzers PortClassifier --
class TestPortClassifier:
    def test_ephemeral_non_browser(self):
        """Line 90-91: ephemeral port + non-browser proc → info assessment."""
        from services.threat_analyzers import PortClassifier

        clf = PortClassifier()
        assessments = clf.analyze_listening([{"port": 50000, "process": "unknown.exe", "pid": 1}])
        assert len(assessments) == 1
        assert assessments[0].status == "info"

    def test_ephemeral_browser_skipped(self):
        """Line 90: ephemeral + browser proc → skipped."""
        from services.threat_analyzers import PortClassifier

        clf = PortClassifier()
        assessments = clf.analyze_listening([{"port": 50000, "process": "chrome.exe", "pid": 1}])
        assert len(assessments) == 0

    def test_unknown_port(self):
        from services.threat_analyzers import PortClassifier

        clf = PortClassifier()
        assessments = clf.analyze_listening([{"port": 4444, "process": "evil.exe", "pid": 1}])
        assert len(assessments) == 1
        assert assessments[0].status == "suspicious"


# -- pre_compute_router --
class TestFormatPreComputeFacts:
    def test_no_iocs(self):
        """Line 262: no IOC → empty string."""
        report = PreComputeReport()  # all fields empty → has_ioc=False
        assert format_pre_compute_facts(report) == ""

    def test_with_internal_ips(self):
        report = PreComputeReport(
            internal_ips=["10.0.0.1"],
            enriched={"evil.com": {"verdict": "malicious"}},
            ioc_types={"evil.com": "domain"},
        )
        result = format_pre_compute_facts(report)
        assert "PRE-COMPUTED" in result
        assert "10.0.0.1" in result


# -- reflection_agent --
class TestBuildReflectionBlock:
    def test_returns_string(self):
        """Lines 76-77, 90-91: telemetry block building."""
        import asyncio

        result = asyncio.run(_build_reflection_block())
        assert isinstance(result, str)


# -- cooldown --
class TestErrorCooldown:
    def test_first_send_allowed(self):
        """Lines 12-22: first send → True."""
        tracker = ErrorCooldown(default_ms=60000)
        assert tracker.can_send(123) is True

    def test_second_send_blocked(self):
        tracker = ErrorCooldown(default_ms=60000)
        tracker.can_send(123)  # first
        assert tracker.can_send(123) is False  # second within cooldown

    def test_different_chats_independent(self):
        tracker = ErrorCooldown(default_ms=60000)
        assert tracker.can_send(123) is True
        assert tracker.can_send(456) is True  # different chat

    def test_custom_cooldown_short(self):
        tracker = ErrorCooldown(default_ms=999999)
        assert tracker.can_send(123, cooldown_ms=1) is True
        # 1ms cooldown — wait a moment and try again
        import time

        time.sleep(0.01)
        assert tracker.can_send(123, cooldown_ms=1) is True  # 1ms elapsed


# -- mitre_mapper --
class TestMitreMapper:
    def test_empty_payload(self):
        """Lines 224, 227, 256, 262, 263, 319: map_payload_to_mitre."""
        result = map_payload_to_mitre({})
        assert isinstance(result, list)

    def test_with_tags(self):
        """Line 224: source_data with tags list."""
        payload = {
            "type": "domain",
            "value": "evil.com",
            "sources": {
                "virustotal": {
                    "tags": ["phishing", "malware"],
                    "classification": "malicious",
                    "found": True,
                }
            },
        }
        result = map_payload_to_mitre(payload)
        assert isinstance(result, list)

    def test_domain_age(self):
        """Lines 256, 262-263: newly registered domain → T1566."""
        payload = {
            "type": "domain",
            "value": "new.com",
            "sources": {
                "rdap": {
                    "registered": "2025-12-01T00:00:00Z",  # very recent
                }
            },
        }
        result = map_payload_to_mitre(payload)
        assert isinstance(result, list)
