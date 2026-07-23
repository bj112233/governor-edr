# tests/test_critic_speculation.py
"""Tests for speculation detection — prevents False-FAIL backstop on speculative drafts.

Validates:
1. _detect_speculation catches invented threat terms not in tool data
2. Speculation guard forces has_flaw=True, blocking False-FAIL backstop
3. Clean drafts (no speculation) are not flagged
"""

from services.agent._agent_tool_audit import _apply_speculation_guard, _detect_speculation


def test_speculation_powershell_bypass_detected():
    """Draft mentions 'PowerShell Bypass' but tool data has no PowerShell."""
    draft = "PowerShell Bypass: תהליכי Python ייתכן ויישמו עקומות PowerShell מוצפנות."
    tool_data = "python.exe connecting to 149.154.167.92:443"
    result = _detect_speculation(draft, tool_data)
    assert result is not None
    assert "powershell" in result.lower() or "bypass" in result.lower()


def test_speculation_theoretical_detected():
    """Draft mentions 'theoretical' analysis not in tool data."""
    draft = "ניתוח איום תיאורטי: ייתכן והמערכת נגועה בתוכנה זדונית."
    tool_data = "CPU: 15%, RAM: 50%, no threats found"
    result = _detect_speculation(draft, tool_data)
    assert result is not None


def test_speculation_might_be_detected():
    """Draft uses 'might be' speculation not grounded in tool data."""
    draft = "This process might be used for data exfiltration."
    tool_data = "Process: chrome.exe, PID: 1234, port 443"
    result = _detect_speculation(draft, tool_data)
    assert result is not None


def test_clean_draft_no_speculation():
    """Draft with only grounded facts should not trigger speculation."""
    draft = "נמצאו 16 כתובות IP ייחודיות. 3 כתובות הוגדרו כחשודות."
    tool_data = "16 unique IPs, 3 flagged: 149.154.167.92, 149.154.166.110, 2001:67c:4e8:f004::9"
    result = _detect_speculation(draft, tool_data)
    assert result is None


def test_speculation_marker_in_tool_data_not_flagged():
    """If the speculative term IS in tool data, it's grounded — not flagged."""
    draft = "PowerShell bypass detected in event log."
    tool_data = "Event ID 4104: PowerShell bypass script block logging enabled."
    result = _detect_speculation(draft, tool_data)
    assert result is None


def test_empty_draft_no_speculation():
    """Empty draft should return None."""
    assert _detect_speculation("", "tool data") is None


def test_empty_tool_data_no_speculation():
    """Empty tool data should return None (no grounding possible)."""
    assert _detect_speculation("some draft", "") is None


def test_speculation_could_be_used():
    """Draft uses 'could be used' speculation."""
    draft = "The connection could be used for C2 communication."
    tool_data = "TCP connection to 8.8.8.8:53"
    result = _detect_speculation(draft, tool_data)
    assert result is not None


# ── _apply_speculation_guard ─────────────────────────────────────────────────


def test_guard_forces_flaw_on_speculation():
    """Guard should force has_flaw=True when speculation detected and no existing flaw."""
    draft = "PowerShell bypass might be used for exfiltration."
    tool_data = "python.exe connecting to 8.8.8.8"
    has_flaw, logical_flaw = _apply_speculation_guard(draft, tool_data, False, "")
    assert has_flaw is True
    assert "Speculative claim" in logical_flaw


def test_guard_preserves_existing_flaw():
    """Guard should not overwrite existing logical_flaw_raw."""
    draft = "PowerShell bypass might be used."
    tool_data = "python.exe"
    has_flaw, logical_flaw = _apply_speculation_guard(draft, tool_data, False, "EXISTING FLAW")
    assert has_flaw is True
    assert logical_flaw == "EXISTING FLAW"


def test_guard_no_action_when_no_speculation():
    """Guard should not modify has_flaw when no speculation detected."""
    draft = "CPU is 15%, RAM is 50%."
    tool_data = "CPU: 15%, RAM: 50%"
    has_flaw, logical_flaw = _apply_speculation_guard(draft, tool_data, False, "")
    assert has_flaw is False
    assert logical_flaw == ""


def test_guard_no_action_when_flaw_already_true():
    """Guard should not modify when has_flaw already True."""
    draft = "PowerShell bypass might be used."
    tool_data = "python.exe"
    has_flaw, logical_flaw = _apply_speculation_guard(draft, tool_data, True, "EXISTING")
    assert has_flaw is True
    assert logical_flaw == "EXISTING"
