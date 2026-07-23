# tests/test_tool_claim_audit.py
"""Regression tests for deterministic tool-claim audit in the critic.

Bug (bot.log 2026-06-26 03:50): The 4B model synthesized a threat hunt report
claiming "בוצעו בדיקות עומס על ידי הכלים get_system_snapshot ו-get_event_log"
— but get_event_log was STRIPPED by the planner (unauthorized). The CoVe
critic PASSed this draft because it can't distinguish real tool_data from
hallucinated tool references.

Fix: _audit_tool_claims runs as a PRE-FILTER before the LLM critic. It
extracts tool-name references from the draft (both backtick-quoted and bare
get_/sentinel_/skill_ prefixed names) and cross-checks against ctx._tools_used.
If the draft mentions tools that never ran, the verdict is forced to FAIL.
"""

from services.agent._agent_tool_audit import _audit_tool_claims

BT = chr(96)  # backtick

_TOOLS_RAN = [
    {"name": "get_system_snapshot"},
    {"name": "skill_intel-skill"},
]


# ── Detection: fabricated tool references ──


def test_fabricated_tool_in_backticks():
    """Draft mentions get_event_log in backticks, but it never ran."""
    draft = f"בוצעו בדיקות על ידי {BT}get_system_snapshot{BT} ו-{BT}get_event_log{BT}."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert "get_event_log" in result


def test_fabricated_tool_bare_text():
    """Draft mentions get_event_log without quotes (real report pattern)."""
    draft = "בוצעו בדיקות עומס על ידי הכלים get_system_snapshot ו-get_event_log."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert "get_event_log" in result


def test_fabricated_sentinel_tool():
    """Draft mentions sentinel_get_process_list which never ran."""
    draft = "בוצעה בדיקה על ידי sentinel_get_process_list."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert "sentinel_get_process_list" in result


def test_multiple_fabricated_tools():
    """Draft mentions several tools that never ran."""
    draft = f"נבדק על ידי {BT}get_event_log{BT}, {BT}get_process_list{BT}, ו-{BT}sentinel_clear_event_queue{BT}."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert "get_event_log" in result
    assert "get_process_list" in result
    assert "sentinel_clear_event_queue" in result


# ── No false positives: real tools only ──


def test_all_real_tools_backtick():
    """Draft only mentions tools that actually ran (backtick quoted)."""
    draft = f"סריקה על ידי {BT}get_system_snapshot{BT} ו-{BT}skill_intel-skill{BT}."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert result == []


def test_all_real_tools_bare():
    """Draft only mentions tools that actually ran (bare text)."""
    draft = "בוצעה סריקה על ידי get_system_snapshot ו-skill_intel-skill."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert result == []


def test_skill_prefix_matching():
    """Draft says 'intel-skill' but tool ran as 'skill_intel-skill'."""
    draft = f"סריקה על ידי {BT}intel-skill{BT}."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert result == []


def test_no_tool_references():
    """Draft has no tool references at all."""
    draft = "המערכת יציבה. CPU 0%, RAM 29%."
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert result == []


# ── Edge cases ──


def test_empty_draft():
    """Empty draft should return empty list."""
    assert _audit_tool_claims("", _TOOLS_RAN) == []


def test_empty_tools_used():
    """No tools ran — any tool reference is fabricated."""
    draft = f"בוצעה בדיקה על ידי {BT}get_event_log{BT}."
    # When tools_used is empty, the function returns [] (no baseline to compare)
    result = _audit_tool_claims(draft, [])
    assert result == []


def test_non_tool_words_ignored():
    """Common tech words (cpu, ram, json) should not be flagged."""
    draft = "CPU 0%, RAM 29%, JSON output, IP 1.2.3.4"
    result = _audit_tool_claims(draft, _TOOLS_RAN)
    assert result == []


def test_real_report_from_bot_log():
    """The actual fabricated report from bot.log 2026-06-26 03:50."""
    real_draft = (
        "בוצעו בדיקות עומס על ידי הכלים `get_system_snapshot` ו-`get_event_log`.\n"
        "בוצעה סריקה (`intel-skill` - Network Sweep Report).\n"
        "בוצעו בדיקות לוגים (`get_event_log`)."
    )
    result = _audit_tool_claims(real_draft, _TOOLS_RAN)
    assert "get_event_log" in result
    # intel-skill should NOT be flagged (matches skill_intel-skill)
    assert "intel-skill" not in result


if __name__ == "__main__":
    test_fabricated_tool_in_backticks()
    test_fabricated_tool_bare_text()
    test_fabricated_sentinel_tool()
    test_multiple_fabricated_tools()
    test_all_real_tools_backtick()
    test_all_real_tools_bare()
    test_skill_prefix_matching()
    test_no_tool_references()
    test_empty_draft()
    test_empty_tools_used()
    test_non_tool_words_ignored()
    test_real_report_from_bot_log()
    print("OK")
