# tests/test_critic_tool_claims.py
"""Tests for _audit_tool_claims — deterministic fabricated tool-name detection.

Verifies the pre-LLM filter that catches drafts referencing tools that were
stripped by the planner or never authorized. Runs in micro-seconds (pure regex).
"""

from services.agent._agent_tool_audit import _audit_tool_claims


class TestAuditToolClaims:
    """Unit tests for deterministic tool-claim audit."""

    def test_fabricated_tool_detected(self):
        """Draft mentions get_event_log but it never ran → flagged."""
        draft = "בוצעו בדיקות על ידי get_event_log ונמצאו פעילויות חשודות."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert any("get_event_log" in r.lower() for r in result)

    def test_real_tool_not_flagged(self):
        """Draft mentions scan_suspicious_procs which actually ran → not flagged."""
        draft = "כלי scan_suspicious_procs הריץ סריקה מלאה."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert result == []

    def test_final_answer_never_flagged(self):
        """final_answer is always in ran_names → never flagged."""
        draft = "The final_answer was generated."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert result == []

    def test_substring_match_not_flagged(self):
        """If candidate is substring of a ran tool → not flagged (line 58)."""
        draft = "Used get_proc for analysis."
        tools_used = [{"name": "get_process_list"}]
        result = _audit_tool_claims(draft, tools_used)
        # "get_proc" is a substring of "get_process_list" → not fabricated
        assert all("get_proc" not in r for r in result)

    def test_ran_tool_substring_of_candidate_not_flagged(self):
        """If ran tool is substring of candidate → not flagged (line 58)."""
        draft = "Used get_process_list_detailed for analysis."
        tools_used = [{"name": "get_process_list"}]
        result = _audit_tool_claims(draft, tools_used)
        # "get_process_list" is substring of "get_process_list_detailed" → not flagged
        assert all("get_process_list" not in r for r in result)

    def test_skill_prefix_variant_not_flagged(self):
        """skill_ prefix variant in ran_names → not flagged (line 55)."""
        draft = "Used sentinel_scan for detection."
        tools_used = [{"name": "skill_sentinel_scan"}]
        result = _audit_tool_claims(draft, tools_used)
        assert result == []

    def test_multiple_fabricated_tools(self):
        """Multiple fabricated tools all flagged."""
        draft = "get_event_log and sentinel_watchdog and skill_forensics were used."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert len(result) >= 3

    def test_empty_draft_returns_empty(self):
        """Empty draft → no candidates."""
        assert _audit_tool_claims("", [{"name": "get_process_list"}]) == []

    def test_empty_tools_used_returns_empty(self):
        """Empty tools_used → no audit (avoid false positives)."""
        draft = "get_event_log was used."
        assert _audit_tool_claims(draft, []) == []

    def test_process_filename_not_flagged(self):
        """Process filenames like get_process.exe should NOT be flagged (negative lookahead)."""
        draft = "Found get_process.exe running."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert result == []

    def test_backtick_quoted_tool_name(self):
        """Backtick-quoted tool names are extracted."""
        draft = "Used `get_network_connections` for analysis."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert any("get_network_connections" in r.lower() for r in result)

    def test_mixed_real_and_fabricated(self):
        """Mix of real and fabricated — only fabricated flagged."""
        draft = "scan_suspicious_procs found issues, get_event_log confirmed."
        tools_used = [{"name": "scan_suspicious_procs"}]
        result = _audit_tool_claims(draft, tools_used)
        assert any("get_event_log" in r.lower() for r in result)
        assert all("scan_suspicious_procs" not in r for r in result)
