"""Branch Rules — Deterministic Conditional DAG Routing tests.

Tests the static rule table that evaluates subtask results and returns
routing decisions: skip_to_final, inject, or continue.

Verifies:
  - Clean system (score 0.0 + no anomalies) → skip_to_final
  - Score 0.0 WITH anomalies → continue (no false skip)
  - C2 port 4444 detected → inject memory scan
  - Suspicious IOC flag → inject enrichment
  - No matching pattern → continue (default)
  - No remaining subtasks → continue (nothing to skip/inject)
  - Remaining subtask with final_answer → no skip (let it run)
  - Empty result → continue
  - Inject inserts correct description and reason
"""

from services.agent._branch_rules import (
    BranchDecision,
    _evaluate_branch_rules,
    _has_no_anomalies,
)

# ── Fixtures ────────────────────────────────────────────────────────────────

_SUBTASKS_4 = [
    {"id": "T1", "description": "Get system snapshot", "depends_on": [], "status": "done"},
    {"id": "T2", "description": "Scan suspicious processes", "depends_on": ["T1"], "status": "pending"},
    {"id": "T3", "description": "Get process list", "depends_on": ["T1"], "status": "pending"},
    {
        "id": "T4",
        "description": "Synthesize findings using final_answer",
        "depends_on": ["T2", "T3"],
        "status": "pending",
    },
]

_SUBTASKS_3_NO_FINAL = [
    {"id": "T1", "description": "Get system snapshot", "depends_on": [], "status": "done"},
    {"id": "T2", "description": "Scan processes", "depends_on": ["T1"], "status": "pending"},
    {"id": "T3", "description": "Get network info", "depends_on": ["T1"], "status": "pending"},
]


# ── Skip-to-Final Rules (DISABLED for threat hunting) ──────────────────────


class TestSkipToFinalDisabled:
    """skip_to_final is intentionally disabled for threat hunting.

    A clean surface snapshot does NOT mean the system is safe — deeper
    scans often reveal hidden threats. All clean-looking results must
    continue to deeper scans, not skip them.
    """

    def test_clean_score_zero_still_continues(self):
        """Score 0.0 + no anomalies → still continue (no skip)."""
        result = '{"threat_score": 0.0, "anomalies": [], "cpu": 12.5}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_real_snapshot_clean_system_continues(self):
        """Actual sentinel_get_system_snapshot_full output → continue, not skip."""
        result = (
            "**🛡️ Sentinel — תמונת מערכת**\n"
            "─────────────────────\n"
            "**🌐 חיבורים חשודים:** ✅ אין\n"
            "─────────────────────\n"
            "✅ **מצב מערכת: תקין**"
        )
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_real_snapshot_clean_with_final_answer_continues(self):
        """Snapshot clean + final_answer subtask remaining → continue."""
        result = "**🛡️ Sentinel — תמונת מערכת**\n**🌐 חיבורים חשודים:** ✅ אין\n✅ **מצב מערכת: תקין**"
        decision = _evaluate_branch_rules(result, _SUBTASKS_4, 0)
        assert decision.action == "continue"

    def test_real_snapshot_with_suspicious_connections_continues(self):
        """Snapshot with suspicious connections → continue."""
        result = "**🛡️ Sentinel — תמונת מערכת**\n**🌐 חיבורים חשודים:** ⚠️ נמצאו 2 חיבורים\n✅ **מצב מערכת: תקין**"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"


# ── Inject Rules ────────────────────────────────────────────────────────────


class TestInject:
    """High-signal patterns → inject a new subtask."""

    def test_c2_port_4444_open_injects_memory_scan(self):
        result = '{"ports": [{"port": 4444, "state": "open", "pid": 1234}]}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "inject"
        assert "scan_memory_for_injection" in decision.inject_description
        assert "port 4444" in decision.reason.lower() or "C2" in decision.reason

    def test_c2_port_4444_listening_injects(self):
        result = "Port 4444 is listening on 0.0.0.0"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "inject"

    def test_c2_port_4444_closed_no_inject(self):
        """Port 4444 mentioned but closed → no inject (false positive guard)."""
        result = '{"ports": [{"port": 4444, "state": "closed"}]}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_suspicious_ioc_flag_injects_enrichment(self):
        result = '{"ioc": "1.2.3.4", "suspicious": true, "score": 85}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "inject"
        assert "intel-skill" in decision.inject_description or "enrich" in decision.inject_description.lower()

    def test_suspicious_false_no_inject(self):
        """suspicious: false → no inject."""
        result = '{"ioc": "1.2.3.4", "suspicious": false}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_high_ttp_score_injects_deep_analysis(self):
        """TTP score 80+ → inject deep analysis."""
        result = "[PROCESS_SCAN_RESULT] Found 3 suspicious-name process(es).\n- PID 9892 | powershell.exe | TTP: T1059.001 (score=85, 42%)"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "inject"
        assert "intel-skill" in decision.inject_description or "deep" in decision.inject_description.lower()

    def test_low_ttp_score_no_inject(self):
        """TTP score < 80 → no inject (low priority)."""
        result = "[PROCESS_SCAN_RESULT] Found 5 suspicious-name process(es).\n- PID 9892 | powershell.exe | TTP: T1059.001 (score=60, 25%)"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_inject_not_triggered_when_no_remaining(self):
        """No remaining subtasks → no inject point."""
        result = "Port 4444 open on host"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 2)
        assert decision.action == "continue"


# ── Continue (default) ──────────────────────────────────────────────────────


class TestContinue:
    """No matching pattern → continue normally."""

    def test_normal_result_continues(self):
        result = '{"cpu": 45.2, "memory": 60.0, "processes": 234}'
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_empty_result_continues(self):
        decision = _evaluate_branch_rules("", _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"

    def test_none_result_continues(self):
        decision = _evaluate_branch_rules(None, _SUBTASKS_3_NO_FINAL, 0)  # type: ignore[arg-type]
        assert decision.action == "continue"

    def test_empty_subtasks_continues(self):
        decision = _evaluate_branch_rules("some result", [], 0)
        assert decision.action == "continue"

    def test_apology_text_continues(self):
        result = "אין לי מידע על כך, לא הצלחתי למצוא נתונים"
        decision = _evaluate_branch_rules(result, _SUBTASKS_3_NO_FINAL, 0)
        assert decision.action == "continue"


# ── Helper: _has_no_anomalies ───────────────────────────────────────────────


class TestHasNoAnomalies:
    """Direct tests for the no-anomalies detector."""

    def test_empty_anomalies_list(self):
        # skip rules disabled — _has_no_anomalies always False
        assert _has_no_anomalies('{"anomalies": []}') is False

    def test_anomaly_count_zero(self):
        assert _has_no_anomalies('{"anomalies_count": 0}') is False

    def test_explicit_no_anomalies_found(self):
        assert _has_no_anomalies("No anomalies found in the system") is False

    def test_explicit_no_anomalies_detected(self):
        assert _has_no_anomalies("no anomalies detected") is False

    def test_anomalies_present(self):
        assert _has_no_anomalies('{"anomalies": ["high_cpu"]}') is False

    def test_no_anomaly_field(self):
        assert _has_no_anomalies('{"cpu": 45.2}') is False

    # ── Real-world format tests ──

    def test_hebrew_no_suspicious_connections(self):
        assert _has_no_anomalies("חיבורים חשודים: ✅ אין") is False

    def test_hebrew_no_anomalies_found(self):
        assert _has_no_anomalies("לא נמצאו חריגות במערכת") is False

    def test_hebrew_no_threats_found(self):
        assert _has_no_anomalies("לא נמצאו איומים") is False

    def test_hebrew_suspicious_present(self):
        assert _has_no_anomalies("חיבורים חשודים: ⚠️ נמצאו 2") is False


# ── BranchDecision dataclass ────────────────────────────────────────────────


class TestBranchDecision:
    """Verify default values."""

    def test_default_is_continue(self):
        d = BranchDecision()
        assert d.action == "continue"
        assert d.inject_description == ""
        assert d.reason == ""

    def test_inject_decision_fields(self):
        d = BranchDecision(action="inject", inject_description="Scan memory", reason="C2 port")
        assert d.action == "inject"
        assert d.inject_description == "Scan memory"
        assert d.reason == "C2 port"
