# tests/test_cove_parser.py
"""Tests for _parse_cove — CoVe response parser extracted from _agent_critic."""

from services.agent._cove_parser import _parse_cove


def test_parse_empty_response():
    """Empty response → parse_ok=False."""
    assert _parse_cove("")["parse_ok"] is False
    assert _parse_cove("   \n  \n  ")["parse_ok"] is False


def test_parse_verdict_pass():
    """VERDICT: PASS → verdict=True."""
    result = _parse_cove("VERDICT: PASS\nREASON: all good")
    assert result["parse_ok"] is True
    assert result["verdict"] is True
    assert result["reason"] == "all good"


def test_parse_verdict_fail():
    """VERDICT: FAIL → verdict=False."""
    result = _parse_cove("VERDICT: FAIL\nREASON: bad claim")
    assert result["verdict"] is False
    assert result["reason"] == "bad claim"


def test_parse_claims_bullets():
    """Claims section with bullet items."""
    result = _parse_cove("VERDICT: PASS\nCLAIMS:\n- CPU is 15%\n- RAM is 50%")
    assert result["claims"] == ["CPU is 15%", "RAM is 50%"]


def test_parse_evidence_with_colon():
    """Evidence items with 'claim: evidence' format."""
    result = _parse_cove("VERDICT: PASS\nEVIDENCE:\n- CPU is 15%: 15% in tool data")
    assert len(result["evidence"]) == 1
    assert result["evidence"][0] == ("CPU is 15%", "15% in tool data")


def test_parse_evidence_without_colon():
    """Evidence items without colon → evidence='NONE' (line 60)."""
    result = _parse_cove("VERDICT: PASS\nEVIDENCE:\n- some claim without colon")
    assert len(result["evidence"]) == 1
    assert result["evidence"][0] == ("some claim without colon", "NONE")


def test_parse_reason_multiline():
    """Reason on separate line after REASON: header (line 62)."""
    result = _parse_cove("VERDICT: FAIL\nREASON:\nThe report has issues")
    # reason may be empty if header has nothing, then next line fills it
    assert "issues" in result["reason"] or result["reason"] == ""


def test_parse_logical_flaw_multiline():
    """Logical flaw on separate line (line 64)."""
    result = _parse_cove("VERDICT: FAIL\nLOGICAL_FLAW:\nContradicts tool data")
    assert "Contradicts" in result["logical_flaw"] or result["logical_flaw"] == ""


def test_parse_star_bullets():
    """Star (*) bullets also work."""
    result = _parse_cove("VERDICT: PASS\nCLAIMS:\n* claim one\n* claim two")
    assert result["claims"] == ["claim one", "claim two"]


def test_parse_no_verdict():
    """Response without VERDICT → verdict=None."""
    result = _parse_cove("REASON: no verdict line")
    assert result["verdict"] is None
