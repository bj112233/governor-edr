r"""Fail-Fast input validation tests — empty `input` rejected before skill execution.

Regression: skill_report-maker was called with `input: '{}'` (empty JSON), producing
a hollow report with no real data. The validation gate in _execute_skill_tool now
rejects empty input BEFORE the subprocess fork, returning a semantic error to the LLM.

Run:  .venv\Scripts\python.exe -m pytest tests/test_skill_input_validation.py -v
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent_tools import (
    _is_empty_input,
    _validate_skill_input,
)

# ── _is_empty_input unit tests ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, True),
        ("", True),
        ("   ", True),
        ("{}", True),
        ("null", True),
        ("[]", True),
        ([], True),
        ({}, True),
        ("real data", False),
        ('{"key": "value"}', False),
        ([1, 2, 3], False),
        ({"host": "localhost"}, False),
        (0, False),  # 0 is not "empty" in the semantic sense
    ],
)
def test_is_empty_input(value, expected):
    assert _is_empty_input(value) == expected


# ── _validate_skill_input integration tests ─────────────────────────────────


def test_validate_rejects_empty_input_for_report_maker():
    """report-maker security_audit with empty input → fail-fast error."""
    err = _validate_skill_input(
        "skill_report-maker",
        "security_audit",
        {"input": "{}", "format": "markdown", "output": "analysis.md"},
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "non-empty" in err
    assert "report-maker" in err
    print("PASS: empty input rejected for report-maker")


def test_validate_accepts_nonempty_input_for_report_maker():
    """report-maker security_audit with real data → no error (None)."""
    err = _validate_skill_input(
        "skill_report-maker",
        "security_audit",
        {"input": '{"host": "localhost", "firewall": {"active_blocks": 3}}', "format": "markdown"},
    )
    assert err is None
    print("PASS: non-empty input accepted for report-maker")


def test_validate_skips_skill_without_input_schema():
    """Skills whose command schema has no `input` property → no validation."""
    # intel-skill's `israeli` command has `target`, not `input`
    err = _validate_skill_input(
        "skill_intel-skill",
        "israeli",
        {"target": "8.8.8.8"},
    )
    assert err is None
    print("PASS: skill without `input` schema skipped")


def test_validate_skips_unknown_skill():
    """Unknown skill → None (let skill_tool handle the error)."""
    err = _validate_skill_input("skill_nonexistent", "default", {"input": "{}"})
    assert err is None
    print("PASS: unknown skill skipped")


def test_validate_handles_missing_input_key():
    """`input` key absent entirely → treated as empty → rejected."""
    err = _validate_skill_input(
        "skill_report-maker",
        "security_audit",
        {"format": "markdown"},  # no `input` key
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    print("PASS: missing input key rejected")


# ── CLI-flag string args (temp file bridge injection) ───────────────────────


def test_validate_accepts_cli_flag_string_input():
    """Regression: temp file bridge injects `--input <path>` as a CLI-flag
    string for skills with unquoted {args} arg_template (e.g. report-maker).
    The validator must parse CLI flags, not just JSON, or it falsely reports
    required fields as empty and blocks the real data injection."""
    err = _validate_skill_input(
        "skill_report-maker",
        "briefing",
        "--input C:\\WINDOWS\\TEMP\\sentinel_report_uf72fgm3.json",
    )
    assert err is None, f"CLI-flag --input should pass validation, got: {err}"
    print("PASS: CLI-flag --input string accepted for report-maker")


def test_validate_rejects_cli_flag_string_missing_input():
    """CLI-flag string WITHOUT --input → still rejected (required field missing)."""
    err = _validate_skill_input(
        "skill_report-maker",
        "briefing",
        "--format markdown --output report.md",
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "input" in err
    print("PASS: CLI-flag string missing --input rejected")


def test_validate_logs_error_on_unparseable_format(caplog):
    """Regression: if args are neither JSON dict nor CLI flags (e.g. XML/YAML
    or a bare JSON scalar), the validator must log an ERROR (not silently
    return empty dict) so a future 4th arg format is caught immediately.
    It still returns a VALIDATION ERROR for the missing required field."""
    import logging

    with caplog.at_level(logging.ERROR, logger="services.agent_tools"):
        err = _validate_skill_input(
            "skill_report-maker",
            "briefing",
            "<xml><data>not parseable</data></xml>",
        )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "input" in err
    # Must log an ERROR-level diagnostic about unparseable args
    error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert any("unparseable args" in r.message for r in error_records), (
        f"Expected ERROR log about unparseable args, got: {[r.message for r in error_records]}"
    )
    print("PASS: unparseable format logged as ERROR + validation error returned")


# ── End-to-end: _execute_skill_tool returns validation error ─────────────────


def test_execute_skill_tool_returns_validation_error_on_empty_input():
    """Full path: _execute_skill_tool with empty input → returns error, no subprocess."""
    from services.agent_tools import _execute_skill_tool

    result = asyncio.run(
        _execute_skill_tool(
            "skill_report-maker",
            {"command": "security_audit", "args": {"input": "{}", "format": "markdown"}},
        )
    )
    assert "VALIDATION ERROR" in result
    assert "non-empty" in result
    # The skill should NOT have been executed (no "✅" success marker)
    assert "✅" not in result
    print("PASS: _execute_skill_tool returns validation error on empty input")


# ── file-analyst path validation (generalized Fail-Fast) ────────────────────


def test_validate_rejects_empty_path_for_file_analyst():
    """file-analyst summarize with empty path → fail-fast error."""
    err = _validate_skill_input(
        "skill_file-analyst",
        "summarize",
        {"path": "", "output": "out.md"},
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "path" in err
    print("PASS: empty path rejected for file-analyst")


def test_validate_rejects_missing_path_for_file_analyst():
    """file-analyst convert with no path key → fail-fast error."""
    err = _validate_skill_input(
        "skill_file-analyst",
        "convert",
        {"output": "out.md"},  # no path key
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "path" in err
    print("PASS: missing path rejected for file-analyst")


def test_validate_accepts_nonempty_path_for_file_analyst():
    """file-analyst summarize with real path → no error (None)."""
    err = _validate_skill_input(
        "skill_file-analyst",
        "summarize",
        {"path": "report.pdf"},
    )
    assert err is None
    print("PASS: non-empty path accepted for file-analyst")


def test_validate_rejects_empty_dir_for_batch():
    """file-analyst batch with empty dir → fail-fast error."""
    err = _validate_skill_input(
        "skill_file-analyst",
        "batch",
        {"dir": ""},
    )
    assert err is not None
    assert "VALIDATION ERROR" in err
    assert "dir" in err
    print("PASS: empty dir rejected for batch command")


def test_validate_accepts_nonempty_dir_for_batch():
    """file-analyst batch with real dir → no error (None)."""
    err = _validate_skill_input(
        "skill_file-analyst",
        "batch",
        {"dir": "./reports"},
    )
    assert err is None
    print("PASS: non-empty dir accepted for batch command")


def test_execute_skill_tool_returns_validation_error_on_empty_path():
    """Full path: _execute_skill_tool with empty path → returns error, no subprocess."""
    from services.agent_tools import _execute_skill_tool

    result = asyncio.run(
        _execute_skill_tool(
            "skill_file-analyst",
            {"command": "summarize", "args": {"path": ""}},
        )
    )
    assert "VALIDATION ERROR" in result
    assert "path" in result
    assert "✅" not in result
    print("PASS: _execute_skill_tool returns validation error on empty path")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
