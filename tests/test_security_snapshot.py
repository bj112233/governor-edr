# tests/test_security_snapshot.py
"""Snapshot tests for _skills_engine/security build_cmd_list + _apply_arg_template.

Locks the "run" command-resolution and cmd_list construction behavior across
SRP refactors (Sprint 4 Ratchet 2).
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from services._skills_engine.security import (
    _apply_arg_template,
    _resolve_run_command,
    build_cmd_list,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_VENV = str(_PROJECT_ROOT / ".venv" / "Scripts" / "python.exe")


def _skill(
    name="demo",
    command_override=None,
    arg_template=None,
    content="```bash\npython {baseDir}/scripts/demo.py run\n```",
):
    return SimpleNamespace(
        name=name,
        command_override=command_override,
        arg_template=arg_template,
        content=content,
    )


# ── _resolve_run_command ──
def test_resolve_run_no_override_uses_skill_name():
    skill = _skill(command_override=None)
    cmd, args = _resolve_run_command(skill, "run", "--foo bar")
    assert cmd == "demo"
    assert args == "--foo bar"


def test_resolve_run_override_contains_run_stays_run():
    skill = _skill(command_override=["run", "quote"])
    cmd, args = _resolve_run_command(skill, "run", "--foo")
    assert cmd == "run"
    assert args == "--foo"


def test_resolve_run_override_first_token_matched_consumes_args():
    skill = _skill(command_override=["forward", "reverse"])
    cmd, args = _resolve_run_command(skill, "run", "forward --address TLV")
    assert cmd == "forward"
    assert args == "--address TLV"


def test_resolve_run_override_first_token_unmatched_defaults_first():
    skill = _skill(command_override=["forward", "reverse"])
    cmd, args = _resolve_run_command(skill, "run", "bogus --x")
    assert cmd == "forward"
    assert args == "bogus --x"


def test_resolve_run_override_no_args_defaults_first():
    skill = _skill(command_override=["forward", "reverse"])
    cmd, args = _resolve_run_command(skill, "run", "")
    assert cmd == "forward"
    assert args == ""


def test_resolve_non_run_passes_through():
    skill = _skill(command_override=["forward"])
    cmd, args = _resolve_run_command(skill, "quote", "--symbol AAPL")
    assert cmd == "quote"
    assert args == "--symbol AAPL"


# ── build_cmd_list: script path (no arg_template) ──
@pytest.mark.asyncio
async def test_build_cmd_list_script_with_args_dict():
    skill = _skill(command_override=["forward"])
    out = await build_cmd_list(skill, "forward", "", {"address": "TLV"}, _PROJECT_ROOT)
    assert out[0].endswith("python.exe")
    assert out[1] == "scripts/demo.py"
    assert out[2] == "forward"
    assert "--address" in out and "TLV" in out


@pytest.mark.asyncio
async def test_build_cmd_list_script_with_args_str():
    skill = _skill(command_override=["forward"])
    out = await build_cmd_list(skill, "forward", "--address TLV", None, _PROJECT_ROOT)
    assert out[2] == "forward"
    assert "--address" in out and "TLV" in out


@pytest.mark.asyncio
async def test_build_cmd_list_unknown_command_no_script():
    skill = _skill(command_override=["bogus"], content="no bash block")
    out = await build_cmd_list(skill, "bogus", "", None, _PROJECT_ROOT)
    assert out[0].startswith("❌ SECURITY ERROR")


@pytest.mark.asyncio
async def test_build_cmd_list_run_maps_to_first_override():
    skill = _skill(command_override=["forward", "reverse"])
    out = await build_cmd_list(skill, "run", "", None, _PROJECT_ROOT)
    assert out[2] == "forward"


# ── build_cmd_list: known bin (-c/-m/-x guard) ──
@pytest.mark.asyncio
async def test_build_cmd_list_known_bin_blocks_dash_c():
    skill = _skill(command_override=["python"])
    out = await build_cmd_list(skill, "python", "-c print(1)", None, _PROJECT_ROOT)
    assert out[0].startswith("❌ SECURITY ERROR")


@pytest.mark.asyncio
async def test_build_cmd_list_known_bin_passes_flag_args():
    # sanitize_args drops bare tokens; only --flag style args survive.
    skill = _skill(command_override=["python"])
    out = await build_cmd_list(skill, "python", "--foo bar", None, _PROJECT_ROOT)
    assert out[0].endswith("python.exe")
    assert "--foo" in out and "bar" in out


# ── _apply_arg_template ──
@pytest.mark.asyncio
async def test_apply_arg_template_renders_command_and_args():
    skill = _skill(
        command_override=["forward"],
        arg_template="scripts/demo.py {command} --addr {args}",
    )
    out = await _apply_arg_template(skill, "forward", "TLV", None, _VENV)
    assert out[0] == _VENV
    assert "scripts/demo.py" in out
    assert "forward" in out
    assert "TLV" in out


@pytest.mark.asyncio
async def test_apply_arg_template_run_maps_to_first_override():
    skill = _skill(
        command_override=["forward", "reverse"],
        arg_template="scripts/demo.py {command}",
    )
    out = await _apply_arg_template(skill, "run", "", None, _VENV)
    assert "forward" in out


@pytest.mark.asyncio
async def test_apply_arg_template_flags_converted_to_json_when_template_expects_json():
    skill = _skill(
        command_override=["run"],
        arg_template="scripts/demo.py run --data '{args}'",
    )
    out = await _apply_arg_template(skill, "run", "--address TLV", None, _VENV)
    # JSON conversion: {"address":"TLV"} should appear as the --data argument
    joined = " ".join(out)
    assert '{"address":"TLV"}' in joined


@pytest.mark.asyncio
async def test_apply_arg_template_dict_serialized_when_template_expects_json():
    skill = _skill(
        command_override=["run"],
        arg_template="scripts/demo.py run --data '{args}'",
    )
    out = await _apply_arg_template(skill, "run", "", {"address": "TLV"}, _VENV)
    joined = " ".join(out)
    assert '{"address":"TLV"}' in joined
