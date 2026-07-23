# tests/test_parser_snapshot.py
"""Snapshot tests for _skills_engine/parser.extract_commands.

Locks the command-extraction behavior across SRP refactors (Sprint 4 Ratchet 1).
Covers: command_override path, bash-block parsing, quick-start section,
backtick scanning, and the subcommand filter.
"""

from types import SimpleNamespace

import pytest

from services._skills_engine.parser import extract_commands, get_script_path


def _skill(content: str, name: str = "demo", command_override=None) -> SimpleNamespace:
    return SimpleNamespace(name=name, content=content, command_override=command_override)


# ── 1. command_override short-circuits all content parsing ──
def test_command_override_wins():
    skill = _skill(content="```bash\npython foo.py run\n```", command_override=["quote", "forward"])
    assert extract_commands(skill) == ["quote", "forward"]


def test_command_override_dedup_and_cap():
    skill = _skill(
        content="",
        command_override=[
            "a",
            "b",
            "a",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "j",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "q",
            "r",
            "s",
            "t",
            "u",
        ],
    )
    out = extract_commands(skill)
    # dedup preserves order, capped at 20
    assert out == ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t"]
    assert len(out) == 20


# ── 2. bash-block python invocation extraction ──
def test_bash_block_python_subcommand():
    content = "```bash\npython {baseDir}/demo.py forward --address TLV\n```"
    skill = _skill(content=content)
    out = extract_commands(skill)
    assert "forward" in out


def test_bash_block_blocks_python_bin_name():
    content = "```bash\npython demo.py python\n```"
    skill = _skill(content=content)
    out = extract_commands(skill)
    assert "python" not in out


def test_bash_block_allowed_direct_binary():
    content = "```bash\nnmap -sV 10.0.0.1\n```"
    skill = _skill(content=content)
    out = extract_commands(skill)
    assert "nmap" in out


# ── 3. Quick-start section ──
# NOTE: current behavior also emits backtick-wrapped tokens from the
# `parts = line.lstrip("-$ ").split()` branch. Locked as source of truth.
def test_quick_start_backtick_command():
    content = "Quick start\n- `forward` geocode an address\n- `--address` the target address\n"
    skill = _skill(content=content)
    out = extract_commands(skill)
    assert "forward" in out
    assert out == ["forward", "`forward`", "`--address`"]


# ── 4. Backtick scanning across body ──
# NOTE: `--symbol` is extracted by the backtick scan but then dropped by
# _is_real_subcommand (startswith "--"). Only bare subcommands survive.
def test_backtick_body_scan():
    content = "Use `quote` to fetch prices. Pass `--symbol` for the ticker."
    skill = _skill(content=content)
    out = extract_commands(skill)
    assert out == ["quote"]


# ── 5. Subcommand filter: drops flags and ALL_CAPS env-like tokens ──
def test_filter_drops_flags_and_uppercase():
    content = "Run `--verbose` or `DEBUG_MODE` then `run`."
    skill = _skill(content=content, name="demo")
    out = extract_commands(skill)
    # flags dropped; long uppercase dropped; `run` survives (not empty → no fallback)
    assert out == ["run"]


def test_empty_falls_back_to_skill_name():
    skill = _skill(content="nothing useful here", name="mytool")
    assert extract_commands(skill) == ["mytool"]


# ── 6. get_script_path ──
def test_get_script_path_from_bash_block():
    content = "```bash\npython {baseDir}/scripts/demo.py forward\n```"
    skill = _skill(content=content)
    assert get_script_path(skill) == "scripts/demo.py"


def test_get_script_path_none_when_absent():
    skill = _skill(content="no bash block here")
    assert get_script_path(skill) is None
