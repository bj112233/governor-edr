# services/_skills_engine/parser.py
"""Extract commands and script paths from SKILL.md content."""

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .models import Skill

logger = logging.getLogger(__name__)

_PYTHON_BINS = {"python", "py", "python3", "python.exe", "py.exe"}
_ALLOWED_BINARIES = {
    "curl",
    "wget",
    "nmap",
    "ping",
    "tracert",
    "nslookup",
    "whois",
}


def _is_real_subcommand(c: str) -> bool:
    """Filter predicate: drop flags, and ALL_CAPS env-like tokens (len>4 or has _)."""
    if not c or c.startswith("--") or c.startswith("-"):
        return False
    if c.isupper() and (len(c) > 4 or "_" in c):
        return False
    return True


def _extract_from_bash_blocks(content: str, commands: list[str]) -> None:
    """Parse ```bash blocks for `python x.py <subcommand>` lines."""
    bash_blocks = re.findall(r"```bash\n(.*?)```", content, re.DOTALL)
    for block in bash_blocks:
        for line in block.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.search(r"(?:python|py|python3)\s+\S+\.py\s+([\w-]+)", line)
            if m:
                c = m.group(1)
                if c and c not in commands and c not in _PYTHON_BINS:
                    commands.append(c)
            else:
                cmd_match = re.search(r"^(\w+)\s", line)
                if cmd_match:
                    c = cmd_match.group(1)
                    if c and c not in _PYTHON_BINS and c in _ALLOWED_BINARIES:
                        commands.append(c)
                    elif c and c not in _PYTHON_BINS:
                        logger.warning("[Skills] Blocked non-allowed binary from SKILL.md: %s", c)


def _extract_from_quick_start(content: str, commands: list[str]) -> None:
    """Parse the `Quick start` section for backtick-wrapped commands and flags."""
    quick_match = re.search(r"Quick start\s*\n(.*?)(?:\n#|\Z)", content, re.DOTALL | re.IGNORECASE)
    if not quick_match:
        return
    for line in quick_match.group(1).split("\n"):
        line = line.strip()
        if not line.startswith("-") and not line.startswith("$"):
            continue
        bt = re.search(r"`(\w+)", line)
        if bt:
            c = bt.group(1)
            if c and c not in commands and c not in _PYTHON_BINS and len(c) > 2:
                commands.append(c)
        flag_bt = re.search(r"`(--[\w-]+)", line)
        if flag_bt:
            c = flag_bt.group(1)
            if c and c not in commands:
                commands.append(c)
        parts = line.lstrip("-$ ").split()
        if parts:
            c = parts[0]
            if c and c not in commands and c not in _PYTHON_BINS and not c.startswith("--"):
                commands.append(c)


def _extract_backtick_commands(content: str, commands: list[str]) -> None:
    """Scan the whole body for backtick-wrapped subcommands and --flags."""
    for m in re.finditer(r"`(\w+)(?:\s+--|\s+\n`|`|$)", content):
        c = m.group(1)
        if c and c not in commands and len(c) > 2 and c not in _PYTHON_BINS:
            commands.append(c)
    for m in re.finditer(r"`(--[\w-]+)", content):
        c = m.group(1)
        if c and c not in commands:
            commands.append(c)


def extract_commands(skill) -> list[str]:
    """Extract available commands from skill content."""
    if skill.command_override is not None:
        return list(dict.fromkeys(skill.command_override))[:20]

    commands: list[str] = []
    _extract_from_bash_blocks(skill.content, commands)
    _extract_from_quick_start(skill.content, commands)
    _extract_backtick_commands(skill.content, commands)

    commands = [c for c in commands if _is_real_subcommand(c)]
    if not commands:
        commands = [skill.name]
    return list(dict.fromkeys(commands))[:10]


def get_script_path(skill) -> str | None:
    """Extract script path from bash examples (relative to skill dir)."""
    blocks = re.findall(r"```bash\n(.*?)```", skill.content, re.DOTALL)
    for block in blocks:
        for line in block.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                m = re.search(r"(?:python|py|python3)\s+(\S+\.py)", line)
                if m:
                    return re.sub(r"^\{baseDir\}/", "", m.group(1))
    return None
