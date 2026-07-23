# services/action_tools/security.py
"""Security policy — constants + validators. Pure data, no side effects."""

import ipaddress
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parent.parent.parent

_WRITE_ALLOWED_ROOTS = [
    _PROJECT_ROOT / "logs",
    _PROJECT_ROOT / "state",
    _PROJECT_ROOT / "memory",
    _PROJECT_ROOT / "temp",
]

_WRITE_BLOCKED_EXTENSIONS = {
    ".py",
    ".env",
    ".db",
    ".bat",
    ".exe",
    ".dll",
    ".pyd",
    ".ps1",
    ".cmd",
    ".vbs",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
}

_PROTECTED_SERVICES = {
    "windefend",
    "mpssvc",
    "eventlog",
    "lsass",
    "wininit",
    "csrss",
    "smss",
    "services",
    "sppsvc",
}

_VALID_SVC_ACTIONS = {"start", "stop", "restart"}

_PS_ALLOWED_VERBS = {
    "get",
    "test",
    "select",
    "where",
    "measure",
    "write",
    "out",
    "format",
    "sort",
    "group",
    "compare",
    "split",
    "join",
    "convert",
}


def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def is_powershell_safe(command: str) -> bool:
    cmd = command.strip()
    if not cmd:
        return False
    # Block all chaining / obfuscation operators (|, ;, `, &, {}, (), [])
    if re.search(r"[|;`&{}()\[\]]", cmd):
        return False
    first_token = cmd.split()[0].lower()
    for verb in _PS_ALLOWED_VERBS:
        if first_token.startswith(verb + "-"):
            return True
    return False


def is_path_write_allowed(target: Path) -> bool:
    target = target.resolve()
    allowed = any(target == root.resolve() or target.is_relative_to(root.resolve()) for root in _WRITE_ALLOWED_ROOTS)
    return allowed


def is_extension_blocked(target: Path) -> bool:
    return target.suffix.lower() in _WRITE_BLOCKED_EXTENSIONS


def is_service_protected(name: str) -> bool:
    return name.lower() in _PROTECTED_SERVICES


def is_service_action_valid(action: str) -> bool:
    return action.lower().strip() in _VALID_SVC_ACTIONS


def is_service_name_valid(name: str) -> bool:
    return bool(re.match(r"^[A-Za-z0-9_.\-$ ]+$", name))
