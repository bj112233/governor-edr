# services/_skills_engine/__init__.py
"""Skills engine — facade + backward compat re-exports."""

from .cli_builder import apply_template, dict_to_cli_flags, parse_args, safe_split_args, sanitize_args
from .executor import run as execute_skill
from .models import Skill
from .parser import extract_commands, get_script_path
from .security import build_cmd_list, check_binary, check_required

# Backward compat: old code imported Skill from _skill.py
__all__ = [
    "Skill",
    "extract_commands",
    "get_script_path",
    "parse_args",
    "apply_template",
    "dict_to_cli_flags",
    "sanitize_args",
    "safe_split_args",
    "build_cmd_list",
    "check_binary",
    "check_required",
    "execute_skill",
]
