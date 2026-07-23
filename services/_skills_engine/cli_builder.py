# services/_skills_engine/cli_builder.py
"""JSON → CLI tokenization. The Smart Builder."""

import json
import logging
import shlex
from typing import TYPE_CHECKING, Optional

from ._cli_utils import _cli_flags_to_json_dict

if TYPE_CHECKING:
    from .models import Skill

logger = logging.getLogger(__name__)


def parse_args(skill, raw_args) -> tuple[str, dict | None]:
    """Normalize LLM args into (remaining_string, parsed_dict)."""
    _args_dict = None
    args = raw_args
    if isinstance(args, dict):
        _args_dict = args
        args = ""
    elif isinstance(args, str):
        args = args.strip()
        if (args.startswith('"') and args.endswith('"')) or (args.startswith("'") and args.endswith("'")):
            args = args[1:-1].strip()
        if args.startswith("{"):
            try:
                parsed = json.loads(args)
                if isinstance(parsed, dict):
                    _args_dict = parsed
                    args = ""
            except (json.JSONDecodeError, ValueError):
                pass
        elif args.startswith("["):
            try:
                parsed = json.loads(args)
                if isinstance(parsed, list):
                    _args_dict = {"args": parsed}
                    args = ""
            except (json.JSONDecodeError, ValueError):
                pass
        elif args and not args.startswith("-"):
            # Only treat as path if it doesn't contain CLI flags (--)
            if " --" in args or args.startswith("--"):
                _args_dict = _cli_flags_to_json_dict(args)
            else:
                _args_dict = {"path": args}
            args = ""
        elif args.startswith("--"):
            _args_dict = _cli_flags_to_json_dict(args)
            args = ""
    else:
        args = str(args or "")
    return args, _args_dict


def apply_template(skill, command: str, args: str) -> str:
    """Apply command_to_args_template if present. Returns updated args."""
    if not skill.command_to_args_template:
        return args
    derived = skill.command_to_args_template.replace("{command}", command)
    if not derived:
        return args
    if not args or args.strip() in ("", "{}"):
        logger.info("[Skills] %s/%s: auto-derived args from template", skill.name, command)
        return derived
    try:
        user_args = json.loads(args)
        tpl_args = json.loads(derived)
        if isinstance(user_args, dict) and isinstance(tpl_args, dict):
            merged = False
            for k, v in tpl_args.items():
                if k not in user_args:
                    user_args[k] = v
                    merged = True
            if merged:
                args = json.dumps(user_args, ensure_ascii=False, separators=(",", ":"))
                logger.info("[Skills] %s/%s: merged template defaults", skill.name, command)
    except (json.JSONDecodeError, AttributeError):
        pass
    return args


def sanitize_args(raw: str) -> list[str]:
    """Parse args via shlex, drop hallucinated script names."""
    try:
        parsed = shlex.split(raw, posix=False)
    except (ValueError, UnicodeEncodeError):
        parsed = safe_split_args(raw)
    # Drop leading .py if LLM hallucinated script name
    if parsed and parsed[0].endswith(".py"):
        parsed.pop(0)
    return parsed


def dict_to_cli_flags(d: dict) -> list[str]:
    """Convert JSON dict to --key value CLI flags."""
    out: list[str] = []
    for k, v in d.items():
        if isinstance(v, bool):
            if v:
                out.append(f"--{k}")
        elif isinstance(v, (list, dict)):
            out.extend([f"--{k}", json.dumps(v, ensure_ascii=False)])
        else:
            out.extend([f"--{k}", str(v)])
    return out


def safe_split_args(args: str) -> list[str]:
    """Fallback argument splitter for Hebrew/Unicode on Windows."""
    tokens = []
    current: list[str] = []
    in_quotes = False
    quote_char = None
    for char in args:
        if char in ('"', "'") and (not in_quotes or char == quote_char):
            in_quotes = not in_quotes
            quote_char = char if in_quotes else None
        elif char == " " and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if current:
        tokens.append("".join(current))
    return tokens
