# services/_skills_engine/_cli_utils.py
"""CLI argument parsing utilities for the skills engine."""

import shlex
from typing import Any

__all__ = ["_cli_flags_to_json_dict", "_coerce_value"]


def _cli_flags_to_json_dict(args: str) -> dict[str, Any]:
    """Convert CLI-style `--flag value --bool` string into a JSON-compatible dict.

    Supports: --flag value, --flag=value, and bare --bool (? true).
    Handles paths with spaces by consuming tokens until the next --flag.
    """
    result: dict[str, Any] = {}
    tokens = shlex.split(args.strip(), posix=False) if args.strip() else []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("--"):
            key = tok.lstrip("-").replace("-", "_")
            if "=" in key:
                key, _, val = key.partition("=")
                result[key] = _coerce_value(val)
                i += 1
                continue
            # Consume all non-flag tokens as a single space-joined value.
            # This handles paths with spaces (e.g. "C:\\dir\\file name.pdf")
            # that the LLM didn't quote properly.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                value_parts: list[str] = []
                j = i + 1
                while j < len(tokens) and not tokens[j].startswith("-"):
                    value_parts.append(tokens[j])
                    j += 1
                result[key] = _coerce_value(" ".join(value_parts))
                i = j
            else:
                result[key] = True
                i += 1
        else:
            i += 1
    return result


def _coerce_value(val: str) -> Any:
    """Coerce a CLI string value into int, float, bool, or str."""
    # Strip surrounding quotes added by shlex.split(posix=False)
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        val = val[1:-1]
    if val.lower() in ("true", "yes", "on"):
        return True
    if val.lower() in ("false", "no", "off"):
        return False
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val
