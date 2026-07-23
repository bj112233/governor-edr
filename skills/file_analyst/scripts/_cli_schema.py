"""
CLI schema adapter — translate MCP JSON argv into legacy CLI args.

Supports two invocation formats (Legacy + MCP) with zero Engine changes
and full backward compatibility.
"""

import json
import sys


def adapt_mcp_schema() -> None:
    """Convert an MCP JSON payload (argv[1]) into CLI-style argv.

    Detects the new MCP format (no "command" key, kebab-case keys) and
    rewrites ``sys.argv`` so the regular argparse path can parse it.
    Legacy JSON and non-JSON argv are left untouched.
    """
    if len(sys.argv) <= 1 or not sys.argv[1].startswith("{"):
        return
    try:
        payload = json.loads(sys.argv[1])
    except (json.JSONDecodeError, ValueError):
        return  # not valid JSON — continue with regular argparse

    # Detect MCP format: no "command", kebab-case keys present
    if "command" in payload or not any("-" in k for k in payload.keys()):
        return

    new_argv = ["file_analyst.py"]  # argv[0]

    # action becomes the positional argument
    if "action" in payload:
        new_argv.append(payload.pop("action"))

    # remaining params become flags
    for k, v in payload.items():
        flag_name = f"--{k}"  # already kebab-case
        if isinstance(v, bool):
            if v:
                new_argv.append(flag_name)
        else:
            new_argv.extend([flag_name, str(v)])

    sys.argv = new_argv
