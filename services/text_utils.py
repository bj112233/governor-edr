# services/text_utils.py
"""
Shared text-sanitization helpers.

Centralizes patterns previously duplicated in:
  - services.agent.run_agent
  - services.local_mcp_server._clean_ide_instructions
"""

from __future__ import annotations

import re

# IDE / Cascade-style instructions occasionally smuggled into the prompt.
# Stripped before any LLM call so the model never sees them.
_IDE_INSTRUCTION_PATTERNS = (
    r"\*\*.*?HEARTBEAT_OK.*?\*\*",
    r"\(כדי לבטא.*?If nothing needs attention.*?\)",
    r"\(בשימוש.*?Use workspace file.*?exact case.*?\)",
    r"If nothing needs attention, reply HEARTBEAT_OK",
    r"Read HEARTBEAT\.md if it exists",
)

_IDE_INSTRUCTION_RE = [re.compile(p, flags=re.DOTALL | re.IGNORECASE) for p in _IDE_INSTRUCTION_PATTERNS]


def clean_ide_instructions(text: str) -> str:
    """Strip Cascade/IDE-injected directives from user-supplied text.

    Returns the cleaned text (whitespace-trimmed). Safe on empty / None.
    """
    if not text:
        return ""
    out = text
    for rx in _IDE_INSTRUCTION_RE:
        out = rx.sub("", out)
    return out.strip()


__all__ = ["clean_ide_instructions"]
