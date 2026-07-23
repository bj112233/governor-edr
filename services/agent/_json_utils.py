# services/agent/_json_utils.py
"""JSON safety utilities: brace balancing, trailing comma cleanup, and
emergency context-window trimming."""

import re
from typing import Optional

__all__ = [
    "_TRAILING_COMMA_RE",
    "_strip_trailing_commas",
    "_brace_depth",
    "_emergency_trim_for_overflow",
    "_get_last_tool_output",
]

_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")


def _strip_trailing_commas(s: str) -> str:
    """Remove trailing commas before } or ] that local 4B models frequently emit."""
    return _TRAILING_COMMA_RE.sub(r"\1", s)


def _brace_depth(s: str) -> tuple[int, int]:
    """Return (brace_depth, bracket_depth) respecting string/escape boundaries."""
    brace_depth = 0
    bracket_depth = 0
    in_string = False
    string_char = None
    escape = False
    for ch in s:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if in_string:
            if ch == string_char:
                in_string = False
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
    return brace_depth, bracket_depth


def _find_last_real_user(messages: list[dict]) -> int:
    """Find the index of the last non-tool-output user message. Returns -1 if none."""
    for i in range(len(messages) - 1, 0, -1):
        m = messages[i]
        if m.get("role") != "user":
            continue
        c = (m.get("content", "") or "").lstrip()
        if not c.startswith("<tool_output>"):
            return i
    return -1


def _truncate_tool_outputs(tail: list[dict]) -> None:
    """Tiered truncation: old tool outputs aggressively trimmed, latest preserved."""
    tool_indices = [i for i, m in enumerate(tail) if (m.get("content", "") or "").lstrip().startswith("<tool_output>")]
    if not tool_indices:
        return

    # Older tool outputs: keep a tiny tail for exit codes/status
    for idx in tool_indices[:-1]:
        c = tail[idx].get("content", "") or ""
        if len(c) > 300:
            tail[idx]["content"] = c[:100] + "\n...[OLD output truncated — see recent output BELOW]...\n" + c[-50:]

    # Most recent tool output: preserve heavily (head for context, tail for results)
    last_idx = tool_indices[-1]
    c = tail[last_idx].get("content", "") or ""
    if len(c) > 2000:
        tail[last_idx]["content"] = c[:1200] + "\n...[trimmed for overflow]...\n" + c[-500:]


def _emergency_trim_for_overflow(messages: list[dict]) -> list[dict]:
    """Hard trim in response to a server-confirmed context_length_exceeded (400)."""
    if len(messages) <= 2:
        if len(messages) == 2:
            c = messages[1].get("content", "") or ""
            if len(c) > 4000:
                messages[1]["content"] = c[:4000] + "\n...[truncated]"
        return messages

    system = messages[0]
    last_real_user_idx = _find_last_real_user(messages)

    if last_real_user_idx <= 0:
        # Preserve mid-conversation system messages (directives, emergency reserves)
        mid_system = [m for m in messages[1:] if m.get("role") == "system"]
        return [system] + mid_system + [messages[-1]]

    # Preserve mid-conversation system messages between head system prompt and current user msg
    mid_system = [m for m in messages[1:last_real_user_idx] if m.get("role") == "system"]
    tail = messages[last_real_user_idx:]

    _truncate_tool_outputs(tail)

    return [system] + mid_system + tail


def _get_last_tool_output(messages: list[dict]) -> str | None:
    """Extract content from the most recent <tool_output> block in message history."""
    for msg in reversed(messages):
        content = msg.get("content", "")
        if isinstance(content, str) and "<tool_output>" in content:
            match = re.search(r"<tool_output>\s*(.*?)\s*</tool_output>", content, re.DOTALL)
            if match:
                return match.group(1).strip()
    return None
