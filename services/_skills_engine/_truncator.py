# services/_skills_engine/_truncator.py
"""JSON-safe string truncation utility.

Extracted from executor.py (SRP): pure string manipulation, zero
dependency on subprocess/skills/IO. Isolates the LIFO state-machine
complexity so executor.py can focus on process lifecycle.
"""

import json
import logging

logger = logging.getLogger(__name__)


def _handle_structural_char(char: str, i: int, stack: list[str]) -> tuple[list[str] | None, int | None]:
    """Handle a structural JSON character outside of strings.

    Returns (stack_snapshot_for_cut, override_position_for_cut) or (None, None).
    """
    if char in "{[":
        stack.append(char)
        return None, None
    if char in "}]":
        if stack and ((char == "}" and stack[-1] == "{") or (char == "]" and stack[-1] == "[")):
            stack.pop()
        return list(stack), i
    if char == ",":
        return list(stack), i - 1
    return None, None


def _scan_safe_cut_points(trimmed: str) -> dict[int, list[str]]:
    """Single-pass LIFO state machine: find safe cut points in JSON text.

    Returns dict mapping cut position → remaining stack at that point.
    """
    stack: list[str] = []
    in_string = False
    escape = False
    safe_cut_points: dict[int, list[str]] = {}

    for i, char in enumerate(trimmed):
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue

        if not in_string:
            snapshot, pos = _handle_structural_char(char, i, stack)
            if snapshot is not None and pos is not None:
                safe_cut_points[pos] = snapshot

    return safe_cut_points


def _try_close_json(trimmed: str, pos: int, remaining_stack: list[str]) -> str | None:
    """Try to close JSON at cut point. Returns valid JSON string or None."""
    candidate = trimmed[: pos + 1]
    closing_chars = "".join("}" if c == "{" else "]" for c in reversed(remaining_stack))
    candidate += closing_chars
    try:
        json.loads(candidate)
        return candidate
    except json.JSONDecodeError:
        return None


def json_safe_truncate(text: str, max_chars: int) -> str:
    """Truncate JSON text safely using a single-pass LIFO state machine."""
    if len(text) <= max_chars:
        return text

    trimmed = text[:max_chars]
    if not trimmed.lstrip().startswith(("{", "[")):
        return trimmed

    safe_cut_points = _scan_safe_cut_points(trimmed)

    for pos in sorted(safe_cut_points.keys(), reverse=True):
        result = _try_close_json(trimmed, pos, safe_cut_points[pos])
        if result is not None:
            return result

    return trimmed
