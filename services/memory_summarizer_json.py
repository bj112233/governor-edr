"""JSON safety utilities for memory summarizer — LLM output parsing.

Extracted from memory_summarizer.py (SRP). Defense-in-depth JSON parse
for LLM output with markdown stripping, array unwrapping, brace repair,
and fallback extraction.
"""

import json
import logging
import re
from typing import Any, Optional

from services.agent._json_utils import _strip_trailing_commas

logger = logging.getLogger(__name__)

_MARKDOWN_TICK_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _strip_markdown_ticks(text: str) -> str:
    """Strip ```json ... ``` wrappers that 4B models inject."""
    m = _MARKDOWN_TICK_RE.search(text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _try_parse(candidate: str) -> object | None:
    """Attempt json.loads with string/brace/comma repair. Returns parsed data or None.

    Handles mid-string truncation (max_tokens exhaustion): closes any unterminated
    string literal first, then strips trailing commas, then closes open
    brackets/braces in correct nesting order via stack-based scanning.
    """
    candidate = _close_open_string(candidate)
    candidate = _strip_trailing_commas(candidate)
    candidate = _close_brackets(candidate)
    try:
        return json.loads(candidate)
    except (json.JSONDecodeError, ValueError):
        return None


def _unwrap_array(clean: str) -> object | None:
    """Unwrap [{...}] array wrapper (4B model anti-pattern)."""
    inner = clean[1:-1].strip().rstrip(",").strip()
    for candidate in (inner, clean):
        data = _try_parse(candidate)
        if data is not None:
            return data
    # Array unwrap failed — try parsing as array and inspect elements
    try:
        arr = json.loads(clean)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(arr, list):
        return arr
    for elem in arr:
        if isinstance(elem, dict):
            return elem
        if isinstance(elem, str):
            elem_stripped = elem.strip()
            if elem_stripped.startswith("{") and elem_stripped.endswith("}"):
                try:
                    return json.loads(elem_stripped)
                except (json.JSONDecodeError, ValueError):
                    pass
    return None


def _extract_first_dict_block(text: str) -> object | None:
    """Fallback: extract first {...} block in raw text."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def _coerce_to_dict(data: object) -> dict | None:
    """Ensure parsed data is a dict; extract first dict from lists."""
    if data is None or isinstance(data, (bool, str, int, float)):
        return None
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
            if isinstance(item, str):
                s = item.strip()
                if s.startswith("{") and s.endswith("}"):
                    try:
                        return json.loads(s)
                    except (json.JSONDecodeError, ValueError):
                        pass
    return None


def _find_repetition_loop(text: str) -> tuple[int, int, int] | None:
    """Scan for a chunk (30-200 chars) repeating 3+ times consecutively.

    Returns (start, chunk_len, repeats) if found, else None.
    The repetition may start at any position — e.g., 10 unique preferences
    followed by the same 10 repeated over and over.
    """
    for chunk_len in range(30, min(201, len(text) // 3)):
        for start in range(0, min(len(text) - chunk_len * 3, 500)):
            chunk = text[start : start + chunk_len]
            # Skip chunks that are just whitespace or too uniform
            if chunk.strip().count(",") < 2:
                continue
            # Check if this chunk repeats 3+ times consecutively from `start`
            pos = start + chunk_len
            repeats = 1
            while text[pos : pos + chunk_len] == chunk:
                repeats += 1
                pos += chunk_len
            if repeats >= 3:
                return (start, chunk_len, repeats)
    return None


def _close_open_string(text: str) -> str:
    """Append a closing quote if the text has an unclosed JSON string."""
    in_string = False
    escape = False
    for ch in text:
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
    if in_string:
        return text + '"'
    return text


def _apply_char_to_bracket_state(
    ch: str,
    state: dict[str, Any],
) -> None:
    """Update bracket-scan state for a single character (mutates `state`).

    State keys: in_string (bool), escape (bool), close_stack (list[str]).
    Handles escape sequences, string boundaries, and bracket nesting.
    """
    if state["escape"]:
        state["escape"] = False
        return
    if ch == "\\":
        state["escape"] = True
        return
    if state["in_string"]:
        if ch == '"':
            state["in_string"] = False
        return
    if ch == '"':
        state["in_string"] = True
    elif ch in "{[":
        state["close_stack"].append("}" if ch == "{" else "]")
    elif ch in "}]":
        stack = state["close_stack"]
        if stack and stack[-1] == ch:
            stack.pop()


def _scan_bracket_stack(text: str) -> list[str]:
    """Walk text tracking string/escape state; return unclosed bracket stack.

    The stack is ordered by nesting depth; reversed it yields the correct
    closing sequence (]}] not ]]}).
    """
    state: dict[str, Any] = {"in_string": False, "escape": False, "close_stack": []}
    for ch in text:
        _apply_char_to_bracket_state(ch, state)
    return state["close_stack"]


def _close_brackets(text: str) -> str:
    """Close open brackets/braces in reverse nesting order (]}] not ]]})."""
    close_stack = _scan_bracket_stack(text)
    return text + "".join(reversed(close_stack))


def _detect_repetition(text: str) -> str | None:
    """Detect 4B repetition loops and truncate at the first repeat boundary.

    The 4B model sometimes enters a degenerate loop, repeating the same
    sequence of array elements N times until max_tokens exhausts — leaving
    truncated, unparseable JSON. This function detects a substring that
    appears 3+ times consecutively and truncates after the 2nd occurrence,
    then closes the JSON structure.

    Returns the repaired text if a repetition loop was detected, else None.
    """
    if len(text) < 200:
        return None

    found = _find_repetition_loop(text)
    if found is None:
        return None

    start, chunk_len, repeats = found
    logger.warning(
        "[JSON-REPAIR] Repetition loop detected: chunk_len=%d repeats=%d at pos=%d. Truncating after 2nd occurrence.",
        chunk_len,
        repeats,
        start,
    )
    # Keep text up to end of 2nd occurrence
    cut_pos = start + chunk_len * 2
    repaired = text[:cut_pos]
    # Close any open strings
    repaired = _close_open_string(repaired)
    # Strip trailing commas/whitespace
    repaired = repaired.rstrip().rstrip(",")
    # Close brackets and braces in reverse nesting order
    repaired = _close_brackets(repaired)
    return repaired


def _safe_parse_json(text: str) -> dict | None:
    """Defense-in-depth JSON parse for LLM output. Returns dict or None."""
    # Layer 0: Repetition loop repair (4B degenerate output)
    repaired = _detect_repetition(text)
    if repaired is not None:
        text = repaired

    # Layer 1: Strip markdown formatting
    clean = text.strip().strip("`").removeprefix("json").strip()
    clean = _strip_markdown_ticks(clean)

    # Layer 2: Unwrap array wrapper [{...}] -> {...}
    if clean.startswith("[") and clean.endswith("]"):
        data = _unwrap_array(clean)
    else:
        # Layer 3: Fix truncated braces and trailing commas
        data = _try_parse(clean)

    # Fallback: extract first {...} block in raw text
    if data is None:
        data = _extract_first_dict_block(text)

    # Layer 4: Coerce to dict
    return _coerce_to_dict(data)
