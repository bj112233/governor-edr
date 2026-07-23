# services/agent/_react_parser.py
"""ReAct response parser: extracts thought + tool_calls from LLM textual output.

Parses the free-text ReAct format:
  Thought: <brief thinking>
  Action: <tool_name>
  Action Input: {"key": "value"}

This replaces the old JSON-schema parser which was unreliable on 4B models
because KoboldCpp wraps plain-text in JSON arrays when response_format is set.
"""

import json
import logging
import re
from typing import Any

from ._json_utils import _strip_trailing_commas

__all__ = ["parse_react_response"]

logger = logging.getLogger(__name__)


def parse_react_response(llm_output: str) -> dict[str, Any]:
    """
    Parse ReAct output — tries textual format first, then falls back to legacy JSON.
    Returns: {"thought": "...", "tool_calls": [{"name": "...", "arguments": {...}}]}
    """
    result: dict[str, Any] = {"thought": "", "tool_calls": []}
    text = llm_output.strip()

    # Try 1: Textual ReAct format (Thought/Action/Action Input)
    textual = _try_parse_textual_react(text)
    if textual is not None:
        return textual

    # Try 2: Legacy JSON format (backward compat for model still emitting old JSON)
    legacy = _try_parse_legacy_json(text)
    if legacy is not None:
        return legacy

    # Fallback: no recognizable structure
    _handle_no_action(text, result)
    return result


def _try_parse_textual_react(text: str) -> dict[str, Any] | None:
    """Parse textual ReAct format — aggressive extraction, ignores surrounding noise."""
    result: dict[str, Any] = {"thought": "", "tool_calls": []}
    text = text.strip()

    # 1. Extract thought — prefer explicit Thought: over internal <thinking>
    thought_source = ""
    text_without_thinking = re.sub(
        r"<thinking>.*?(?:</thinking>|(?=^\s*Action:)|\Z)", "", text, flags=re.DOTALL | re.IGNORECASE | re.MULTILINE
    )
    thought_match = re.search(
        r"^\s*Thought:\s*(.*?)(?=^\s*Action:|\Z)", text_without_thinking, re.DOTALL | re.IGNORECASE | re.MULTILINE
    )
    if thought_match:
        result["thought"] = thought_match.group(1).strip()
        thought_source = "thought"
    else:
        thinking_match = re.search(
            r"<thinking>\s*(.*?)(?:\s*</thinking>|(?=^\s*Action:)|\Z)",
            text,
            re.DOTALL | re.IGNORECASE | re.MULTILINE,
        )
        if thinking_match:
            result["thought"] = thinking_match.group(1).strip()
            thought_source = "thinking"
        else:
            parts = re.split(r"Action:", text, maxsplit=1, flags=re.IGNORECASE)
            if len(parts) > 1:
                result["thought"] = parts[0].strip()[:500]
                thought_source = "prefix"

    # 2. Extract ALL Action declarations (with or without Action Input)
    # Split by "Action:" to find each tool call block
    action_blocks = re.split(r"Action:\s*", text, flags=re.IGNORECASE)
    # action_blocks[0] is everything before first Action:, skip it
    for block in action_blocks[1:]:
        # Extract tool name (first word after Action:)
        name_match = re.match(r"(\S+)", block)
        if not name_match:
            continue
        tool_name = name_match.group(1).strip()

        # Look for Action Input: after the tool name
        args = {}
        input_match = re.search(r"Action Input:\s*(\{.*?\})(?:\n|$)", block, re.DOTALL | re.IGNORECASE)
        if input_match:
            raw_args = input_match.group(1).strip()
            args = _parse_action_input(raw_args, tool_name)
        elif tool_name == "final_answer":
            # LLM wrote plain text (no JSON braces). Try "Action Input: <text>"
            # first, then fall back to text after the tool name.
            ai_match = re.search(r"Action Input:\s*(.+)", block, re.DOTALL | re.IGNORECASE)
            if ai_match:
                raw_text = ai_match.group(1).strip()
            else:
                raw_text = block[len(tool_name) :].strip()
            if raw_text:
                logger.warning("[PARSER] No JSON braces for final_answer, wrapping raw text")
                args = {"text": raw_text}
            elif result.get("thought") and thought_source != "thinking":
                # LLM wrote "Action: final_answer" with no input, but left
                # synthesis in the Thought field. Salvage it.
                logger.warning(
                    "[PARSER] final_answer has no input — salvaging Thought (%d chars) as text.",
                    len(result["thought"]),
                )
                args = {"text": result["thought"]}

        result["tool_calls"].append({"name": tool_name, "arguments": args})

    if result["tool_calls"]:
        return result
    return None


def _try_parse_legacy_json(text: str) -> dict | None:
    """Fallback: parse old JSON-schema output if model still emits it."""
    # Look for JSON block or raw JSON object
    json_text = text
    code_block_match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if code_block_match:
        json_text = code_block_match.group(1).strip()

    # Must look like a JSON object
    if not (json_text.startswith("{") and json_text.endswith("}")):
        return None

    import json

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    thought = data.get("thought", "")
    tool_calls = []
    for tc in data.get("tool_calls", []):
        if isinstance(tc, dict):
            name = tc.get("name", "")
            args = tc.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"text": args} if name == "final_answer" else {}
            tool_calls.append({"name": name, "arguments": args})

    if tool_calls:
        return {"thought": thought, "tool_calls": tool_calls}
    return None


def _parse_action_input(raw_args: str, tool_name: str) -> dict:
    """Parse Action Input JSON with multiple fallback layers."""
    if not raw_args:
        return {}

    # Layer 1: Direct JSON parse
    try:
        return json.loads(raw_args)
    except json.JSONDecodeError:
        pass

    # Layer 2: Strip trailing commas and retry
    try:
        return json.loads(_strip_trailing_commas(raw_args))
    except json.JSONDecodeError:
        pass

    # Layer 3: Handle string literal (model wrapped JSON in quotes)
    if raw_args.startswith('"') and raw_args.endswith('"'):
        try:
            inner = json.loads(raw_args)
            if isinstance(inner, str):
                return json.loads(inner)
        except (json.JSONDecodeError, ValueError):
            pass

    # Layer 4: For final_answer, wrap raw text
    if tool_name == "final_answer":
        logger.warning("[PARSER] Wrapping raw text for final_answer: %r", raw_args[:80])
        return {"text": raw_args}

    # Layer 5: Error feedback so model can fix on retry
    logger.error("[PARSER] Failed to parse Action Input for %s: %r", tool_name, raw_args[:200])
    return {
        "CRITICAL_ERROR": (
            f"Action Input for tool '{tool_name}' is not valid JSON. "
            'You MUST output a valid JSON object (e.g., {"key": "value"}).'
        ),
        "your_raw_input": raw_args[:500],
    }


def _handle_no_action(text: str, result: dict) -> None:
    """Handle cases where no Action line is found."""
    thought_text = result.get("thought", "")

    # Thought Leak Salvage: model dumped full answer in thought
    if len(thought_text) > 1500:
        logger.warning(
            "[PARSER] Thought Leak detected (%d chars). Salvaging to final_answer.",
            len(thought_text),
        )
        result["tool_calls"] = [{"name": "final_answer", "arguments": {"text": thought_text}}]
        result["thought"] = "Auto-recovered answer from thought field."
        return

    # Check if the model just typed an answer without any ReAct structure
    # BUT: reject tool_output echoes — the model copied a <tool_output> block
    # verbatim instead of synthesizing an answer. Salvaging that would send
    # raw tool data to the user as the "answer".
    if text and not result["thought"] and len(text) > 20 and not text.lstrip().startswith("<tool_output>"):
        logger.warning("[PARSER] No ReAct structure found. Salvaging to final_answer.")
        # Record event for the No-ReAct frequency tracker — auto-injects
        # aggressive format directive into future system prompts if the
        # model repeatedly collapses to free-form text.
        from ._noreact_tracker import record_no_react

        record_no_react()
        result["tool_calls"] = [{"name": "final_answer", "arguments": {"text": text}}]
        result["thought"] = "Auto-recovered: model output without ReAct structure."
        result["no_react_salvaged"] = True
    elif text and text.lstrip().startswith("<tool_output>"):
        logger.warning("[PARSER] Model echoed <tool_output> block — not salvaging. Nudging for real answer.")
        result["echo_detected"] = True
