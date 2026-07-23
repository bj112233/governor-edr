"""Message-history utilities for agent nodes.

Pure functions (no async, no I/O) that extract and sanitize <tool_output>
blocks from the agent's message history.
"""

from ._context import _AgentContext


def _has_tool_outputs_in_history(ctx: _AgentContext) -> bool:
    """Return True if the CURRENT request has produced actual tool output.

    Uses the persisted raw result (_last_raw_tool_result) instead of scanning
    all messages, so injected conversation history from previous turns does not
    trigger false positives. Falls back to _tool_outputs_buffer (which accumulates
    across subtasks) when _last_raw_tool_result is cleared between subtasks.
    """
    return bool(getattr(ctx, "_last_raw_tool_result", "")) or bool(getattr(ctx, "_tool_outputs_buffer", []))


def _extract_tool_history(ctx: _AgentContext) -> str:
    """Extract concatenated raw tool outputs from message history for critic inspection.

    Merges <tool_output> blocks from messages with _tool_outputs_buffer
    (which persists across subtasks and survives sanitization).
    Deduplicates by content to avoid double-counting.
    """
    outputs: list[str] = []
    seen: set[str] = set()
    for m in ctx.messages:
        content = m.get("content", "")
        start = content.find("<tool_output>")
        while start != -1:
            end = content.find("</tool_output>", start)
            if end == -1:
                break
            block = content[start + len("<tool_output>") : end].strip()
            if block and block not in seen:
                outputs.append(block)
                seen.add(block)
            start = content.find("<tool_output>", end)
    # Always merge _tool_outputs_buffer (persists across subtask sanitization)
    for entry in getattr(ctx, "_tool_outputs_buffer", []):
        formatted = f"[{entry['name']}] {entry['result']}"
        if formatted not in seen:
            outputs.append(formatted)
            seen.add(formatted)
    # Include pre-compute hard facts so the critic entity audit can verify
    # IPs/IOCs from deterministic enrichment (not just LLM tool outputs).
    hard_facts = getattr(ctx, "_hard_facts", "")
    if hard_facts and hard_facts not in seen:
        outputs.append(f"[PRE_COMPUTE] {hard_facts}")
        seen.add(hard_facts)
    return "\n---\n".join(outputs)[:4000]


def _get_last_tool_output(msgs: list) -> str:
    """Extract the last tool output from message history."""
    for m in reversed(msgs):
        content = m.get("content", "")
        start = content.rfind("<tool_output>")
        if start != -1:
            end = content.find("</tool_output>", start)
            if end != -1:
                return content[start + len("<tool_output>") : end].strip()
    return ""


def _sanitize_subtask_messages(messages: list[dict]) -> list[dict]:
    """Strip raw tool outputs between subtasks to keep context clean (OOM guard)."""
    return [m for m in messages if not (m.get("role") == "user" and "<tool_output>" in m.get("content", ""))]
