"""No-tool-call handler — extracted from _executor_phases.py (SRP).

Handles cases where the LLM response contains no tool calls: echo detection,
thought leak, zero-tool silent failure, and termination fallback.

Refactored (Phase 2): Chain of Responsibility — each guard clause extracted
as a pure detector function returning Optional[result].
"""

import logging

from .._context import AgentState, _AgentContext
from .._helpers import _get_last_tool_output
from ..utils import _strip_markdown
from .state_manager import handle_no_tool_call

logger = logging.getLogger(__name__)

# Type alias: (handled, next_state, output, tool_calls_override)
_HandlerResult = tuple[bool, AgentState, str | None, list]

_ECHO_NUDGE = (
    "CRITICAL: You echoed a <tool_output> block as your answer. "
    "That is RAW DATA, not an answer. You MUST synthesize the tool results "
    "into a clear, structured response for the user. "
    "Call final_answer with your synthesized report NOW."
)


def _compute_fallback_text(ctx: _AgentContext, thought_text: str) -> tuple[str, str, str]:
    """Compute fallback text from raw tool result, last output, or thought.

    Returns (fallback_text, raw, last_output).
    """
    _raw = getattr(ctx, "_last_raw_tool_result", "")
    last_output = _get_last_tool_output(ctx.messages)
    fallback = (
        _raw
        if (_raw and len(_raw) > 10)
        else (
            last_output
            if (last_output and len(last_output) > 20)
            else (thought_text if thought_text else "המשימה הושלמה.")
        )
    )
    return fallback, _raw, last_output


def _detect_echo_subtask(ctx: _AgentContext, parsed: dict) -> _HandlerResult | None:
    """Echo detection in subtask mode — must precede auto-advance."""
    if not parsed.get("echo_detected"):
        return None
    logger.warning(
        "[AGENT] Tool-output echo in subtask mode (step %d). Nudging for synthesis before auto-advance.",
        ctx.step_count,
    )
    ctx.messages.append({"role": "user", "content": _ECHO_NUDGE})
    return True, AgentState.EXECUTE, None, []


def _detect_thought_leak(
    ctx: _AgentContext,
    thought_text: str,
    raw: str,
    last_output: str,
) -> _HandlerResult | None:
    """Thought leak: long thought field with no tool data."""
    if raw or last_output or len(thought_text) <= 500:
        return None
    logger.warning(
        "[AGENT] Thought Leak Nudge (step %d): %d chars in thought, no tool data. Looping back.",
        ctx.step_count,
        len(thought_text),
    )
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                "CRITICAL ERROR: You wrote a long answer inside the 'thought' field "
                "instead of calling the final_answer tool. Your thought field is for planning ONLY "
                "(max 100 chars). Call final_answer NOW with the complete answer inside its 'text' argument."
            ),
        }
    )
    return True, AgentState.EXECUTE, None, []


def _detect_zero_tool_failure(ctx: _AgentContext) -> _HandlerResult | None:
    """Zero-tool silent failure: tools available but none used."""
    _real_tools_used = len(ctx._tools_used) > 0
    _has_actionable_tools = any(
        t.get("function", {}).get("name", "") not in ("final_answer", "") for t in ctx.active_tools
    )
    if not (_has_actionable_tools and not _real_tools_used):
        return None
    logger.warning(
        "[AGENT] Zero-tool silent failure (step %d). %d tools available, 0 used. Nudging.",
        ctx.step_count,
        len(ctx.active_tools) - 1,
    )
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                "CRITICAL ERROR: You have not called ANY tool yet, but tools are available. "
                "You MUST select and call an appropriate tool. Do NOT write inside the 'thought' field — call a tool NOW."
            ),
        }
    )
    return True, AgentState.EXECUTE, None, []


def _detect_echo_general(
    ctx: _AgentContext,
    parsed: dict,
    fallback_text: str,
) -> _HandlerResult | None:
    """General echo detection: model copied <tool_output> verbatim."""
    if not (parsed.get("echo_detected") or fallback_text.lstrip().startswith("<tool_output>")):
        return None
    logger.warning("[AGENT] Tool-output echo detected (step %d). Nudging for synthesized answer.", ctx.step_count)
    ctx.messages.append({"role": "user", "content": _ECHO_NUDGE})
    return True, AgentState.EXECUTE, None, []


def _termination_fallback(ctx: _AgentContext, fallback_text: str) -> _HandlerResult:
    """Non-subtask mode — old auto-dispatch final_answer."""
    logger.warning("[AGENT] Termination fallback: auto-dispatch final_answer (step %d)", ctx.step_count)
    return False, AgentState.EXECUTE, None, [{"name": "final_answer", "arguments": {"text": fallback_text}}]


def _route_thought_only(ctx: _AgentContext, thought_text: str) -> _HandlerResult | None:
    """No tool_call but thought present — route as clarification."""
    if not thought_text:
        return None
    logger.info("[AGENT] No tool_call but thought present — routing clarification.")
    ctx.output = _strip_markdown(thought_text)
    return True, AgentState.FINALIZE, ctx.output, []


async def _handle_step_gt_zero(ctx: _AgentContext, parsed: dict, thought_text: str) -> _HandlerResult:
    """Handle no-tool-call when step_count > 0 (chain of guards)."""
    fallback_text, raw, last_output = _compute_fallback_text(ctx, thought_text)

    # Echo in subtask mode — must precede auto-advance
    result = _detect_echo_subtask(ctx, parsed)
    if result is not None:
        return result

    # Delegate to state manager (subtask auto-advance)
    _handled, _next_state, _output = await handle_no_tool_call(ctx, fallback_text)
    if _handled:
        assert _next_state is not None
        return True, _next_state, _output, []

    # Thought leak
    result = _detect_thought_leak(ctx, thought_text, raw, last_output)
    if result is not None:
        return result

    # Zero-tool silent failure
    result = _detect_zero_tool_failure(ctx)
    if result is not None:
        return result

    # General echo detection
    result = _detect_echo_general(ctx, parsed, fallback_text)
    if result is not None:
        return result

    # Termination fallback
    return _termination_fallback(ctx, fallback_text)


async def handle_no_tool_calls(
    ctx: _AgentContext, parsed: dict, tool_calls: list
) -> tuple[bool, AgentState, str | None, list]:
    """Handle no-tool-call case. Returns (handled, next_state, output, tool_calls_override)."""
    thought_text = (parsed.get("thought") or "").strip()

    if ctx.step_count > 0:
        return await _handle_step_gt_zero(ctx, parsed, thought_text)

    result = _route_thought_only(ctx, thought_text)
    if result is not None:
        return result

    return False, AgentState.EXECUTE, None, []
