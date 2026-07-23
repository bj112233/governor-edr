"""Tool Selection Review — plain-text SCORE: regex for 4B model robustness."""

import logging
import re

logger = logging.getLogger(__name__)


def _check_no_alternatives(available_tools: list[dict]) -> dict | None:
    """Return perfect-score result if no alternatives available."""
    if not available_tools:
        return {
            "tool_selection_score": 100,
            "missed_tools": [],
            "suggested_sequence": [],
            "reasoning": "No alternatives available.",
        }
    return None


def _check_zero_tool_usage(tools_used: list[dict], available_tools: list[dict]) -> dict | None:
    """Return zero-score result if no tools used but actionable tools exist."""
    actionable = [t for t in available_tools if t.get("function", {}).get("name", "") != "final_answer"]
    if not tools_used and actionable:
        return {
            "tool_selection_score": 0,
            "missed_tools": [t.get("function", {}).get("name", "?") for t in actionable],
            "suggested_sequence": [
                {"tool": t.get("function", {}).get("name", "?"), "reason": "נדרש לשימוש לפי בקשת המשתמש"}
                for t in actionable[:3]
            ],
            "reasoning": "הסוכן לא השתמש באף כלי למרות הכלים הזמינים.",
        }
    return None


def _build_review_prompts(original_query: str, tools_used: list[dict], available_tools: list[dict]) -> tuple[str, str]:
    """Build (system_prompt, user_input) for the LLM review call."""
    tool_catalog = "\n".join(
        f"- {t.get('name', '?')}: {t.get('description', 'No description')[:120]}" for t in available_tools
    )
    used_summary = "\n".join(
        f"- {t.get('name', '?')}({t.get('command', '')}) → {str(t.get('output_summary', ''))[:80]}" for t in tools_used
    )
    review_system = (
        "You are a Tool Selection Reviewer. Evaluate whether the agent chose "
        "the optimal tools for the user's request.\n\n"
        "RULES:\n"
        "1. Score 0-100: Were the RIGHT tools chosen?\n"
        "2. List missed tools that WOULD have helped\n"
        "3. Suggest a BETTER sequence if one exists\n"
        "4. Be concise -- max 3 suggestions\n\n"
        "Output ONLY the final score in this exact format:\n"
        "SCORE: <number between 0 and 100>"
    )
    review_input = (
        f"User request: {original_query}\n\n"
        f"Tools USED by agent:\n{used_summary}\n\n"
        f"Available tools catalog:\n{tool_catalog}"
    )
    return review_system, review_input


_FAIL_CLOSED = {
    "tool_selection_score": 0,
    "missed_tools": [],
    "suggested_sequence": [],
    "reasoning": "Review failed -- fail-closed.",
}


async def _run_tool_selection_review(
    original_query: str,
    tools_used: list[dict],
    available_tools: list[dict],
    engine,
) -> dict:
    """Evaluate whether the agent chose optimal tools for the request.

    Returns structured feedback with scores and suggestions.
    """
    early = _check_no_alternatives(available_tools)
    if early:
        return early

    early = _check_zero_tool_usage(tools_used, available_tools)
    if early:
        return early

    review_system, review_input = _build_review_prompts(original_query, tools_used, available_tools)

    try:
        response = await engine.complete(
            system_prompt=review_system,
            user_input=review_input,
            temperature=0.0,
            max_tokens=128,
        )
        match = re.search(r"SCORE:\s*(\d+)", response)
        if match:
            score = int(match.group(1))
            return {
                "tool_selection_score": min(max(score, 0), 100),
                "missed_tools": [],
                "suggested_sequence": [],
                "reasoning": "",
            }
        logger.warning("[ToolReview] Failed to extract score. Raw: %r", response[:200])
    except Exception as exc:
        logger.error("[ToolReview] LLM call failed: %s", exc)

    return _FAIL_CLOSED
