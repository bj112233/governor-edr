"""Subtask result synthesis — combine multiple subtask outputs into one answer."""

import logging

logger = logging.getLogger(__name__)


async def _synthesize_results(
    user_question: str,
    subtask_results: list[str],
    engine,
    tools_used: list[dict] | None = None,
) -> str:
    """Combine subtask results into a single coherent answer.

    Args:
        tools_used: ctx._tools_used — list of {"name": ...} dicts for tools
            that actually executed. When provided, the synthesis prompt
            includes an explicit allowlist to prevent the 4B model from
            mentioning tools that were stripped/unavailable (a known
            hallucination pattern: the model claims it ran get_event_log
            when that tool was never authorized).
    """
    if not subtask_results:
        return "⚠️ כל התת-משימות נכשלו."
    if len(subtask_results) == 1:
        return subtask_results[0]

    # Build tool allowlist constraint if tools_used is provided
    tool_constraint = ""
    if tools_used:
        ran_names = [t["name"] for t in tools_used if "name" in t]
        if ran_names:
            tool_constraint = (
                f"\n6. The ONLY tools that actually executed are: {', '.join(ran_names)}.\n"
                "   You MUST NOT mention, reference, or claim to have used any other tool name.\n"
                "   If a planned tool was unavailable, say 'לא בוצע' — do NOT fabricate its output.\n"
            )

    system_prompt = (
        "You are a synthesis engine. Combine the following subtask results into a single, "
        "coherent answer to the user's original question.\n\n"
        "STRICT ANTI-HALLUCINATION RULES:\n"
        "1. You MUST ONLY use factual data explicitly stated in the subtask results below.\n"
        "2. You MUST NOT invent IP addresses, threat scores, attack names, or any data not present.\n"
        "3. You MUST NOT use your internal training knowledge.\n"
        "4. If a subtask result says 'No data' or 'Failed', you MUST report that honestly.\n"
        "5. If ALL subtasks failed or returned no data, say explicitly: 'אין לי מידע על כך.'\n"
        f"{tool_constraint}\n"
        "FORMAT: Preserve ALL factual data. Respond in the same language as the user's question. "
        "Keep cyber terms in English: MITRE ATT&CK, TTP, IOC, Encoded Commands, Execution Policy Bypass, Defense Evasion. "
        "Be THOROUGH but HONEST. Do NOT embellish."
    )
    user_input = f"Original question: {user_question}\n\nSubtask results:\n" + "\n\n".join(
        f"[{i + 1}] {r}" for i, r in enumerate(subtask_results)
    )

    try:
        result = await engine.complete(
            system_prompt=system_prompt,
            user_input=user_input,
            temperature=0.1,
            max_tokens=2048,
            timeout=180.0,  # synthesis is a background daemon — allow 3min under CPU load
        )
        return result.strip()
    except Exception as exc:
        logger.warning("[PLANNER] Synthesis failed: %s", exc)
        return "\n\n---\n\n".join(subtask_results)
