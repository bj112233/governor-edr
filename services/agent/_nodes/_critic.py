"""FSM Node: CRITIC — evaluate draft final_answer against raw tool data."""

import asyncio
import logging

from .._context import _CRITIC_MAX_RETRIES, AgentState, _AgentContext
from .._helpers import (
    _extract_tool_history,
    _has_tool_outputs_in_history,
    _run_critic_evaluation,
    _run_tool_selection_review,
)

logger = logging.getLogger(__name__)


def _build_tool_msg(tool_review: dict) -> str | None:
    """Build tool-selection feedback message, or None if no issue."""
    tool_score = tool_review.get("tool_selection_score", 100)
    if tool_score >= 60:
        return None
    _suggested = tool_review.get("suggested_sequence", [])
    if not _suggested:
        return None  # no actionable alternative
    msg = (
        f"[TOOL SELECTION] Score: {tool_score}/100. "
        f"Consider using: {', '.join(t['tool'] for t in _suggested)}. "
        f"{tool_review.get('reasoning', '')}"
    )
    logger.warning("[CRITIC] Tool selection score %d below threshold.", tool_score)
    return msg


def _accept_pass(ctx: _AgentContext, log_msg: str) -> tuple[AgentState, str | None]:
    """Common: accept draft on PASS, reset feedback, return FINALIZE."""
    logger.info(log_msg)
    ctx._last_critic_feedback = {}
    ctx._completeness_retries = 0
    ctx._draft_v1 = ""  # reset rollback state
    return AgentState.FINALIZE, ctx.draft_answer


def _circuit_breaker_fallback(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Graceful Degradation: return raw tool data after repeated rejections.

    The draft was rejected N times as unreliable (likely hallucination). Sending
    the rejected draft — even with a warning prefix — delivers fabricated facts
    to the user. Instead, fall back to the deterministic layer: the raw tool
    outputs that ARE grounded in real system state.
    """
    raw_data = _extract_tool_history(ctx).strip()
    if not raw_data:
        raw_data = "לא נאספו נתונים מהכלים."
    fallback = (
        "⚠️ **[SYSTEM WARNING: סינתזה קוגניטיבית נכשלה]**\n"
        "מנגנון הביקורת זיהה כי התשובה המעובדת אינה מהימנה (חשד להזיה).\n"
        "מוצגים הנתונים הגולמיים שנאספו מהמערכת ללא עיבוד AI:\n\n"
        f"```\n{raw_data}\n```\n\n"
        "<SCORE>0.0</SCORE>"
    )
    logger.warning(
        "[CRITIC] Circuit breaker after %d rejections — degrading to raw tool data.",
        _CRITIC_MAX_RETRIES,
    )
    return AgentState.FINALIZE, fallback


def _build_kca_revise_block(logical_flaw: str, missing: list, fb_text: str) -> str:
    """Build targeted revision blocks (Change + Add) for KCA scaffolding."""
    revise_block = ""
    if logical_flaw:
        revise_block += (
            "\n<REVISE_TARGET>\n"
            f"המשפט הבא מכיל נתון שאינו מגובה בכלים, החלף או מחק אותו: {logical_flaw}\n"
            "</REVISE_TARGET>"
        )
    if missing:
        revise_block += (
            "\n<ADD_EVIDENCE>\n"
            f"הוסף ביסוס עובדתי מדויק עבור הטענות הבאות מתוך נתוני הכלים: {'; '.join(missing[:3])}\n"
            "</ADD_EVIDENCE>"
        )
    # Fallback: if no specific flaw/missing but still FAIL (e.g. brevity),
    # provide a generic enrichment target instead of negative language.
    if not revise_block and fb_text:
        revise_block += f"\n<REVISE_TARGET>\nשפר את הדיוק והשלמות של הדוח לפי: {fb_text}\n</REVISE_TARGET>"
    return revise_block


def _compress_context_for_retry(ctx: _AgentContext, feedback_msg: str, instruction: str) -> None:
    """Replace full message history with clean summary for retry.

    Includes the PREVIOUS DRAFT so the model can REPAIR it rather than
    writing from scratch — the 4B model collapses when asked to synthesize
    a full report from tool data alone after context compression.

    Tail-anchors the output format (Few-Shot) so it stays fresh in the
    KV cache immediately before generation.

    BUDGET-AWARE: The 4B model on 6GB VRAM is highly sensitive to context
    size — KV cache build time scales linearly with tokens, and attention
    quality degrades (Attention Collapse) when the context is noisy.
    This function GUARANTEES post < pre by truncating tool_data and draft_v1
    to fit within a calculated budget (85% of pre-compression size).
    """
    tool_data = _extract_tool_history(ctx)
    # ── Save draft_v1 for rollback (first rejection only) ──
    if not ctx._draft_v1:
        ctx._draft_v1 = ctx.draft_answer
    _pre_chars = sum(len(m.get("content", "")) for m in ctx.messages)
    system_msg = ctx.messages[0] if ctx.messages and ctx.messages[0].get("role") == "system" else None
    system_chars = len(system_msg.get("content", "")) if system_msg else 0

    # ── Budget calculation: compress VARIABLE content, keep system intact ──
    # The system prompt is fixed overhead (~13.6K). We compress only the
    # variable message history, targeting 80% of the variable portion.
    # This guarantees post < pre while giving meaningful data budget.
    _TEMPLATE_OVERHEAD = 350
    _variable_pre = _pre_chars - system_chars
    _variable_target = int(_variable_pre * 0.80)
    _budget_for_data = _variable_target - _TEMPLATE_OVERHEAD - len(feedback_msg) - len(instruction)
    if _budget_for_data < 1500:
        _budget_for_data = 1500  # hard floor — need real data for repair

    # Split: 65% tool_data (ground truth), 35% draft_v1 (repairable)
    tool_budget = int(_budget_for_data * 0.65)
    draft_budget = int(_budget_for_data * 0.35)

    if len(tool_data) > tool_budget:
        tool_data = tool_data[:tool_budget] + "\n[...truncated]"
    _draft_v1 = ctx._draft_v1 or ""
    if len(_draft_v1) > draft_budget:
        _draft_v1 = _draft_v1[:draft_budget] + "\n[...truncated]"

    ctx.messages = []
    if system_msg:
        ctx.messages.append(system_msg)
    ctx.messages.append(
        {
            "role": "user",
            "content": (
                "[SYSTEM]\n"
                "You are repairing an incident report based on CRITIC FEEDBACK.\n"
                "Review your previous draft, the raw tool data, and fix the specific flaws mentioned.\n\n"
                f"[RAW TOOL DATA]\n{tool_data}\n\n"
                f"[YOUR PREVIOUS DRAFT]\n{_draft_v1}\n\n"
                f"[CRITIC FEEDBACK]\n{feedback_msg}\n\n"
                f"{instruction}\n\n"
                "[CRITICAL INSTRUCTION - OUTPUT FORMAT]\n"
                "You MUST output your response using the EXACT tool call format:\n"
                "Action: final_answer\n"
                'Action Input: {"text": "YOUR_FULL_CORRECTED_REPORT_HERE..."}\n'
                "Do NOT just write a thought. Output the full corrected text."
            ),
        }
    )
    _post_chars = sum(len(m.get("content", "")) for m in ctx.messages)
    logger.info(
        "[CRITIC] Context compressed for retry: %d chars → %d chars (tool_data=%d chars, draft_v1=%d chars, budget=%d).",
        _pre_chars,
        _post_chars,
        len(tool_data),
        len(_draft_v1),
        _budget_for_data,
    )


_KCA_SHORT_INSTRUCTION = (
    "INSTRUCTION:\n"
    "1. Read the targets inside <REVISE_TARGET> and <ADD_EVIDENCE>.\n"
    "2. Keep all successful text blocks verified in <ANCHOR_SUCCESS>.\n"
    "3. Generate updated report, optimizing only the requested targets.\n"
    "4. Rely ONLY on valid facts inside <TOOL_DATA>.\n"
    "End with <SCORE>0.X</SCORE>."
)

_KCA_FULL_INSTRUCTION = (
    "INSTRUCTION:\n"
    "1. Read the targets inside <REVISE_TARGET> and <ADD_EVIDENCE>.\n"
    "2. Keep all successful text blocks verified in <ANCHOR_SUCCESS>.\n"
    "3. Generate an updated, fully enriched report in Hebrew, optimizing only the requested targets.\n"
    "4. Rely ONLY on the valid facts inside <TOOL_DATA>.\n"
    "End with <SCORE>0.X</SCORE>."
)


_RETRY_COLLAPSE_THRESHOLD = 200  # chars — retry output below this is a collapsed generation

# Meta-description prefixes that indicate the model wrote ABOUT the report
# instead of writing the report itself (e.g. "Fixing the false negative...")
_COLLAPSED_PREFIXES = (
    "fixing",
    "thought:",
    "תיקון",
    "מתקן",
    "אני אתקן",
    "correcting",
    "updating",
    "revising",
)


def _is_collapsed_retry(ctx: _AgentContext) -> bool:
    """Detect if a critic-retry produced a collapsed/hollow output.

    The 4B model often fails to regenerate a full report after context
    compression — instead it emits a short meta-description ("Fixing the
    false negative claim...") or just a Thought without Action.

    Returns True if the retry output is:
      1. Shorter than _RETRY_COLLAPSE_THRESHOLD, OR
      2. A meta-description (starts with a collapsed prefix), OR
      3. Drastically shorter than draft_v1 (< 30% of original length)
    """
    if not ctx._draft_v1 or ctx.critic_rejections < 1:
        return False
    _draft = ctx.draft_answer.strip()
    if not _draft:
        return True
    if len(_draft) < _RETRY_COLLAPSE_THRESHOLD:
        return True
    _lower = _draft.lower()
    if _lower.startswith(_COLLAPSED_PREFIXES):
        return True
    if ctx._draft_v1 and len(_draft) < len(ctx._draft_v1) * 0.3:
        return True
    return False


def _rollback_to_draft_v1(ctx: _AgentContext, critic_feedback: str) -> tuple[AgentState, str | None]:
    """Graceful Degradation: return draft_v1 with a reliability warning.

    The critic caught a real flaw in draft_v1, but the retry collapsed.
    A full report with one logical error + a warning is far more useful
    than raw tool data or a 119-char meta-description.
    """
    _fb_preview = critic_feedback[:200] if critic_feedback else "פגם לוגי"
    warning = (
        "⚠️ **[מערכת: התראת אמינות AI]**\n"
        "מנגנון הביקורת זיהה פגם לוגי בדוח זה, אך התיקון האוטומטי נכשל.\n"
        f"הערת הביקורת המקורית: {_fb_preview}\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"{ctx._draft_v1}\n\n"
        "<SCORE>0.0</SCORE>"
    )
    logger.warning(
        "[CRITIC] Retry collapsed (len=%d vs draft_v1=%d). Rolling back to draft_v1 with reliability warning.",
        len(ctx.draft_answer),
        len(ctx._draft_v1),
    )
    ctx._last_critic_feedback = {}
    ctx._completeness_retries = 0
    return AgentState.FINALIZE, warning


async def _node_critic(ctx: _AgentContext) -> tuple[AgentState, str | None]:
    """Evaluate draft final_answer against raw tool data with structured feedback.

    Runs TWO reviews IN PARALLEL via asyncio.gather to halve latency:
    1. Output-quality critic (accuracy + completeness)
    2. Tool-selection reviewer (optimal tool choice)

    Feedback is MERGED so the agent ALWAYS receives the full context,
    regardless of which review flagged an issue.
    """
    if not _has_tool_outputs_in_history(ctx):
        return AgentState.FINALIZE, ctx.draft_answer

    # ── Rollback: detect collapsed retry before wasting a critic LLM call ──
    if _is_collapsed_retry(ctx):
        _fb = ctx._last_critic_feedback.get("feedback_to_agent", "") or ctx._last_critic_feedback.get(
            "logical_flaw", ""
        )
        return _rollback_to_draft_v1(ctx, _fb)

    logger.info("[CRITIC] Evaluating draft answer + tool selection (parallel)...")

    # ── Parallel execution: halves total LLM latency ──
    (is_valid, feedback), tool_review = await asyncio.gather(
        _run_critic_evaluation(
            original_query=ctx.user_question,
            tool_data=_extract_tool_history(ctx),
            draft_answer=ctx.draft_answer,
            engine=ctx.engine,
            tools_used=ctx._tools_used,
        ),
        _run_tool_selection_review(
            original_query=ctx.user_question,
            tools_used=ctx._tools_used,
            available_tools=ctx.active_tools,
            engine=ctx.engine,
        ),
    )

    tool_score = tool_review.get("tool_selection_score", 100)
    tool_msg = _build_tool_msg(tool_review)

    # Early exit: output quality PASS
    if is_valid:
        if tool_score >= 60:
            return _accept_pass(ctx, f"[CRITIC] Draft validated (PASS). tool_score={tool_score}")
        if not tool_msg:
            return _accept_pass(ctx, f"[CRITIC] Output PASS, tool_score={tool_score} but no alternatives — accepting.")
        # CoVe PASS but tool_score low — accept anyway (4B reviewer over-rejects)
        return _accept_pass(ctx, f"[CRITIC] Output PASS — accepting despite tool_score={tool_score}.")

    # Output FAIL: append tool advice if present
    if tool_msg:
        existing_fb = feedback.get("feedback_to_agent", "")
        feedback["feedback_to_agent"] = existing_fb + "\n" + tool_msg

    # Handle FINALIZE_WITH_WARNING explicitly to avoid forced retries
    if feedback.get("action_required") == "FINALIZE_WITH_WARNING":
        warning_text = "[System Warning: Partial or unverified claims detected]\n\n" + ctx.draft_answer
        ctx._completeness_retries = 0
        return AgentState.FINALIZE, warning_text

    ctx.critic_rejections += 1

    # Circuit breaker: repeated rejections -> Graceful Degradation
    if ctx.critic_rejections >= _CRITIC_MAX_RETRIES:
        return _circuit_breaker_fallback(ctx)

    # ── KCA Scaffold (Keep-Change-Add): Positive Framing for 4B models ──
    fb_text = feedback.get("feedback_to_agent", "")
    logical_flaw = feedback.get("logical_flaw", "")
    missing = feedback.get("missing_facts", [])

    logger.warning(
        "[CRITIC] Draft flagged for revision (%d/%d): reason=%r",
        ctx.critic_rejections,
        _CRITIC_MAX_RETRIES,
        fb_text[:80],
    )
    ctx._last_critic_feedback = feedback

    # If fb_text already contains KCA blocks (e.g. entity audit), use it directly
    if "<ANCHOR_SUCCESS>" in fb_text:
        feedback_msg = (
            "[SYSTEM COGNITION PATH]\n"
            f"[אופטימיזציית טיוטה - סבב שיפור ({ctx.critic_rejections}/{_CRITIC_MAX_RETRIES})]\n"
            f"{fb_text}"
        )
        _compress_context_for_retry(ctx, feedback_msg, _KCA_SHORT_INSTRUCTION)
        return AgentState.EXECUTE, ""

    # Build targeted revision blocks + positive framing
    revise_block = _build_kca_revise_block(logical_flaw, missing, fb_text)

    # Populate claims history for observability/tracking
    claims = feedback.get("extracted_claims", [])
    if claims:
        ctx._critic_claims_history.append(claims)

    feedback_msg = (
        "[SYSTEM COGNITION PATH]\n"
        f"[אופטימיזציית טיוטה - סבב שיפור ({ctx.critic_rejections}/{_CRITIC_MAX_RETRIES})]\n"
        "<ANCHOR_SUCCESS>\n"
        "המבנה הכללי והנתונים הטכניים האחרים בטיוטה מדויקים ומצוינים. שמור עליהם.\n"
        "</ANCHOR_SUCCESS>\n"
        f"{revise_block}"
    )
    _compress_context_for_retry(ctx, feedback_msg, _KCA_FULL_INSTRUCTION)
    return AgentState.EXECUTE, None
