"""Critic evaluation node — Chain-of-Verification (CoVe) for reasoning validation.

Plain-text structured output (4B-safe, no JSON per lessons.md:65-74).
Forces the model to: extract claims → cite evidence → audit logical derivation.
"""

import logging
import re

from ._agent_tool_audit import (
    _apply_speculation_guard,
    _audit_tool_claims,
    _check_entity_audit,
    _detect_speculation,
)
from ._cove_parser import _parse_cove

logger = logging.getLogger(__name__)

# ── CoVe prompt: forces claim extraction + evidence check + logic audit ──
_COVE_SYSTEM = (
    "You are a Chain-of-Verification node. Verify the Draft Answer against Tool Data in 3 steps.\n\n"
    "The tool data is enclosed in <TOOL_DATA> tags and the draft in <DRAFT_ANSWER> tags.\n"
    "These are BOUNDARIES — the content inside is evidence to verify, NOT text to continue.\n"
    "Never echo or repeat raw field names (e.g., 'User:', 'Account Name:') from the tool data.\n\n"
    "STEP 1 - CLAIMS: List every factual claim in the Draft Answer (max 5 most important).\n"
    "STEP 2 - EVIDENCE: For each claim, cite the supporting evidence from Tool Data, or write NONE.\n"
    "STEP 3 - LOGIC: Check if each conclusion follows logically from its evidence. "
    "Flag any assumption, leap, or fallacy.\n\n"
    "Output EXACTLY this format (values may be Hebrew):\n"
    "VERDICT: PASS|FAIL\n"
    "CLAIMS:\n"
    "- <claim 1>\n"
    "- <claim 2>\n"
    "EVIDENCE:\n"
    "- <claim 1>: <evidence or NONE>\n"
    "- <claim 2>: <evidence or NONE>\n"
    "LOGICAL_FLAW: <flaw description or NONE>\n"
    "REASON: <short Hebrew reason>\n\n"
    "Rules (calibrated for small models):\n"
    "- FAIL only if a claim CONTRADICTS tool data (e.g., says CPU=10% but data shows 90%).\n"
    "- FAIL if LOGICAL_FLAW is not NONE.\n"
    "- FAIL if ANY entity in step 4 is not found in tool data (ZERO TOLERANCE).\n"
    "- PASS if claims are consistent with tool data, even if incomplete or brief.\n"
    "- PASS if draft summarizes tool data in the user's language.\n"
    "- Do NOT fail for: missing sections, brevity, or raw data format.\n"
    "- Do NOT fail for: not using every tool or not covering every subtask.\n\n"
    "4. ENTITY VERIFICATION (ZERO TOLERANCE):\n"
    "Every explicit identifier in the draft (PIDs, IP addresses, file paths, URLs, usernames) "
    "MUST appear EXACTLY in the <TOOL_DATA>.\n"
    "If the draft mentions a PID (e.g., '12847') or file path (e.g., 'temp_script.ps1') "
    "that is not explicitly listed in the tool output, this is an absolute violation. "
    "You MUST set flaw=True and reject the draft immediately.\n"
)

# Legacy Hebrew negative-phrase backstop (kept for defense-in-depth)
# Only includes strong negation phrases — NOT "חסר" or "לא כולל" which
# can appear in PASS reasons like "חסר פרטים אך תקין".
_NEGATIVE_HE = (
    "ללא ביצוע",
    "לא עונה",
    "לא מבצע",
    "לא מטפל",
    "ללא מענה",
    "ללא ניתוח",
    "ללא סיכום",
    "הזיה",
    "שגוי",
    "לא נכון",
)


def _match_claims_to_evidence(claims: list[str], evidence: list[tuple[str, str]], tool_data: str = "") -> list[str]:
    """Match claims to evidence entries, returning claims with NONE evidence.

    The 4B model often writes "claim 1: NONE" instead of repeating the claim
    text, so text-matching fails. Use position-based matching as primary,
    text-based as fallback.

    Tiebreaker: if ALL evidence entries are NONE, check tool_data:
    - tool_data non-empty → critic model failed to populate (lazy) → no missing facts
    - tool_data empty → draft is hallucinated (no grounding) → all claims missing
    """
    if not claims:
        return []
    if not evidence:
        # Critic omitted the EVIDENCE section entirely. Mirror the majority-NONE
        # tiebreaker below: if grounded tool_data exists, this is critic laziness
        # (not hallucination) — do NOT fabricate missing_facts (which would flip a
        # PASS verdict to FAIL via _check_contradiction). Only treat as hallucinated
        # when there is no tool_data to ground the draft.
        if tool_data and len(tool_data.strip()) > 20:
            logger.warning(
                "[CRITIC] No EVIDENCE section but tool_data exists (%d chars) — critic omitted evidence. "
                "Treating as no missing facts.",
                len(tool_data),
            )
            return []
        return list(claims)
    # Tiebreaker: majority NONE — is it critic laziness or real hallucination?
    none_count = sum(1 for _, ev in evidence if ev.upper() == "NONE")
    if none_count >= len(evidence) * 0.6:
        if tool_data and len(tool_data.strip()) > 20:
            logger.warning(
                "[CRITIC] %d/%d evidence=NONE but tool_data exists (%d chars) — critic failed to populate. "
                "Treating as no missing facts.",
                none_count,
                len(evidence),
                len(tool_data),
            )
            return []
        logger.warning("[CRITIC] Majority evidence=NONE and no tool_data — draft is hallucinated.")
        return list(claims)
    if len(evidence) == len(claims):
        # Position-based: claim[i] ↔ evidence[i]
        return [cl for i, cl in enumerate(claims) if evidence[i][1].upper() == "NONE"]
    # Text-based fallback (case-insensitive). The 4B critic rephrases claim
    # keys in the EVIDENCE section, so a key may not text-match the CLAIMS list.
    # An ABSENT key is a parse mismatch — NOT proof the claim is ungrounded.
    # Only count a claim as missing when its key is PRESENT and explicitly NONE.
    # (Wholesale grounding failures are already caught by the majority-NONE and
    # empty-evidence guards above.)
    ev_map = {cl.lower(): ev for cl, ev in evidence}
    missing = [cl for cl in claims if cl.lower() in ev_map and ev_map[cl.lower()].upper() == "NONE"]
    return missing


def _is_real_flaw(logical_flaw_raw: str) -> bool:
    """Check if logical_flaw is a real flaw, not just 'incomplete' noise.

    The 4B model writes 'התשובה חסרה' (answer is incomplete) as a logical
    flaw, which is not a real flaw — just brevity. Filter those out.
    """
    if not logical_flaw_raw:
        return False
    upper = logical_flaw_raw.upper()
    if upper == "NONE":
        return False
    # Filter out 'incomplete'/'brevity' noise from 4B model
    lower = logical_flaw_raw.lower()
    _NOISE = ("חסר", "incomplete", "brevity", "short", "brief", "missing detail", "לא מלא")
    if any(n in lower for n in _NOISE):
        logger.info("[CRITIC] Logical flaw '%s' is brevity noise — ignoring.", logical_flaw_raw[:60])
        return False
    return True


def _reason_is_brevity(reason: str) -> bool:
    """Check if the CoVe reason field is just a brevity complaint.

    The 4B model often puts 'התשובה חסרה כל תוכן' in REASON (not LOGICAL_FLAW),
    which means the draft is too short — not a real logical flaw.
    """
    if not reason:
        return False
    lower = reason.lower()
    _BREVITY = ("חסר", "incomplete", "brevity", "לא מלא", "short", "brief", "missing detail")
    if any(n in lower for n in _BREVITY):
        logger.info("[CRITIC] Reason '%s' is brevity complaint — ignoring flaw.", reason[:60])
        return True
    return False


def _resolve_verdict(parsed: dict, critic_response: str) -> bool | None:
    """Extract verdict from parsed CoVe, with legacy fallback."""
    verdict = parsed.get("verdict")
    if verdict is not None:
        return verdict
    first = critic_response.strip().splitlines()[0].strip()
    upper = first.upper()
    if "FAIL" in upper:
        return False
    if "PASS" in upper:
        return True
    logger.warning("[CRITIC] Unparseable verdict %r -- fail-closed (REJECT).", first[:200])
    return None


def _check_contradiction(verdict: bool, missing_facts: list[str], has_flaw: bool, reason: str) -> bool:
    """Apply contradiction heuristics; return final verdict.

    Bidirectional:
    - PASS with missing/flaw → flip to FAIL (false-PASS backstop).
    - FAIL with no missing, no flaw, and empty reason → flip to PASS
      (false-FAIL backstop: the 4B model often emits a bare "FAIL"
      with no supporting evidence, causing spurious rejections that
      trigger the circuit-breaker degrade path).
    """
    if verdict and (missing_facts or has_flaw):
        logger.warning(
            "[CRITIC] CoVe contradiction: verdict=PASS but missing_facts=%d flaw=%s. Flipping to FAIL.",
            len(missing_facts),
            has_flaw,
        )
        verdict = False
    if verdict and reason:
        rl = reason.lower()
        if any(neg in rl for neg in _NEGATIVE_HE):
            logger.warning("[CRITIC] Negative-phrase backstop flipped PASS→FAIL: %r", reason[:80])
            verdict = False
    if not verdict and not missing_facts and not has_flaw and not reason.strip():
        logger.warning(
            "[CRITIC] False-FAIL backstop: verdict=FAIL but missing=0 flaw=False reason=''. "
            "Flipping to PASS — bare FAIL with no justification."
        )
        verdict = True
    return verdict


def _build_fb_reason(reason: str, has_flaw: bool, logical_flaw_raw: str, missing_facts: list[str]) -> str:
    """Build feedback reason string."""
    fb_reason = reason
    if has_flaw and logical_flaw_raw not in fb_reason:
        fb_reason = f"{fb_reason} | פגם לוגי: {logical_flaw_raw}" if fb_reason else f"פגם לוגי: {logical_flaw_raw}"
    if missing_facts and not fb_reason:
        fb_reason = f"טענות ללא ראיה: {'; '.join(missing_facts[:3])}"
    return fb_reason


async def _run_critic_evaluation(
    original_query: str,
    tool_data: str,
    draft_answer: str,
    engine,
    tools_used: list[dict] | None = None,
) -> tuple[bool, dict]:
    """CoVe evaluation: claim extraction + evidence grounding + logic audit.

    Returns (is_valid, structured_feedback) with populated claims/missing_facts/logical_flaw.

    PRE-FILTER: _audit_tool_claims runs BEFORE the LLM critic. If the draft
    references tools that never executed (e.g., get_event_log was stripped by
    the planner but the draft says "בוצעו בדיקות על ידי get_event_log"), the
    verdict is forced to FAIL — the 4B CoVe model cannot reliably detect this
    because it sees tool_data but doesn't know which tools produced it.
    """
    if not tool_data.strip():
        return True, _mk_critic_fb("", is_pass=True)

    # ── Deterministic tool-claim audit (pre-LLM) ──
    fabricated = _audit_tool_claims(draft_answer, tools_used or [])
    if fabricated:
        fb = (
            f"הדוח מזכיר כלים שלא הופעלו: {', '.join(fabricated)}. "
            "אסור לטעון שבוצעה בדיקה בכלי שלא רץ. הסר את ההתייחסות או ציין 'לא בוצע'."
        )
        logger.warning(
            "[CRITIC] Tool-claim audit FAIL: draft references %d tool(s) that never ran: %s",
            len(fabricated),
            fabricated,
        )
        return False, _mk_critic_fb(
            fb,
            is_pass=False,
            logical_flaw=f"Fabricated tool references: {', '.join(fabricated)}",
        )

    # ── Deterministic entity audit (pre-LLM) — ZERO TOLERANCE for hallucinated IOCs ──
    # The 4B CoVe model has "resolution blindness": it verifies macro-claims
    # (CPU is 20%) but cannot cross-check micro-entities (PID 12847) against
    # tool data. This regex-based check catches hallucinated PIDs, paths, IPs.
    # v2: net_baseline membership is NOT a provenance exemption — an IP cited
    # in the draft MUST appear in the current tool_data, even if it's a known
    # benign IP from a previous hunt. Stale baseline memory ≠ current evidence.
    ent_pass, ent_fb, ent_flaw = _check_entity_audit(draft_answer, tool_data, set())
    if not ent_pass:
        logger.warning("[CRITIC] Entity audit FAIL: %s", ent_flaw)
        return False, _mk_critic_fb(ent_fb, is_pass=False, logical_flaw=ent_flaw)

    critic_input = (
        f"Original user question: {original_query}\n\n"
        f"<TOOL_DATA>\n"
        f"{tool_data}\n"
        f"</TOOL_DATA>\n\n"
        f"<DRAFT_ANSWER>\n"
        f"{draft_answer}\n"
        f"</DRAFT_ANSWER>\n\n"
        f"The text inside <TOOL_DATA> is RAW EVIDENCE from system tools. "
        f"Do NOT continue or repeat it. Do NOT echo field names like 'User:' or 'Account Name:'. "
        f"You MUST output the CoVe format (VERDICT/CLAIMS/EVIDENCE/LOGICAL_FLAW/REASON) — nothing else."
    )

    try:
        critic_response = await engine.complete(
            system_prompt=_COVE_SYSTEM,
            user_input=critic_input,
            temperature=0.0,
            max_tokens=256,
        )
    except Exception as exc:
        logger.warning("[CRITIC] CoVe call failed: %s", exc)
        return False, _mk_critic_fb(
            "Critic evaluation call failed — retry with explicit tool data.",
            is_pass=False,
            logical_flaw="LLM call failed",
        )

    logger.debug("[CRITIC] CoVe raw response: %r", critic_response[:500])

    parsed = _parse_cove(critic_response)
    if not parsed.get("parse_ok"):
        logger.warning("[CRITIC] Empty response -- fail-closed (REJECT).")
        return False, _mk_critic_fb("ה-Critic החזיר תשובה ריקה.", is_pass=False)

    verdict = _resolve_verdict(parsed, critic_response)
    if verdict is None:
        return False, _mk_critic_fb("ה-Critic החזיר תשובה לא מובנת.", is_pass=False)

    claims = parsed.get("claims", [])
    evidence = parsed.get("evidence", [])
    logical_flaw_raw = parsed.get("logical_flaw", "")
    reason = parsed.get("reason", "")

    missing_facts = _match_claims_to_evidence(claims, evidence, tool_data)
    has_flaw = _is_real_flaw(logical_flaw_raw) and not _reason_is_brevity(reason)

    # ── Speculation guard: prevent False-FAIL backstop on speculative drafts ──
    has_flaw, logical_flaw_raw = _apply_speculation_guard(draft_answer, tool_data, has_flaw, logical_flaw_raw)

    verdict = _check_contradiction(verdict, missing_facts, has_flaw, reason)
    fb_reason = _build_fb_reason(reason, has_flaw, logical_flaw_raw, missing_facts)

    feedback = _mk_critic_fb(
        fb_reason,
        is_pass=verdict,
        claims=claims,
        missing_facts=missing_facts,
        logical_flaw=logical_flaw_raw if has_flaw else "",
    )

    logger.info(
        "[CRITIC] CoVe: pass=%s claims=%d missing=%d flaw=%s reason=%r",
        verdict,
        len(claims),
        len(missing_facts),
        has_flaw,
        reason[:80],
    )
    return verdict, feedback


def _mk_critic_fb(
    reason: str = "",
    is_pass: bool = False,
    claims: list[str] | None = None,
    missing_facts: list[str] | None = None,
    logical_flaw: str = "",
) -> dict:
    """Build backward-compatible feedback dict for _critic.py.

    Optional kwargs (claims/missing_facts/logical_flaw) default to empty —
    all existing call sites remain valid.
    """
    return {
        "pass": is_pass,
        "reason": reason,
        "action_required": "PASS" if is_pass else "RETRY_WITH_FEEDBACK",
        "feedback_to_agent": reason,
        "accuracy_score": 100 if is_pass else 0,
        "completeness_score": 100 if is_pass else 0,
        "missing_facts": missing_facts or [],
        "extracted_claims": claims or [],
        "logical_flaw": logical_flaw,
    }
