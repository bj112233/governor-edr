# services/agent/bypass/elaborate.py
import logging
import re
from typing import Optional

from services.agent.context import get_last_document
from services.bot_memory import async_store_conversation, get_memory_service

logger = logging.getLogger(__name__)

_ELABORATE_INTENT_RE = re.compile(
    r"^\s*(?:"
    r"תפרט|פרט|הרחב|הסבר עוד|הסבר|המשך|תמשיך|"
    r"עוד פרטים|הוסף פרטים|תן דוגמה|פרט עוד|"
    r"נתח|תנתח|בצע ניתוח|לנתח|"
    r"elaborate|expand|more details|tell me more|continue|go on"
    r")\s*[\.\!\?…]*\s*$",
    re.IGNORECASE,
)
_ELABORATE_MAX_QUESTION_CHARS = 40

_ELABORATE_SYSTEM_PROMPT = (
    "אתה ממשיך שיחה קודמת ומפרט/מרחיב על תשובה שכבר נתת. "
    "אסור לבקש מהמשתמש לבחור קטגוריה (מטבע/מניה/מרחק/חדשות וכד'). "
    "אסור להגיד 'מה בדיוק אתה רוצה' או לבקש הבהרות גנריות. "
    "התבסס אך ורק על המסמך, השאלה הקודמת והתשובה הקודמת שמופיעים בקלט. "
    "תן פירוט טכני, מהותי וקונקרטי בעברית — נקודה אחר נקודה. "
    "אם המידע אינו מספיק לפירוט נוסף — אמור זאת במפורש."
)
_ELABORATE_MAX_DOC_CHARS = 8000
_ELABORATE_MAX_PREV_RESP_CHARS = 3000
_ELABORATE_TIMEOUT_S = 240.0

_ANALYSIS_ONLY_RE = re.compile(r"נתח|תנתח|בצע ניתוח|לנתח", re.IGNORECASE)

# A-4: Template-based elaborate thresholds
_TEMPLATE_MIN_DOC_RATIO = 1.5  # doc must be 1.5x longer than response to have room for elaboration
_TEMPLATE_MAX_NEW_SECTIONS = 3  # append up to 3 new document sections


def _try_template_elaborate(prev_response: str, last_doc: str) -> str | None:
    """Deterministic elaboration for structured responses (zero LLM cost).

    If the previous response has markdown ``##`` headers and the source
    document is significantly longer, append document sections that were
    NOT included in the original response.  Returns ``None`` when no
    structured match is possible → caller falls through to the LLM path.
    """
    if not last_doc or "##" not in prev_response:
        return None
    if len(last_doc) <= len(prev_response) * _TEMPLATE_MIN_DOC_RATIO:
        return None
    doc_sections = re.split(r"\n(?=##\s)", last_doc)
    response_lower = prev_response.lower()
    new_sections: list[str] = []
    for section in doc_sections:
        header = section.split("\n", 1)[0].lower()
        if section.strip() and header not in response_lower:
            new_sections.append(section.strip())
    if not new_sections:
        return None
    return prev_response + "\n\n" + "\n\n".join(new_sections[:_TEMPLATE_MAX_NEW_SECTIONS])


def _detect_elaborate_query(q: str) -> bool:
    """True only for short, exact follow-up requests like 'תפרט', 'elaborate'."""
    if not q:
        return False
    if len(q) > _ELABORATE_MAX_QUESTION_CHARS:
        return False
    return bool(_ELABORATE_INTENT_RE.match(q.strip()))


def _find_usable_prev_turn(recent) -> object | None:
    """Find the most recent meaningful turn.

    Skips empty/error responses and avoids recursion on a previous elaboration
    request. Returns None if no usable turn exists.
    """
    for entry in recent:
        if not entry.response or len(entry.response.strip()) < 20:
            continue
        if entry.response.startswith(("⚠️", "❌")):
            continue
        if entry.query and _detect_elaborate_query(entry.query):
            continue
        return entry
    return None


def _build_elaborate_sections(user_question: str, prev_query: str, prev_response: str, last_doc: str) -> str:
    """Assemble the LLM user_input from document + previous turn + request."""
    if len(prev_response) > _ELABORATE_MAX_PREV_RESP_CHARS:
        prev_response = prev_response[-_ELABORATE_MAX_PREV_RESP_CHARS:]
    if len(last_doc) > _ELABORATE_MAX_DOC_CHARS:
        last_doc = last_doc[:_ELABORATE_MAX_DOC_CHARS]

    sections: list[str] = []
    if last_doc:
        sections.append(f"== המסמך המקורי ==\n{last_doc}")
    if prev_query:
        sections.append(f"== השאלה הקודמת ==\n{prev_query}")
    sections.append(f"== התשובה הקודמת שלי ==\n{prev_response}")
    sections.append(f"== בקשת ההמשך מהמשתמש ==\n{user_question}")
    sections.append(
        "== ההנחיה ==\nהרחב את התשובה הקודמת. תן פירוט קונקרטי וטכני של "
        "כל נקודה. אל תבקש הבהרות. אל תציע לבחור קטגוריה."
    )
    return "\n\n".join(sections)


async def _run_elaborate_llm(user_input: str) -> str | None:
    """Call the LLM bridge with the elaborate system prompt. None on hard failure."""
    from services.llm_bridge import LLMBridge

    try:
        bridge = LLMBridge.get_instance()
        response = await bridge.complete(
            system_prompt=_ELABORATE_SYSTEM_PROMPT,
            user_input=user_input,
            temperature=0.3,
            max_tokens=2048,
            timeout=_ELABORATE_TIMEOUT_S,
        )
    except Exception as e:
        logger.error(f"[AGENT] Elaborate bypass failed: {e}")
        return f"⚠️ שגיאה בהפקת פירוט: {e}"

    final = (response or "").strip() or "⚠️ לא הופק פירוט."
    try:
        await async_store_conversation(user_input, final)
    except Exception as e:
        logger.debug(f"[AGENT] Memory storage failed (elaborate bypass): {e}")
    return final


async def _direct_elaborate_bypass(user_question: str) -> str | None:
    """Deterministic elaboration on the previous assistant turn.

    Returns `None` if no usable prior turn exists — caller falls through to
    the normal LLM agent loop. Otherwise returns a fully composed answer
    that elaborates on the previous topic, bypassing the skill router.
    """
    try:
        svc = get_memory_service()
        recent = await svc.get_recent(5, "conversation")
    except Exception as e:
        logger.warning(f"[AGENT] Elaborate bypass: memory recall failed: {e}")
        return None

    prev = _find_usable_prev_turn(recent)
    if prev is None:
        logger.info("[AGENT] Elaborate bypass: no usable prior turn → fallback")
        return None

    # ANTI-SHADOWING: analysis keywords require a document context.
    # If user said "נתח" / "תנתח" etc. with no document, fall through
    # so the ReAct agent can route to OSINT/finance skills.
    if _ANALYSIS_ONLY_RE.search(user_question or "") and not get_last_document():
        logger.info("[AGENT] Elaborate bypass: analysis intent with no document → fall through")
        return None

    last_doc = get_last_document() or ""
    prev_query = (getattr(prev, "query", "") or "").strip()
    prev_response = (getattr(prev, "response", "") or "").strip()

    # A-4: Try deterministic template-based elaboration first (zero LLM cost).
    template_result = _try_template_elaborate(prev_response, last_doc)
    if template_result is not None:
        logger.info("[AGENT] Elaborate bypass: template expansion (zero LLM) — %d chars", len(template_result))
        try:
            await async_store_conversation(user_question, template_result)
        except Exception as e:
            logger.debug(f"[AGENT] Memory storage failed (template elaborate): {e}")
        return template_result

    logger.info(
        f"[AGENT] Elaborate bypass: prev_q={len(prev_query)} prev_resp={len(prev_response)} doc={len(last_doc)} chars"
    )

    user_input = _build_elaborate_sections(user_question, prev_query, prev_response, last_doc)
    return await _run_elaborate_llm(user_input)
