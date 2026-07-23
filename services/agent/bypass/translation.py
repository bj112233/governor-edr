"""Translation bypass router — thin layer that detects translation/summarization requests."""

import importlib.util
import logging
import re
from pathlib import Path

from services.agent.bypass._translation_handlers import llm_summarize_doc, llm_translate_doc
from services.agent.bypass._translation_utils import split_for_translation
from services.agent.bypass.currency import _SUMMARIZE_INTENT_RE
from services.agent.context import get_last_document
from services.bot_memory import async_store_conversation, get_memory_service

logger = logging.getLogger(__name__)

# Real translator skill integration
_translator_path = (
    Path(__file__).parent.parent.parent.parent / "skills" / "translator-skill" / "scripts" / "translator.py"
)
_real_translator = None


def _get_real_translator():
    global _real_translator
    if _real_translator is None:
        spec = importlib.util.spec_from_file_location("translator_skill", _translator_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load translator skill from {_translator_path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _real_translator = mod.MultiBackendTranslator()
    return _real_translator


_LANG_MAP = {
    "עברית": "he",
    "hebrew": "he",
    "he": "he",
    "אנגלית": "en",
    "english": "en",
    "en": "en",
    "צרפתית": "fr",
    "french": "fr",
    "fr": "fr",
    "ספרדית": "es",
    "spanish": "es",
    "es": "es",
    "גרמנית": "de",
    "german": "de",
    "de": "de",
    "רוסית": "ru",
    "russian": "ru",
    "ru": "ru",
    "ערבית": "ar",
    "arabic": "ar",
    "ar": "ar",
}


def _extract_target_lang(q: str) -> str:
    for name, code in _LANG_MAP.items():
        if name in q.lower():
            return code
    return "he"


def _extract_explicit_text(q: str) -> str | None:
    if ":" in q:
        return q.split(":", 1)[1].strip()
    return None


_TRANSLATION_BYPASS_KEYWORDS: frozenset[str] = frozenset(["תרגם", "תרגום", "translate", "translation"])


async def _translate_explicit_text(user_question: str, explicit_text: str, target_lang: str) -> str:
    """CASE 1: Translate explicit text via real translator skill."""
    logger.info(f"[AGENT] Translation bypass: explicit text, target={target_lang}")
    try:
        translator = _get_real_translator()
        result, backend = translator.translate(explicit_text, source="auto", target=target_lang)
        final = result.strip() or "⚠️ לא הופק תרגום."
    except Exception as e:
        logger.error(f"[AGENT] Real translator failed: {e}")
        final = f"⚠️ שגיאה בתרגום: {e}"
    try:
        await async_store_conversation(user_question, final)
    except Exception as e:
        logger.debug(f"[AGENT] Memory storage failed (translation bypass): {e}")
    return final


def _format_recent_context(recent: list) -> str:
    """Format recent conversation entries into a context string for summarization."""
    context_lines: list[str] = []
    for entry in recent:
        if entry.query:
            context_lines.append(f"משתמש: {entry.query.strip()}")
        if entry.response:
            resp = entry.response.strip()
            if len(resp) > 400:
                resp = resp[:400] + "..."
            context_lines.append(f"סוכן: {resp}")
    return "\n\n".join(reversed(context_lines))


async def _summarize_conversation(user_question: str, context_text: str) -> str:
    """LLM-summarize recent conversation context."""
    from services.llm_bridge import LLMBridge

    bridge = LLMBridge.get_instance()
    final = await bridge.complete(
        system_prompt=(
            "אתה מסכם מסמכים טכניים בעברית. הפק סיכום ענייני וקצר: התמקד במידע "
            "הטכני המהותי. שמר מונחי סייבר באנגלית: MITRE ATT&CK, TTP, IOC, "
            "Encoded Commands, Execution Policy Bypass, Defense Evasion, Persistence. "
            "דלג על תוכן עניינים, היסטוריית גרסאות, מילון, סימני מסחר וקרדיטים."
        ),
        user_input=(
            "סכם את השיחה האחרונה בעברית בכ־5-10 שורות, התמקד במידע "
            "המהותי והתשובות שהסוכן נתן:\n\n" + context_text
        ),
        temperature=0.2,
        max_tokens=2048,
        timeout=240.0,
    )
    return (final or "").strip() or "⚠️ לא הופק סיכום."


async def _handle_summarize_bypass(user_question: str) -> str | None:
    """CASE 2: Summarize intent — document or conversation context."""
    last_doc = get_last_document()
    if last_doc:
        return await llm_summarize_doc(user_question, last_doc)

    # TASK 4 FALLBACK: no document → summarize last N conversation messages
    logger.info("[AGENT] Summarize bypass: no document, fetching conversation context")
    try:
        svc = get_memory_service()
        recent = await svc.get_recent(10, "conversation")
    except Exception as e:
        logger.warning(f"[AGENT] Summarize fallback: memory recall failed: {e}")
        return None  # fall through to ReAct

    if not recent:
        return None  # fall through to ReAct

    context_text = _format_recent_context(recent)
    try:
        final = await _summarize_conversation(user_question, context_text)
    except Exception as e:
        logger.error(f"[AGENT] Conversation summary failed: {e}")
        return f"⚠️ שגיאה בסיכום שיחה: {e}"
    try:
        await async_store_conversation(user_question, final)
    except Exception as e:
        logger.debug(f"[AGENT] Memory storage failed (summarize fallback): {e}")
    return final


async def _direct_translation_bypass(user_question: str) -> str | None:
    """Translate (or summarize) using real translator skill or LLM fallback.

    Intent detection:
      - Explicit text after colon → translate via real translator skill.
      - "סכם"/"summarize" + document → per-chunk LLM summarization.
      - No document + summarize → summarize last N messages from DB.
      - Otherwise → translate last document (or fall through if none).
    """
    target_lang = _extract_target_lang(user_question)
    explicit_text = _extract_explicit_text(user_question)
    summarize_mode = bool(_SUMMARIZE_INTENT_RE.search(user_question or ""))

    # ── CASE 1: Explicit text provided → translate via real skill ──
    if explicit_text:
        return await _translate_explicit_text(user_question, explicit_text, target_lang)

    # ── CASE 2: Summarize intent ──
    if summarize_mode:
        return await _handle_summarize_bypass(user_question)

    # ── CASE 3: Translate last document ──
    last_doc = get_last_document()
    if not last_doc:
        return None  # fall through to ReAct agent

    return await llm_translate_doc(user_question, last_doc, target_lang)
