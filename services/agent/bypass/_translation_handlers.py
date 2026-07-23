"""Translation handlers — LLM-based translation and summarization with chunking."""

import logging
import re

from services.bot_memory import async_store_conversation
from services.llm_bridge import LLMBridge

from ._translation_utils import split_for_translation, strip_document_noise

logger = logging.getLogger(__name__)

# Translation tuning constants
_TRANSLATION_CHUNK_CHARS = 3000
_TRANSLATION_TIMEOUT_S = 240.0
_TRANSLATION_MAX_TOKENS = 2048
_TRANSLATION_DOC_HARD_CAP = 24000  # ~8 chunks; protects against runaway PDFs

# A-3: Extractive summarization thresholds
_EXTRACTIVE_SHORT_DOC_CHARS = 1000  # below this → return as-is (already concise)
_EXTRACTIVE_MAX_SENTENCES = 5  # lead-N sentences for medium docs


def _extractive_summary(text: str, max_sentences: int = _EXTRACTIVE_MAX_SENTENCES) -> str:
    """Extractive summarization — top-N sentences by word frequency scoring.

    Zero LLM cost. Falls back to returning the text as-is if it's too short
    or has too few sentences to meaningfully summarize.
    """
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    if len(sentences) <= max_sentences:
        return text.strip()
    words = re.findall(r"\w+", text.lower())
    freq: dict[str, int] = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    scored = []
    for i, s in enumerate(sentences):
        s_words = re.findall(r"\w+", s.lower())
        score = sum(freq.get(w, 0) for w in s_words) / max(len(s_words), 1)
        scored.append((score, i, s))
    top = sorted(scored, key=lambda x: (-x[0], x[1]))[:max_sentences]
    top.sort(key=lambda x: x[1])
    return " ".join(s for _, _, s in top)

# System prompts
_CYBER_TERMS_ANCHOR = (
    "שמר מונחי סייבר באנגלית: MITRE ATT&CK, TTP, IOC, Encoded Commands, "
    "Execution Policy Bypass, Defense Evasion, Persistence, Lateral Movement, Privilege Escalation."
)
_TRANSLATE_SYSTEM_PROMPT = (
    "אתה מתרגם טקסט לעברית. תרגם בצורה ברורה ומדויקת. "
    f"שמר על מונחים טכניים באנגלית כשצריך. {_CYBER_TERMS_ANCHOR} "
    "אל תוסיף הערות או הקדמות — רק התרגום."
)
_SUMMARIZE_SYSTEM_PROMPT = (
    "אתה מסכם מסמכים טכניים בעברית. הפק סיכום ענייני וקצר: התמקד במידע "
    "הטכני המהותי (מאפיינים, ספרות, יישומים, מגבלות). דלג על תוכן עניינים, "
    f"היסטוריית גרסאות, מילון, סימני מסחר וקרדיטים. {_CYBER_TERMS_ANCHOR} "
    "אל תכתוב הקדמות — ישר לעניין."
)
_CONSOLIDATE_SYSTEM_PROMPT = (
    "אתה מאחד סיכומים חלקיים לסיכום אחיד וקוהרנטי בעברית. "
    "הסר חזרות, ארגן לפי נושאים טכניים, ושמר על דיוק. "
    f"{_CYBER_TERMS_ANCHOR} הימנע מתוכן עניינים ומהיסטוריית גרסאות."
)


_LANG_NAMES = {
    "he": "עברית",
    "en": "אנגלית",
    "fr": "צרפתית",
    "es": "ספרדית",
    "de": "גרמנית",
    "ru": "רוסית",
    "ar": "ערבית",
}


def _truncate_text(text: str) -> tuple[str, bool]:
    """Truncate to hard cap. Returns (text, truncated_flag)."""
    if len(text) > _TRANSLATION_DOC_HARD_CAP:
        return text[:_TRANSLATION_DOC_HARD_CAP], True
    return text, False


def _dedupe_parts(parts: list[str]) -> list[str]:
    """Deduplicate summary parts by first-160-chars key."""
    import re

    unique: list[str] = []
    seen: set[str] = set()
    for p in parts:
        if not p:
            continue
        key = re.sub(r"\s+", " ", p).strip()[:160]
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)
    return unique


async def _process_chunks_translate(bridge, chunks: list[str], lang_name: str) -> list[str]:
    """LLM I/O: translate each chunk."""
    parts: list[str] = []
    for idx, chunk in enumerate(chunks, 1):
        try:
            part = await bridge.complete(
                system_prompt=_TRANSLATE_SYSTEM_PROMPT,
                user_input=f"תרגם את הטקסט הזה ל{lang_name}:\n\n{chunk}",
                temperature=0.1,
                max_tokens=_TRANSLATION_MAX_TOKENS,
                timeout=_TRANSLATION_TIMEOUT_S,
            )
        except Exception as e:
            logger.error(f"[AGENT] translate chunk {idx}/{len(chunks)} failed: {e}")
            part = f"[שגיאה בקטע {idx}: {e}]"
        parts.append(part.strip())
    return parts


async def _process_chunks_summarize(bridge, chunks: list[str]) -> list[str]:
    """LLM I/O: summarize each chunk."""
    parts: list[str] = []
    for idx, chunk in enumerate(chunks, 1):
        try:
            part = await bridge.complete(
                system_prompt=_SUMMARIZE_SYSTEM_PROMPT,
                user_input=(
                    "סכם בעברית את הקטע הבא בכ־5-10 שורות, התמקד במידע טכני מהותי "
                    "ודלג על תוכן עניינים והיסטוריית גרסאות:\n\n{chunk}"
                ),
                temperature=0.2,
                max_tokens=_TRANSLATION_MAX_TOKENS,
                timeout=_TRANSLATION_TIMEOUT_S,
            )
        except Exception as e:
            logger.error(f"[AGENT] summarize chunk {idx}/{len(chunks)} failed: {e}")
            part = f"[שגיאה בקטע {idx}: {e}]"
        parts.append(part.strip())
    return parts


async def _consolidate_summaries(bridge, unique_parts: list[str]) -> str:
    """LLM I/O: consolidate multiple summaries into one."""
    merged = "\n\n".join(unique_parts)
    try:
        final = await bridge.complete(
            system_prompt=_CONSOLIDATE_SYSTEM_PROMPT,
            user_input=("אחד את הסיכומים החלקיים הבאים לסיכום אחד קוהרנטי וממוקד בעברית:\n\n" + merged),
            temperature=0.2,
            max_tokens=4096,
            timeout=_TRANSLATION_TIMEOUT_S,
        )
        return final.strip() or merged
    except Exception as e:
        logger.warning(f"[AGENT] Summary consolidation failed: {e}; using concatenated")
        return merged


async def llm_translate_doc(user_question: str, text: str, target_lang: str) -> str:
    """LLM-based document translation (chunked)."""
    text, truncated = _truncate_text(text)
    chunks = split_for_translation(text, _TRANSLATION_CHUNK_CHARS)
    logger.info(f"[AGENT] LLM translate: doc_chars={len(text)} chunks={len(chunks)}")
    if not chunks:
        return "⚠️ המסמך ריק — אין מה לתרגם."

    try:
        bridge = LLMBridge.get_instance()
        lang_name = _LANG_NAMES.get(target_lang, target_lang)
        parts = await _process_chunks_translate(bridge, chunks, lang_name)
        result = "\n\n".join(p for p in parts if p)
        if truncated:
            result += f"\n\n⚠️ הערה: המסמך נחתך ל{_TRANSLATION_DOC_HARD_CAP} תווים."
        final = result or "⚠️ לא הופק פלט."
    except Exception as e:
        logger.error(f"[AGENT] Translation failed: {e}")
        final = f"⚠️ שגיאה בעיבוד: {e}"

    try:
        await async_store_conversation(user_question, final)
    except Exception as e:
        logger.debug(f"[AGENT] Memory storage failed (translation): {e}")
    return final


async def llm_summarize_doc(user_question: str, text: str) -> str:
    """LLM-based document summarization (chunked + consolidate)."""
    before = len(text)
    text = strip_document_noise(text)
    logger.info(f"[AGENT] Doc noise stripped: {before} → {len(text)} chars (removed {before - len(text)})")

    text, truncated = _truncate_text(text)
    chunks = split_for_translation(text, _TRANSLATION_CHUNK_CHARS)
    logger.info(f"[AGENT] LLM summarize: doc_chars={len(text)} chunks={len(chunks)}")
    if not chunks:
        return "⚠️ המסמך ריק — אין מה לסכם."

    # A-3: Short documents don't need LLM — extractive or as-is saves GPU cycles.
    if len(text) < _EXTRACTIVE_SHORT_DOC_CHARS:
        logger.info("[AGENT] Summarize: short doc (%d chars) — returning as-is (zero LLM)", len(text))
        final = text.strip()
        try:
            await async_store_conversation(user_question, final)
        except Exception as e:
            logger.debug(f"[AGENT] Memory storage failed (summarize short): {e}")
        return final
    if len(chunks) == 1:
        logger.info("[AGENT] Summarize: single chunk (%d chars) — extractive summary (zero LLM)", len(text))
        final = _extractive_summary(text)
        try:
            await async_store_conversation(user_question, final)
        except Exception as e:
            logger.debug(f"[AGENT] Memory storage failed (summarize extractive): {e}")
        return final

    try:
        bridge = LLMBridge.get_instance()
        parts = await _process_chunks_summarize(bridge, chunks)
        unique_parts = _dedupe_parts(parts)

        if len(unique_parts) > 1:
            result = await _consolidate_summaries(bridge, unique_parts)
        else:
            result = "\n\n".join(unique_parts)

        if truncated:
            result += f"\n\n⚠️ הערה: המסמך נחתך ל{_TRANSLATION_DOC_HARD_CAP} תווים."
        final = result or "⚠️ לא הופק פלט."
    except Exception as e:
        logger.error(f"[AGENT] Summarize failed: {e}")
        final = f"⚠️ שגיאה בעיבוד: {e}"

    try:
        await async_store_conversation(user_question, final)
    except Exception as e:
        logger.debug(f"[AGENT] Memory storage failed (summarize): {e}")
    return final
