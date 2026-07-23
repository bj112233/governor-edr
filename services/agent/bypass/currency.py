# services/agent/bypass/currency.py
import asyncio
import logging
import re

from services.bot_memory import async_store_conversation
from services.skills_engine import get_skills_engine

from .currency_lexicon import (
    _ADJECTIVE_MERGE_GAP,
    _CURRENCY_ADJECTIVE_KEYWORDS,
    _CURRENCY_AMOUNT_RE,
    _CURRENCY_CODES_RE,
    _CURRENCY_KEYWORDS_EN,
    _CURRENCY_KEYWORDS_HE,
    _CURRENCY_MAP,
    _CURRENCY_SYMBOL_MAP,
    _CURRENCY_SYMBOLS,
    _ELABORATE_INTENT_RE,
    _ELABORATE_MAX_QUESTION_CHARS,
    _SUMMARIZE_INTENT_RE,
    _TRANSLATION_INTENT_RE,
)

logger = logging.getLogger(__name__)


def _detect_currency_query(q: str) -> bool:
    """Return True iff query is a currency/exchange request.

    Hardened against false positives in technical documents (datasheets, etc.).
    Rules:
      1. Hebrew currency lexemes fire on their own (domain-specific).
      2. English fires only on phrase-level triggers (e.g. "exchange rate")
         OR on a word-bounded ISO currency code OR a currency symbol.
      3. Translation intent ("תרגם"/"translate") suppresses currency detection
         entirely — translation of a previous document takes precedence.
    """
    if not q:
        return False
    if _TRANSLATION_INTENT_RE.search(q):
        return False
    if _SUMMARIZE_INTENT_RE.search(q):
        return False
    if _ELABORATE_INTENT_RE.search(q):
        return False
    q_low = q.lower()
    if any(kw in q_low for kw in _CURRENCY_KEYWORDS_HE):
        return True
    if any(kw in q_low for kw in _CURRENCY_KEYWORDS_EN):
        return True
    if _CURRENCY_CODES_RE.search(q_low):
        return True
    if any(sym in q for sym in _CURRENCY_SYMBOLS):
        return True
    return False


def _scan_lexicon(q_low: str, claimed: list[tuple[int, int]]) -> list[tuple[int, int, str, bool]]:
    """Scan lexicon (multi-word + single-word + ISO codes). Returns raw occurrences."""
    raw: list[tuple[int, int, str, bool]] = []

    def _claim(start: int, end: int) -> bool:
        for cs, ce in claimed:
            if start < ce and end > cs:
                return False
        claimed.append((start, end))
        return True

    for keyword, code in _CURRENCY_MAP.items():
        kw_low = keyword.lower()
        is_adj = kw_low in _CURRENCY_ADJECTIVE_KEYWORDS
        start = 0
        while True:
            idx = q_low.find(kw_low, start)
            if idx == -1:
                break
            end = idx + len(kw_low)
            if kw_low.isalpha() and len(kw_low) <= 4 and kw_low.isascii():
                left_ok = idx == 0 or not q_low[idx - 1].isalnum()
                right_ok = end == len(q_low) or not q_low[end].isalnum()
                if not (left_ok and right_ok):
                    start = end
                    continue
            if _claim(idx, end):
                raw.append((idx, end, code, is_adj))
            start = end
    return raw


def _scan_symbols(q: str, claimed: list[tuple[int, int]]) -> list[tuple[int, int, str, bool]]:
    """Scan currency symbols. Returns raw occurrences."""
    raw: list[tuple[int, int, str, bool]] = []

    def _claim(start: int, end: int) -> bool:
        for cs, ce in claimed:
            if start < ce and end > cs:
                return False
        claimed.append((start, end))
        return True

    for sym, code in _CURRENCY_SYMBOL_MAP.items():
        start = 0
        while True:
            idx = q.find(sym, start)
            if idx == -1:
                break
            end = idx + len(sym)
            if _claim(idx, end):
                raw.append((idx, end, code, False))
            start = end
    return raw


def _merge_adjectives(raw: list[tuple[int, int, str, bool]], q: str) -> list[tuple[int, int, str, bool]]:
    """Merge country adjectives into preceding nouns (e.g. "דולר קנדי" → CAD)."""
    merged: list[tuple[int, int, str, bool]] = []
    i = 0
    while i < len(raw):
        cur = raw[i]
        if (
            i + 1 < len(raw)
            and raw[i + 1][3]  # next is adjective
            and not cur[3]  # current is noun
            and raw[i + 1][0] - cur[1] <= _ADJECTIVE_MERGE_GAP
        ):
            gap_text = q[cur[1] : raw[i + 1][0]]
            if "ל" not in gap_text:
                merged.append((cur[0], raw[i + 1][1], raw[i + 1][2], False))
                i += 2
                continue
        merged.append(cur)
        i += 1
    return merged


def _find_currency_occurrences(q: str) -> list[tuple[int, str]]:
    """Return all (offset, ISO_code) occurrences ordered by position.

    Detection sources, in priority of accuracy (per-position highest wins):
      1. Multi-word Hebrew expressions (longest match first via map order).
      2. Single-word Hebrew lexemes (incl. country adjectives as fallback).
      3. ISO codes with word boundaries (case-insensitive).
      4. Currency symbols.

    Overlapping matches are deduplicated by offset (first detector to claim
    an offset wins; the map iterates longest→shortest so multi-word phrases
    eclipse their single-word substrings).

    Post-processing: when a country adjective appears within
    `_ADJECTIVE_MERGE_GAP` chars after a generic currency noun (e.g.
    "דולר הקנדי"), merge them — adjective code wins. This collapses
    `[USD@5, CAD@12]` into a single `[CAD@5]` entry.
    """
    if not q:
        return []
    q_low = q.lower()
    claimed: list[tuple[int, int]] = []

    raw = _scan_lexicon(q_low, claimed) + _scan_symbols(q, claimed)
    raw.sort(key=lambda t: t[0])
    merged = _merge_adjectives(raw, q)

    return [(off, code) for off, _end, code, _adj in merged]


def _parse_currency_query(q: str) -> tuple[float | None, str | None, str | None]:
    """Extract (amount, from_iso, to_iso) from a free-form query.

    Defaults: amount=1.0, target=ILS (or USD if source is ILS).
    Heuristic: first currency in text → source; second → target.
    """
    occurrences = _find_currency_occurrences(q)

    # Amount: first numeric literal in the query.
    # Comma handling: `1,500` (3 digits after comma) is treated as a
    # thousands separator → 1500. Anything else is European decimal notation.
    amount = 1.0
    m = _CURRENCY_AMOUNT_RE.search(q)
    if m:
        raw = m.group(1)
        if "," in raw and "." not in raw:
            before, _, after = raw.partition(",")
            if len(after) == 3 and before.isdigit():
                raw = before + after
            else:
                raw = raw.replace(",", ".")
        try:
            amount = float(raw)
        except ValueError:
            amount = 1.0

    # Deduplicate consecutive identical codes (e.g. "USD usd" → one entry).
    distinct: list[str] = []
    for _, code in occurrences:
        if not distinct or distinct[-1] != code:
            distinct.append(code)

    if not distinct:
        return None, None, None

    if len(distinct) == 1:
        src = distinct[0]
        tgt = "ILS" if src != "ILS" else "USD"
        return amount, src, tgt

    src, tgt = distinct[0], distinct[1]
    if src == tgt:
        tgt = "ILS" if src != "ILS" else "USD"
    return amount, src, tgt


# Backward-compat thin wrapper. External callers (and tests) may still rely on
# the single-currency extractor; it now returns the parsed `from` field.
def _extract_currency_from_query(q: str) -> str:
    _, frm, _ = _parse_currency_query(q)
    return frm or ""


async def _direct_currency_bypass(user_question: str) -> str | None:
    """Deterministic bypass: call skill_currency-skill directly, return verbatim.

    Prevents LLM hallucination of fake exchange rates (e.g., 1 USD = 0.34 ILS).
    Detects amount + source + target from user query.
    Returns None when no currency could be detected.
    """
    engine = get_skills_engine()
    amount, source_currency, target_currency = _parse_currency_query(user_question)

    if amount is None or source_currency is None or target_currency is None:
        return None

    logger.info(f"[AGENT] Currency bypass: {amount:g} {source_currency}→{target_currency}")
    try:
        result = await engine.execute(
            "currency-skill",
            "run",
            f"--amount {amount:g} --from {source_currency} --to {target_currency}",
        )
    except Exception as e:
        logger.error(f"[AGENT] Currency bypass failed: {e}")
        return "⚠️ שגיאה בשאילת שערי מטבע."
    if not result or result.startswith("❌"):
        return "⚠️ לא ניתן לקבל שערי מטבע כרגע."
    try:
        await async_store_conversation(user_question, result)
    except Exception:
        pass
    return result
