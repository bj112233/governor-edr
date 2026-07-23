# services/agent/routing/hebrew_norm.py
import logging
import re
from collections.abc import Iterable

logger = logging.getLogger(__name__)

_HEB_PREFIXES: tuple[str, ...] = ("ה", "ב", "ל", "מ", "ו", "ש", "כ")
_HEB_LETTER_RE = re.compile(r"^[\u05d0-\u05ea]+$")
_PUNCT_RE = re.compile(r"[^\w\s\u05d0-\u05ea]+")


def _strip_hebrew_prefix(word: str) -> str:
    """Strip a single common Hebrew prefix if word is long enough.

    Conservative rules:
    - Word must be >= 4 Hebrew letters (so the stripped stem is still >= 3).
    - First char must be a known prefix letter.
    - Remainder must be all Hebrew letters (avoids stripping in mixed tokens
      like "ה1", "מgpu", which are not Hebrew words).
    """
    if len(word) < 4:
        return word
    if word[0] not in _HEB_PREFIXES:
        return word
    remainder = word[1:]
    if _HEB_LETTER_RE.match(remainder):
        return remainder
    return word


def _normalize_hebrew_query(query: str) -> str:
    """Lightweight Hebrew normalization for keyword matching.

    Pipeline:
        1. Lowercase (preserves Hebrew, lowercases Latin).
        2. Replace punctuation with spaces.
        3. Per-token: strip a single Hebrew prefix when safe.

    Returns a normalized string. Caller should match keywords against
    BOTH the original lowercase form AND the normalized form to maximize
    hit rate without losing precision.
    """
    if not query:
        return ""
    q = query.lower()
    q = _PUNCT_RE.sub(" ", q)
    tokens = q.split()
    return " ".join(_strip_hebrew_prefix(t) for t in tokens)


def _normalize_keyword_set(keywords: Iterable[str]) -> tuple[str, ...]:
    """Pre-normalize a static keyword tuple at module load time.

    Returns the union of (a) the original lowercased keywords and
    (b) their normalized forms — deduplicated, order-stable.
    Empty strings (artifacts of normalization) are dropped.
    """
    seen: dict[str, None] = {}
    for kw in keywords:
        lo = kw.lower()
        if lo and lo not in seen:
            seen[lo] = None
        norm = _normalize_hebrew_query(kw)
        if norm and norm not in seen:
            seen[norm] = None
    return tuple(seen.keys())
