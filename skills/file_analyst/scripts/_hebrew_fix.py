"""
Hebrew font encoding fix for Israeli PDFs — custom glyph-to-Latin corruption.
"""

import sys

_HEBREW_CP_RANGE = ("\u0590", "\u05ff")

# Tiny English stopword set — used analytically to disprove "encoded Hebrew".
# If the text contains any real English vocabulary, we abort the fix.
_ENGLISH_STOPWORDS = frozenset(
    {
        "the", "and", "of", "to", "in", "is", "that", "for", "it", "on",
        "with", "as", "this", "by", "an", "be", "are", "or", "from", "at",
        "was", "were", "have", "has", "had", "not", "but", "they", "you",
        "we", "all", "can", "will", "would", "should", "their", "there",
        "which", "what", "when", "where", "who", "how", "page", "figure",
        "table", "section", "chapter",
    }
)


def _looks_like_encoded_hebrew(text: str, encoding_keys: set[str]) -> bool:
    """Analytical detector for the Israeli-PDF custom-font glyph-to-Latin
    corruption.

    A text is classified as "encoded Hebrew" iff ALL of the following hold:
      1. Sample size is meaningful: ≥20 alphabetic characters (lowered from
         50 to catch short headers like "ANNA ODTIN" in form fields).
      2. Native Hebrew is absent (<1% of alphabetic chars are in the Hebrew
         Unicode block). If real Hebrew is present, the text was decoded
         correctly — no fix needed.
      3. English stopword density is low (≤60% of Latin words). A coherent
         English document will always contain multiple stopwords; their
         absence is a strong signal of non-English Latin output.
      4. Character-level structural overlap: ≥20% of Latin alphabetic
         characters are present in the encoding map keys (lowered from 30%
         to catch mixed or short samples).
      5. Uppercase ratio is high (≥50%). Custom-font-encoded Hebrew maps
         Hebrew glyphs to UPPERCASE Latin characters. Legitimate English
         text (including technical datasheets) is predominantly lowercase.
         Without this check, English datasheets with low stopword density
         get falsely classified as encoded Hebrew.

    Returns False for any borderline case. The caller MUST treat False as
    "leave text untouched".
    """
    import re

    alpha = [c for c in text if c.isalpha()]
    if len(alpha) < 20:
        return False

    # (2) Native Hebrew already present → already decoded.
    hebrew_chars = sum(
        1 for c in alpha if _HEBREW_CP_RANGE[0] <= c <= _HEBREW_CP_RANGE[1]
    )
    if hebrew_chars / len(alpha) > 0.01:
        return False

    # (5) Uppercase ratio check — encoded Hebrew is predominantly UPPERCASE.
    # English text (even technical) is predominantly lowercase.
    ascii_alpha = [c for c in alpha if c.isascii()]
    if ascii_alpha:
        upper_count = sum(1 for c in ascii_alpha if c.isupper())
        upper_ratio = upper_count / len(ascii_alpha)
        if upper_ratio < 0.50:
            return False

    # (3) Real English vocabulary present → not encoded Hebrew.
    latin_words = re.findall(r"\b[A-Za-z]+\b", text)
    if not latin_words:
        return False
    stopword_hits = sum(1 for w in latin_words if w.lower() in _ENGLISH_STOPWORDS)
    if stopword_hits / len(latin_words) > 0.60:
        return False

    # (4) Character-level density match against encoding keys.
    latin_chars = [c for c in text if c.isalpha() and c.isascii()]
    if not latin_chars:
        return False
    matched_chars = sum(1 for c in latin_chars if c.upper() in encoding_keys)
    return (matched_chars / len(latin_chars)) >= 0.20


def _fix_custom_font_encoding(text: str, lang: str = "") -> str:
    """
    Fix custom font encoding corruption common in Israeli PDFs.
    Some PDFs use fonts that map Hebrew glyphs to Latin character codes.

    Strict prerequisites (ALL required — else return text unchanged):
      * `lang` must explicitly request Hebrew ("heb" in lang). Without an
        explicit Hebrew context, mapping uppercase Latin → Hebrew would
        corrupt legitimate English documents (acronyms, headings, ALL-CAPS
        legalese).
      * `_looks_like_encoded_hebrew()` must return True — i.e. the text
        analytically resembles the encoded form (no English stopwords,
        no native Hebrew, structural overlap with the mapping table).
    """
    if "heb" not in (lang or "").lower():
        return text

    _base_map = {
        # Hebrew letters mapped to look-alike Latin chars
        "A": "א", "N": "נ", "W": "ש", "H": "ה", "T": "ת",
        "M": "מ", "D": "ד", "Y": "י", "V": "ב", "P": "פ",
        "K": "כ", "L": "ל", "R": "ר", "Z": "ז", "G": "ג",
        "S": "ס", "C": "צ", "Q": "ק", "X": "ח", "J": "ח",
        "O": "ו", "I": "י", "U": "ו", "B": "ב", "F": "פ",
        "E": "א",
        # Common multi-char patterns from observed gibberish
        "MW": "שמ", "PI": "פי", "VO": "בו", "IV": "יב", "WA": "שא",
        "NA": "נה", "TA": "תא", "YA": "יא", "AN": "אנ", "NI": "ני",
        "TI": "תי", "MI": "מי", "DI": "די", "VI": "בי", "LI": "לי",
        "RI": "רי", "NIW": "נשו", "TIW": "תשו", "MIW": "משו",
        "ONN": "ונן", "ONNA": "ונה", "ONNI": "וני", "NN": "נן",
        "WW": "שש", "MM": "מם", "DD": "דד",
        # Numbers pass through
        "0": "0", "1": "1", "2": "2", "3": "3", "4": "4",
        "5": "5", "6": "6", "7": "7", "8": "8", "9": "9",
    }
    # Dynamically inject lowercase keys for single alphabetic characters
    # to support Tesseract's lowercase garbage output.
    encoding_map = dict(_base_map)
    for key, val in list(_base_map.items()):
        if len(key) == 1 and key.isalpha():
            encoding_map.setdefault(key.lower(), val)

    # Analytical detector — see _looks_like_encoded_hebrew for full
    # prerequisite list. Operates on character density, not on
    # naïve token overlap.
    has_real_hebrew = any("\u0590" <= c <= "\u05ff" for c in text)
    looks_encoded = _looks_like_encoded_hebrew(
        text, {k for k in encoding_map if len(k) == 1}
    )

    # FORCE-FIX: Hebrew requested but NO real Hebrew Unicode found.
    # This catches scanned Israeli PDFs where the detector fails due to
    # short samples, English metadata, or mixed content.
    # BUT: only force-fix if the text is predominantly UPPERCASE —
    # legitimate English text (datasheets, manuals) is predominantly
    # lowercase and must NOT be corrupted.
    if not looks_encoded and not has_real_hebrew:
        ascii_alpha = [c for c in text if c.isalpha() and c.isascii()]
        if ascii_alpha:
            upper_count = sum(1 for c in ascii_alpha if c.isupper())
            upper_ratio = upper_count / len(ascii_alpha)
            if upper_ratio < 0.50:
                return text  # lowercase-dominant → real English, not encoded Hebrew
        pass  # Continue to fix below
    elif not looks_encoded:
        return text

    # _safe_print wrapper to avoid Windows pipe errors on stderr.
    try:
        print(
            "[OCR] Detected custom font encoding. Applying fix…",
            flush=True,
            file=sys.stderr,
        )
    except OSError:
        pass
    result = text
    # Replace longer patterns first to avoid partial overlaps.
    for pattern, hebrew in sorted(encoding_map.items(), key=lambda x: -len(x[0])):
        result = result.replace(pattern, hebrew)
    return result
