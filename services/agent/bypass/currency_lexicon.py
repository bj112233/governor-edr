"""Currency lexicon — detection maps, regexes, and constants.

Extracted from bypass/currency.py (SRP). Pure data module — no logic.
"""

import re

# ── Regex intent markers ──────────────────────────────────────────────────────
_TRANSLATION_INTENT_RE = re.compile(r"תרגם|תרגום|translate|translation", re.IGNORECASE)
_SUMMARIZE_INTENT_RE = re.compile(r"סכם|סיכום|תמצת|תקציר|summari[sz]e|summary", re.IGNORECASE)
_ELABORATE_INTENT_RE = re.compile(
    r"^\s*(?:"
    r"תפרט|פרט|הרחב|הסבר עוד|הסבר|המשך|תמשיך|"
    r"עוד פרטים|הוסף פרטים|תן דוגמה|פרט עוד|"
    r"elaborate|expand|more details|tell me more|continue|go on"
    r")\s*[\.\!\?…]*\s*$",
    re.IGNORECASE,
)
_ELABORATE_MAX_QUESTION_CHARS = 40

# ── Currency detection sets ───────────────────────────────────────────────────
_CURRENCY_KEYWORDS_HE: frozenset[str] = frozenset(["דולר", "שער", "המרה", "כמה שווה", "יורו", "שקל", "שקלים"])
_CURRENCY_KEYWORDS_EN: frozenset[str] = frozenset(["currency", "exchange rate", "forex", "fx rate"])
_CURRENCY_CODES_RE = re.compile(r"\b(usd|eur|ils|gbp|jpy|chf|nis|cad|aud|btc|eth)\b", re.IGNORECASE)
_CURRENCY_SYMBOLS: frozenset[str] = frozenset(["$", "€", "£", "¥", "₪"])
_CURRENCY_KEYWORDS: frozenset[str] = _CURRENCY_KEYWORDS_HE | _CURRENCY_KEYWORDS_EN

# מיפוי מטבעות מזוהים בשאילתה → קוד ISO
# הסדר חשוב: ביטויים ארוכים יותר חייבים להופיע לפני קצרים יותר כדי
# למנוע התאמה חלקית (למשל "דולר קנדי" לפני "דולר").
_CURRENCY_MAP: dict[str, str] = {
    # ── ביטויים מרובי-מילים בעברית (חייבים להופיע ראשונים) ──
    "דולר קנדי": "CAD",
    "דולר אוסטרלי": "AUD",
    "דולר אמריקאי": "USD",
    "לירה טורקית": "TRY",
    "לירה סטרלינג": "GBP",
    "פרנק שוויצרי": "CHF",
    "יואן סיני": "CNY",
    "ין יפני": "JPY",
    "פורינט הונגרי": "HUF",
    "פרוניט הונגרי": "HUF",  # טעות-כתיב נפוצה (אותיות מוחלפות)
    "ריאל ברזילאי": "BRL",
    "פזו מקסיקני": "MXN",
    "וון קוריאני": "KRW",
    "רובל רוסי": "RUB",
    # ── עברית (מילה יחידה) ──
    "דולר": "USD",
    "יורו": "EUR",
    "אירו": "EUR",
    "שקלים": "ILS",
    "שקל": "ILS",
    "פאונד": "GBP",
    "סטרלינג": "GBP",
    "פורינט": "HUF",
    "פורניט": "HUF",  # טעות-כתיב נפוצה (נ-י ← י-נ)
    "פרוניט": "HUF",  # טעות-כתיב נפוצה
    "פרנק": "CHF",
    "יואן": "CNY",
    "רנמינבי": "CNY",
    "רובל": "RUB",
    "פזו": "MXN",
    "וון": "KRW",
    # שים לב: "ין" לא מתווסף כמילה יחידה כי הוא רצף נפוץ בעברית
    # (למשל "אין", "מין"); נדרש "ין יפני" מפורש.
    # שים לב: "לירה" לא מתווסף כמילה יחידה (עמום: בריטית/טורקית/מצרית).
    # ── תארי-לאום עבריים (fallback לכשהשם הספציפי לא זוהה / נכתב בטעות) ──
    # מסתמך על כך שתארים אלה במשפט עם מספר/מטבע מציינים את מטבע המדינה.
    "הונגרי": "HUF",
    "קנדי": "CAD",
    "אוסטרלי": "AUD",
    "בריטי": "GBP",
    "אמריקאי": "USD",
    "ברזילאי": "BRL",
    "מקסיקני": "MXN",
    "קוריאני": "KRW",
    "רוסי": "RUB",
    "טורקי": "TRY",
    "סיני": "CNY",
    "שוויצרי": "CHF",
    "יפני": "JPY",
    # ── אנגלית: ISO codes ──
    "usd": "USD",
    "eur": "EUR",
    "ils": "ILS",
    "nis": "ILS",
    "gbp": "GBP",
    "jpy": "JPY",
    "chf": "CHF",
    "cad": "CAD",
    "aud": "AUD",
    "cny": "CNY",
    "rmb": "CNY",
    "rub": "RUB",
    "try": "TRY",
    "brl": "BRL",
    "mxn": "MXN",
    "krw": "KRW",
    # ── אנגלית: שמות נפוצים ──
    "dollars": "USD",
    "dollar": "USD",
    "euros": "EUR",
    "euro": "EUR",
    "shekels": "ILS",
    "shekel": "ILS",
    "pounds": "GBP",
    "pound": "GBP",
    "sterling": "GBP",
    "yen": "JPY",
    "yuan": "CNY",
    "renminbi": "CNY",
    "franc": "CHF",
    "ruble": "RUB",
    "rouble": "RUB",
    "real": "BRL",
    "peso": "MXN",
    "won": "KRW",
    "forint": "HUF",
    "huf": "HUF",
    # ── קריפטו ──
    "ביטקוין": "BTC",
    "ביטקויין": "BTC",
    "bitcoin": "BTC",
    "btc": "BTC",
    "אתריום": "ETH",
    "ethereum": "ETH",
    "eth": "ETH",
}

# סמלי מטבע → ISO (לזיהוי בשאילתות כגון "$100 to ₪").
_CURRENCY_SYMBOL_MAP: dict[str, str] = {
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "¥": "JPY",
    "₪": "ILS",
}

# Regex לזיהוי קוד ISO תקני בגבולות מילה. נבנה דינמית מן המפה.
_CURRENCY_ISO_RE = re.compile(
    r"\b(USD|EUR|ILS|NIS|GBP|JPY|CHF|CAD|AUD|CNY|RMB|RUB|TRY|BRL|MXN|KRW|HUF)\b",
    re.IGNORECASE,
)
_CURRENCY_AMOUNT_RE = re.compile(r"(\d+(?:[.,]\d+)?)")

# תארי-לאום עבריים שמשמשים כ-fallback לזיהוי מטבע. אם הם מופיעים סמוך
# למילת מטבע אחרת ("דולר קנדי", "ין יפני"), התואר גובר על שם-המטבע
# הכללי — כי "דולר קנדי" = CAD ולא USD.
_CURRENCY_ADJECTIVE_KEYWORDS: frozenset[str] = frozenset(
    [
        "הונגרי",
        "קנדי",
        "אוסטרלי",
        "בריטי",
        "אמריקאי",
        "ברזילאי",
        "מקסיקני",
        "קוריאני",
        "רוסי",
        "טורקי",
        "סיני",
        "שוויצרי",
        "יפני",
    ]
)
_ADJECTIVE_MERGE_GAP = 6  # תווים מותרים בין שם-המטבע לתואר (מאפשר "ה" ורווח)
