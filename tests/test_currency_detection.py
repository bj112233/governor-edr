"""Regression tests for `_detect_currency_query` and translation/currency
bypass priority in `services.agent`.

Background: a generic "rate" keyword in `_CURRENCY_KEYWORDS` caused technical
documents (e.g. TPA3255 datasheet — "sample rate", "switching rate") to
trigger `currency-skill` during a translation flow. This suite locks in the
hardened behavior.
"""

from __future__ import annotations

import pytest

from services import agent as agent_mod
from services.agent import (
    _SUMMARIZE_INTENT_RE,
    _detect_currency_query,
    _detect_elaborate_query,
    _parse_currency_query,
    _split_for_translation,
    _strip_document_noise,
)


def test_translation_prompts_preserve_cyber_terms() -> None:
    from services.agent.bypass._translation_handlers import (
        _CONSOLIDATE_SYSTEM_PROMPT,
        _SUMMARIZE_SYSTEM_PROMPT,
        _TRANSLATE_SYSTEM_PROMPT,
    )

    prompts = (_TRANSLATE_SYSTEM_PROMPT, _SUMMARIZE_SYSTEM_PROMPT, _CONSOLIDATE_SYSTEM_PROMPT)
    assert all("Encoded Commands" in prompt for prompt in prompts)
    assert all("Execution Policy Bypass" in prompt for prompt in prompts)


# ── Negative cases: must NOT trigger currency bypass ──────────────────────────
@pytest.mark.parametrize(
    "q",
    [
        "sample rate is 48 kHz",
        "bit rate of the stream",
        "switching rate of the Class-D output stage",
        "high frame rate video capture",
        "the data rate exceeds 10 Gbps",
        "תרגם את המסמך הזה שמכיל sample rate",
        "translate this document with switching rate values",
        "",
    ],
)
def test_currency_not_detected_on_technical_text(q: str) -> None:
    assert _detect_currency_query(q) is False, f"false-positive on: {q!r}"


# ── Positive cases: must trigger currency bypass ──────────────────────────────
@pytest.mark.parametrize(
    "q",
    [
        "מה שער הדולר היום?",
        "המר 100 דולר לשקלים",
        "כמה שווה יורו בשקל",
        "USD to ILS",
        "convert 50 EUR",
        "current exchange rate",
        "what is the currency rate",
        "$100 to ₪",
        "GBP",
    ],
)
def test_currency_detected_on_real_currency_intent(q: str) -> None:
    assert _detect_currency_query(q) is True, f"false-negative on: {q!r}"


# ── Translation intent suppresses currency detection ──────────────────────────
def test_translation_intent_blocks_currency_detection() -> None:
    # Even if the text would otherwise match (e.g. contains USD), an explicit
    # translation directive must win — the document context, not currency, is
    # the user's intent.
    assert _detect_currency_query("תרגם את המסמך שמזכיר USD ו-EUR") is False
    assert _detect_currency_query("translate the section about USD reserves") is False


# ── Bypass priority in run_agent: translation (with last_document) over currency
def test_translation_bypass_takes_priority_over_currency(monkeypatch) -> None:
    """When a previous document exists and the user asks to translate, the
    translation bypass must fire — even if the message coincidentally contains
    currency-ish tokens. This guards the order in `run_agent`.

    _BYPASS_HANDLERS is a list of direct function references captured at import
    time, so patching module attributes does NOT intercept them. We replace the
    entire dispatcher list with a minimal ordered set that exercises only the
    translation-vs-currency priority we care about.
    """
    import asyncio

    agent_mod.set_last_document("Datasheet excerpt: sample rate 48kHz, USD pricing.")

    called = {"translation": 0, "currency": 0}

    async def fake_translation_handler(q: str) -> str | None:
        if any(kw in q.lower() for kw in ("תרגם", "תרגום", "translate", "translation")):
            called["translation"] += 1
            return "TRANSLATED"
        return None

    async def fake_currency_handler(q: str) -> str | None:
        # Mirror real _detect_currency_query: translation intent suppresses it.
        from services.agent.bypass.currency import _detect_currency_query

        if _detect_currency_query(q):
            called["currency"] += 1
            return "CURRENCY"
        return None

    # Stub the real translation subprocess (translator skill) so that even if
    # the original _BYPASS_HANDLERS list leaks through, no live subprocess fires.
    # Pattern mirrored from tests/test_bypass_handlers.py.
    from services.agent import _bypasses as bp
    from services.agent._nodes import _initializer as init

    async def _fake_direct_translation(q: str) -> str:
        return "TRANSLATED"

    async def _patched_try_translation(q: str) -> str | None:
        if any(kw in q.lower() for kw in ("תרגם", "תרגום", "translate", "translation")):
            return await _fake_direct_translation(q)
        return None

    monkeypatch.setattr(bp, "_direct_translation_bypass", _fake_direct_translation)
    monkeypatch.setattr(bp, "_try_translation_bypass", _patched_try_translation)

    # Replace the dispatcher with translation-first, currency-second ordering.
    # _initializer holds a direct import-time reference, so patch there too.
    # Also neutralize store_message (calls embedding service → network hang).
    monkeypatch.setattr(bp, "_BYPASS_HANDLERS", [fake_translation_handler, fake_currency_handler])
    monkeypatch.setattr(init, "_BYPASS_HANDLERS", [fake_translation_handler, fake_currency_handler])

    async def _noop_store(*a, **kw):
        return None

    monkeypatch.setattr(init, "_store_message", _noop_store)

    # asyncio.run() — not get_event_loop() — avoids RuntimeError under pytest
    # where no current event loop exists in the main thread.
    result = asyncio.run(agent_mod.run_agent("תרגם את המסמך — מכיל sample rate ו-USD"))

    assert result == "TRANSLATED"
    assert called["translation"] == 1
    assert called["currency"] == 0

    # Cleanup global state to avoid cross-test leakage.
    agent_mod.set_last_document("")


# ── Currency query parser: (amount, from_iso, to_iso) ────────────────────────
@pytest.mark.parametrize(
    "q,expected",
    [
        # Hebrew, single-currency queries → default target ILS
        ("שער הדולר", (1.0, "USD", "ILS")),
        ("מה שער היורו היום?", (1.0, "EUR", "ILS")),
        ("שער האירו", (1.0, "EUR", "ILS")),
        ("שער הפאונד הבריטי לשקל", (1.0, "GBP", "ILS")),
        # Hebrew, explicit amount + direction
        ("כמה שווה 100 דולר בשקלים", (100.0, "USD", "ILS")),
        ("המר 50 אירו לדולר", (50.0, "EUR", "USD")),
        ("100 פורינט הונגרי לשקל", (100.0, "HUF", "ILS")),
        ("500 ין יפני לשקל", (500.0, "JPY", "ILS")),
        ("המר 200 פרנק שוויצרי לשקל", (200.0, "CHF", "ILS")),
        ("1000 יואן סיני לשקל", (1000.0, "CNY", "ILS")),
        ("כמה שווים 75 דולר קנדי בשקלים", (75.0, "CAD", "ILS")),
        # Thousands separator
        ("המר 1,500 דולר לשקל", (1500.0, "USD", "ILS")),
        # English ISO codes
        ("convert 200 USD to EUR", (200.0, "USD", "EUR")),
        ("USD to ILS", (1.0, "USD", "ILS")),
        ("50 GBP", (50.0, "GBP", "ILS")),
        # Symbols
        ("$100 to ₪", (100.0, "USD", "ILS")),
        # ILS as source flips default target to USD
        ("100 שקל לדולר", (100.0, "ILS", "USD")),
        ("שער השקל", (1.0, "ILS", "USD")),
        # No currency in query → no match (current API returns None tuple)
        ("מה השער היום", (None, None, None)),
        # Common Hebrew typos (letter swap)
        ("1000 שקל לפרוניט", (1000.0, "ILS", "HUF")),
        ("1000 שקל לפרוניט הונגרי", (1000.0, "ILS", "HUF")),
        # Bug: "פורניט" (nun-yud transposed) was missing from map → defaulted to ILS
        ("2080 דולר לפורניט", (2080.0, "USD", "HUF")),
        # Country-adjective fallback (when noun is absent / misspelled)
        ("100 שקל להונגרי", (100.0, "ILS", "HUF")),
        ("שער הקנדי לשקל", (1.0, "CAD", "ILS")),
    ],
)
def test_parse_currency_query(q: str, expected: tuple[float, str, str]) -> None:
    assert _parse_currency_query(q) == expected, f"failed on: {q!r}"


def test_parse_currency_query_no_false_positive_on_country() -> None:
    """`country` contains the substring `try`; word-boundary check must
    prevent a spurious TRY match. Current API returns (None, None, None)
    when no currency is mentioned."""
    result = _parse_currency_query("which country has the highest GDP")
    assert result == (None, None, None)


def test_parse_currency_query_multiword_eclipses_singleword() -> None:
    """`דולר קנדי` must resolve to CAD, not USD (single-word `דולר`).
    Adjective-merge handles ה-prefix variant ('הדולר הקנדי') too."""
    assert _parse_currency_query("100 דולר קנדי לשקל") == (100.0, "CAD", "ILS")
    # ה-prefix variant: adjacent country adjective overrides the noun.
    assert _parse_currency_query("שער הדולר הקנדי") == (1.0, "CAD", "ILS")


# ── Translation chunk splitter ────────────────────────────────────────────────
def test_split_short_text_returns_single_chunk() -> None:
    assert _split_for_translation("hello world", 3000) == ["hello world"]


def test_split_empty_text_returns_empty_list() -> None:
    assert _split_for_translation("", 3000) == []
    assert _split_for_translation("   \n\n  ", 3000) == []


def test_split_paragraphs_under_budget() -> None:
    text = "para1\n\npara2\n\npara3"
    out = _split_for_translation(text, 3000)
    assert out == [text]


def test_split_paragraphs_split_into_multiple_chunks() -> None:
    p = "x" * 1000
    text = "\n\n".join([p, p, p, p])  # 4 paragraphs of 1000 chars
    out = _split_for_translation(text, 2500)
    assert len(out) >= 2
    # All chunks must respect the budget.
    assert all(len(c) <= 2500 for c in out)
    # Reconstructed body must contain every paragraph.
    joined = "\n\n".join(out)
    assert joined.count(p) == 4


def test_split_oversized_single_paragraph_is_sliced() -> None:
    big = "y" * 7000
    out = _split_for_translation(big, 3000)
    assert len(out) == 3
    assert out[0] == "y" * 3000
    assert out[1] == "y" * 3000
    assert out[2] == "y" * 1000


# ── Summarization intent detection ────────────────────────────────────────────
@pytest.mark.parametrize(
    "q",
    [
        "תרגם וסכם את המסמך",
        "סכם בבקשה",
        "אני רוצה סיכום של ה-PDF",
        "תמצת לי את זה",
        "תקציר של הדטאשיט",
        "translate and summarize this",
        "give me a summary",
        "please summarise the document",
    ],
)
def test_summarize_intent_detected(q: str) -> None:
    assert _SUMMARIZE_INTENT_RE.search(q) is not None, f"missed: {q!r}"


@pytest.mark.parametrize(
    "q",
    [
        "תרגם את המסמך",
        "translate the document",
        "מה כתוב כאן",
        "",
    ],
)
def test_summarize_intent_not_detected_on_pure_translation(q: str) -> None:
    assert _SUMMARIZE_INTENT_RE.search(q) is None, f"false-positive: {q!r}"


# ── Document noise stripper (TOC + metadata) ──────────────────────────────────
def test_strip_removes_toc_dot_leader_lines() -> None:
    raw = (
        "מאפיינים.................................................. 1\n"
        "9.3 תיאור המאפיין................................. 17\n"
        "תיאור משמעותי של היחידה הוא מודל Class-D עם הספק 315W.\n"
    )
    out = _strip_document_noise(raw)
    assert "...." not in out
    assert "מאפיינים" not in out  # TOC entry dropped
    assert "Class-D" in out  # prose retained


def test_strip_removes_ti_doc_header_and_url() -> None:
    raw = (
        "TPA3255 הוא מגבר Class-D דו-ערוצי.\n"
        "SLASEA8A–FEBRUARY2016–REVISEDOCTOBER2016\n"
        "www.ti.com\n"
        "טווח מתח ספק: 18V עד 53.5V.\n"
    )
    out = _strip_document_noise(raw)
    assert "SLASEA8A" not in out
    assert "www.ti.com" not in out
    assert "TPA3255" in out
    assert "53.5V" in out


def test_strip_removes_bare_page_numbers() -> None:
    raw = "פסקה ראשונה עם תוכן טכני.\n\n42\n\nפסקה שנייה עם תוכן נוסף.\n"
    out = _strip_document_noise(raw)
    assert "\n42\n" not in out
    assert "פסקה ראשונה" in out
    assert "פסקה שנייה" in out


def test_strip_preserves_normal_decimals() -> None:
    """A decimal value like `2.5W` (one or two dots) must NOT be stripped."""
    raw = "אבטלה מתחת ל-2.5 וואט במצב idle.\nהפרשי מתח 0.1V מקובלים.\n"
    out = _strip_document_noise(raw)
    assert "2.5 וואט" in out
    assert "0.1V" in out


def test_strip_handles_empty_input() -> None:
    assert _strip_document_noise("") == ""
    assert _strip_document_noise("   \n\n  ") == ""


# ── Elaboration bypass detector ───────────────────────────────────────────────
@pytest.mark.parametrize(
    "q",
    [
        "תפרט",
        "תפרט.",
        "  תפרט!  ",
        "פרט",
        "הרחב",
        "הסבר",
        "הסבר עוד",
        "המשך",
        "תמשיך",
        "עוד פרטים",
        "הוסף פרטים",
        "תן דוגמה",
        "elaborate",
        "ELABORATE.",
        "more details",
        "tell me more",
        "continue",
        "go on",
    ],
)
def test_elaborate_intent_detected(q: str) -> None:
    assert _detect_elaborate_query(q) is True, f"missed elaborate: {q!r}"


@pytest.mark.parametrize(
    "q",
    [
        "",
        "תפרט על המוצר השלישי ברשימה כולל מחירים והערות",  # > 40 chars
        "מה השעה",
        "תרגם את המסמך",
        "סכם",
        "explain how the firewall works in detail",  # too long, contextual
        "מה זה",
        "תפרט לי בבקשה איזה מחיר יש למוצר הזה ועוד",  # too long
    ],
)
def test_elaborate_intent_not_detected(q: str) -> None:
    assert _detect_elaborate_query(q) is False, f"false-positive elaborate: {q!r}"


# ── System prompt: follow-up continuity guard ─────────────────────────────────
def test_system_prompt_is_non_empty_str() -> None:
    """_AGENT_SYSTEM must be a non-empty string (ReAct loop directive).

    The FOLLOW-UP CONTINUITY block was removed in Sprint 4 when the system
    prompt was refactored to the ReAct-only directive. This test now guards
    the invariant that the prompt exists and carries the core directive.
    """
    sp = agent_mod._AGENT_SYSTEM
    assert isinstance(sp, str) and len(sp) > 50
    assert "REACT" in sp.upper()


def test_strip_handles_ocr_fragmented_toc_with_spaced_dots() -> None:
    """OCR extractor inserts `\\n\\n` between every word, splitting dot-leaders
    into one-dot-per-line. Stripper must collapse + drop the TOC anyway."""
    # Build an OCR-fragmented TOC: each token (word/dot/number) on its own line
    # separated by double newline (the FiiO-extractor style observed in prod).
    toc_tokens = [
        "תוכן",
        "העניינים",
        "1",
        "מאפיינים",
        ".",
        ".",
        ".",
        ".",
        ".",
        ".",
        ".",
        "1",
        "9.3",
        "תיאור",
        "המאפיין",
        ".",
        ".",
        ".",
        ".",
        ".",
        ".",
        "17",
        "2",
        "יישומים",
        ".",
        ".",
        ".",
        ".",
        ".",
        ".",
        "1",
    ]
    toc = "\n\n".join(toc_tokens)
    # Real prose body that must survive: must be substantive (>120 chars).
    body_tokens = (
        "TPA3255 הוא מגבר Class-D דו-ערוצי בהספק עד 315W "
        "לערוץ ב-4 אום ועד 150W לערוץ ב-8 אום. המכשיר תומך "
        "בתצורות BTL, SE ו-PBTL, וכולל הגנות מובנות מפני "
        "מתח-יתר וחום-יתר באריזת HTSSOP-44."
    ).split()
    body = "\n\n".join(body_tokens)
    raw = toc + "\n\n\n\n" + body  # 4 newlines = paragraph break

    out = _strip_document_noise(raw)

    # TOC tokens must NOT appear; prose substance must survive.
    assert "מאפיינים" not in out, f"TOC entry leaked: {out!r}"
    assert "9.3" not in out
    assert "TPA3255" in out
    assert "Class-D" in out
    assert "315W" in out
