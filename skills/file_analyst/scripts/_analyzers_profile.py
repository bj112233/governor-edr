"""Profile-based document analysis — analyze_with_profile + legacy fallback.

Extracted from _analyzers.py (SRP). analyze_with_profile was D(30) CC.
"""
import re

try:
    from profile_loader import detect_profile, load_profile
except ImportError:
    detect_profile = None
    load_profile = None


def _analyze_contract_legacy(text: str, filename: str = "") -> str:
    """Legacy hardcoded rental contract analysis (fallback)."""
    text_lower = text.lower()
    out = [f"# ניתוח חוזה (legacy): {filename}\n"]

    def find_context(keywords, max_chars=120):
        for kw in keywords:
            for m in re.finditer(re.escape(kw), text_lower):
                start = max(m.start() - max_chars, 0)
                end = min(m.end() + max_chars, len(text))
                ctx = text[start:end].replace("\n", " ").strip()
                if ctx:
                    return ctx
        return None

    def has_any(keywords):
        return any(kw in text_lower for kw in keywords)

    clauses = []

    if has_any(["שכר דירה", "דמי שכירות", "rent"]):
        clauses.append(("תשלום שכר דירה", "נמצא סעיף שכירות", "neutral"))

    if has_any(["ביטחון", "הפקדה", "ערבות", "deposit"]):
        clauses.append(("הפקדת ביטחון", "נמצא סעיף ביטחון", "neutral"))

    if has_any(["סיום מוקדם", "הודעה מוקדמת", "termination"]):
        clauses.append(("סיום מוקדם", "נמצא סעיף סיום", "neutral"))

    if not clauses:
        return "⚠️ לא זוהו סעיפי חוזה שכירות בטקסט (legacy mode).\n\n---\n" + text[:600]

    out.append("## סעיפים מזוהים (legacy)\n")
    for name, desc, score in clauses:
        label = {"good": "✅ טוב", "bad": "❌ רע", "neutral": "⚪ ניטרלי"}.get(score, "?")
        out.append(f"- **{name}**: {label} - {desc}")

    out.append("\n> ⚠️ ניתוח legacy - מומלץ לבדוק פרופילים זמינים.")
    return "\n".join(out)


def _score_item(item, has_any) -> str:
    """Classify a profile item as good/bad/neutral based on its keywords."""
    classifier = item.get("classifier")
    if classifier == "neutral":
        return "neutral"
    if has_any(item.get("good_if", [])):
        return "good"
    if has_any(item.get("bad_if", [])):
        return "bad"
    return "neutral"


def _find_context(keywords, text: str, text_lower: str, max_chars: int = 120) -> str | None:
    for kw in keywords or []:
        for m in re.finditer(re.escape(kw.lower()), text_lower):
            start = max(m.start() - max_chars, 0)
            end = min(m.end() + max_chars, len(text))
            ctx = text[start:end].replace("\n", " ").strip()
            if ctx:
                return ctx
    return None


def _format_profile_results(found, doc_type, filename, profile, profile_name, text) -> str:
    """Format the found clauses into a Markdown report."""
    out = [f"# ניתוח {doc_type}: {filename}"]
    if profile.get("description"):
        out.append(f"**פרופיל:** {profile['description']}\n")

    if not found:
        return (
            f"⚠️ לא זוהו סעיפים מובהקים בטקסט עבור פרופיל '{profile_name}'.\n\n"
            f"---\n{text[:800]}"
        )

    out.append("## סעיפים מזוהים\n")
    out.append("| סעיף | טוב/רע | תיאור |")
    out.append("|------|--------|-------|")
    LABEL = {"good": "✅ טוב", "bad": "❌ רע", "neutral": "⚪ ניטרלי"}
    for name, desc, score in found:
        out.append(f"| {name} | {LABEL.get(score, '?')} | {desc[:80]}... |")

    good = [n for n, _, s in found if s == "good"]
    bad = [n for n, _, s in found if s == "bad"]
    out.append("\n## סיכום\n")
    if good:
        out.append("**טוב:**")
        out.extend(f"- {n}" for n in good)
    if bad:
        out.append("**דורש תשומת לב:**")
        out.extend(f"- {n}" for n in bad)
    if not good and not bad:
        out.append("המסמך ניטרלי — אין סעיפים מובהקים.")

    out.append("\n> ⚠️ **הנחיה:** זהו סיכום אוטומטי. יש להתייעץ עם מומחה לפני פעולה.")
    return "\n".join(out)


def analyze_with_profile(text: str, filename: str = "", profile_name: str = "") -> str:
    """Unified profile-based document analysis."""
    if not profile_name and detect_profile:
        profile_name = detect_profile(text, filename) or ""

    if not profile_name:
        return _analyze_contract_legacy(text, filename)

    profile = load_profile(profile_name) if load_profile else None
    if not profile:
        return (
            f"❌ Profile '{profile_name}' not found in config/profiles/. "
            "Falling back to legacy heuristic.\n\n"
            + _analyze_contract_legacy(text, filename)
        )

    items = profile.get("clauses") or profile.get("fields") or profile.get("sections") or []
    text_lower = text.lower()
    doc_type = profile.get("description", profile_name.replace("_", " ").title())

    def has_any(keywords) -> bool:
        return any(kw.lower() in text_lower for kw in (keywords or []))

    found: list[tuple[str, str, str]] = []
    for item in items:
        name = item.get("name", "Unknown")
        keywords = item.get("keywords", [])
        if not keywords or not has_any(keywords):
            continue
        score = _score_item(item, has_any)
        ctx = _find_context(keywords, text, text_lower) or f"נמצא: {', '.join(keywords[:2])}"
        found.append((name, ctx, score))

    return _format_profile_results(found, doc_type, filename, profile, profile_name, text)
