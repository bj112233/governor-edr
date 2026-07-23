"""
Document analyzers — contract analysis, datasheet extraction, smart summarization.

Profile-based analysis extracted to _analyzers_profile.py (SRP).
"""
import os
import re

try:
    from profile_loader import detect_profile, get_profile_category, load_profile
except ImportError:
    detect_profile = None
    get_profile_category = None
    load_profile = None

from _analyzers_profile import _analyze_contract_legacy, analyze_with_profile  # noqa: F401


def pdf_to_markdown(path: str, engine: str = "auto") -> str:
    """Convert PDF to Markdown via MarkItDown.

    Args:
        engine: ignored (kept for backward compatibility)
    """
    try:
        from markitdown import MarkItDown

        md = MarkItDown()
        result = md.convert(path)
        return result.text_content
    except ImportError:
        return "❌ MarkItDown not installed. Run: pip install markitdown"
    except Exception as e:
        return f"❌ MarkItDown error: {e}"


def analyze_contract(text: str, filename: str = "") -> str:
    """
    Analyze contract using profile-based analysis.
    Auto-detects contract type from text/filename, or defaults to rental_contract.
    Falls back to generic pattern matching if profile unavailable.
    """
    contract_type = None
    if detect_profile:
        detected = detect_profile(text, filename)
        if detected and get_profile_category and get_profile_category(detected) == "contracts":
            contract_type = detected

    if not contract_type:
        contract_type = "rental_contract"

    return analyze_with_profile(text, filename, profile_name=contract_type)


def smart_summarize(text: str, lines: int = 10) -> str:
    """Summarize large documents by extracting key sections, not just first paragraphs."""
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    if not paragraphs:
        return "(ריק)"

    total_len = len(text)
    full_threshold = int(os.getenv("SENTINEL_SUMMARY_FULL_THRESHOLD", "32000"))
    if total_len < full_threshold or len(paragraphs) <= lines:
        return "\n\n".join(paragraphs)

    section_headers = re.compile(
        r"^(?:\d+\.\s*)?(?:Features?|Overview|Description|Specifications?|"
        r"Electrical\s+Characteristics|Absolute\s+Maximum\s+Ratings|Pin\s+Configuration|"
        r"Pinout|Typical\s+Applications?|Applications?|Package\s+Information|"
        r"Block\s+Diagram|Functional\s+Diagram|Recommended\s+Operating\s+Conditions|"
        r"Ordering\s+Information|Revision\s+History|Contents?|Table\s+of\s+Contents|"
        r"מפרט|תיאור|מאפיינים|מפרט\s+טכני|חיבורים|יישומים|מידות|תוכן\s+עניינים|"
        r"רקע|פרטי\s+המטופל|בדיקה|סיכום|ממצאים|אבחנה|טיפול|המלצות|"
        r"דף\s+ראשון|פתיחה|תוצאות|בירורים|בדיקות|רפואה|מדיקציה|"
        r"משפחה|התפתחות|תרופות|משקל|גובה|נוירולוג|פסיכולוג|רופא|"
        r"היסטוריה\s+רפואית|Background|Patient\s+Info|History|Findings|"
        r"Conclusions|Recommendations|Summary|Tests|Results|Medications|"
        r"Family\s+History|Development|Physical\s+Exam|Examination|Diagnosis|"
        r"Assessment|Plan|Treatment|Follow.up|Followup|Notes|Report)",
        re.IGNORECASE | re.MULTILINE,
    )

    sections = []
    current_header = "(הקדמה)"
    for para in paragraphs:
        m = section_headers.match(para.split("\n")[0])
        if m:
            current_header = m.group(0).strip()
            sections.append((current_header, para))
        elif sections and len(sections[-1][1]) < 1200:
            sections[-1] = (sections[-1][0], sections[-1][1] + "\n" + para)

    if sections:
        seen = set()
        out = []
        for hdr, para in sections:
            key = hdr.lower()[:30]
            if key not in seen:
                seen.add(key)
                out.append(f"**{hdr}**\n{para[:1200]}")
            if len(out) >= lines:
                break
        summary = "\n\n".join(out)
        return (
            f"# סיכום מסמך ({len(paragraphs)} פסקאות, {total_len:,} תווים)\n\n{summary}"
        )

    return "\n\n".join(paragraphs[:lines])


def analyze_datasheet(text: str, filename: str = "") -> str:
    """Extract key sections from an IC / amplifier datasheet."""
    lines = text.split("\n")
    seen = set()
    unique_lines = []
    for line in lines:
        line = line.strip()
        if line and line not in seen and len(line) > 5:
            seen.add(line)
            unique_lines.append(line)
    text = "\n".join(unique_lines)

    out = [f"# Datasheet Analysis: {filename}\n"]

    def find_section(headers, max_chars=800):
        pat = re.compile(
            r"(?:^|\n)(?:\d+\.\s*)?("
            + "|".join(re.escape(h) for h in headers)
            + r")\s*[:\n](.*?)(?=\n(?:\d+\.\s*)?[A-Z][A-Za-z\s]{3,40}\s*[:\n]|\Z)",
            re.IGNORECASE | re.DOTALL,
        )
        m = pat.search(text)
        if m:
            return m.group(2).strip()[:max_chars]
        for para in text.split("\n\n"):
            if any(h.lower() in para.lower() for h in headers):
                return para.strip()[:max_chars]
        return None

    first_line = text.strip().split("\n")[0][:100]
    out.append(f"**Device:** {first_line}\n")

    features = find_section(["Features", "Key Features", "Highlights", "מאפיינים", "תכונות"])
    if features:
        out.append(f"## Features\n{features}\n")

    desc = find_section(["Description", "General Description", "Overview", "תיאור", "תיאור כללי"])
    if desc:
        out.append(f"## Description\n{desc}\n")

    spec_lines = []
    for line in text.split("\n"):
        line_stripped = line.strip()
        if re.search(r"\d+\s*(V|A|W|Ω|Hz|dB|%|°C|mm)\b", line_stripped) and len(line_stripped) < 120:
            if any(kw in line_stripped.lower() for kw in [
                "power", "voltage", "current", "thd", "efficiency",
                "frequency", "impedance", "gain", "snr", "power supply",
                "output", "input", "load", "temperature",
                "רמת עצמה", "מתח", "זרם", "עומס", "תדר", "רווח",
            ]):
                spec_lines.append(line_stripped)
    if spec_lines:
        out.append("## Key Specifications")
        for line in spec_lines[:15]:
            out.append(f"- {line}")
        out.append("")

    pinout = find_section(["Pin Configuration", "Pinout", "Pin Assignments", "Package", "חיבורים", "רגלי IC"])
    if pinout:
        out.append(f"## Pinout / Package\n{pinout}\n")

    absmax = find_section(["Absolute Maximum Ratings", "Maximum Ratings", "Limiting Values", "Safe Operating", "מדדי בטיחות"])
    if absmax:
        out.append(f"## Absolute Maximum Ratings\n{absmax}\n")

    apps = find_section(["Applications", "Typical Applications", "Application Information", "יישומים", "שימושים"])
    if apps:
        out.append(f"## Applications\n{apps}\n")

    if len(out) == 1:
        out.append("⚠️ לא זוהו סעיפי datasheet טיפוסיים. מציג סיכום כללי:\n")
        out.append(smart_summarize(text, lines=8))

    out.append(f"\n---\n📄 מסמך: {filename} | תווים: {len(text):,} | פסקאות: {len(text.split(chr(10)))}")
    return "\n".join(out)
