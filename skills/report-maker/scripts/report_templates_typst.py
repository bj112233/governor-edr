"""Report Maker Typst conversion — Markdown→Typst, template assembly.

Extracted from report_templates.py (SRP).
"""
import re
from datetime import datetime
from pathlib import Path


def _escape_typst(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _md_to_typst(md: str) -> str:
    """Basic Markdown → Typst. Best-effort for headings, bold, italic, links, lists."""
    text = re.sub(r"\*\*(.+?)\*\*", lambda m: f"«BOLD»{m.group(1)}«/BOLD»", md)
    text = re.sub(r"__(.+?)__", lambda m: f"«BOLD»{m.group(1)}«/BOLD»", text)

    def _italic(m):
        start = m.start()
        prefix = text[:start]
        open_count = prefix.count("«BOLD»") - prefix.count("«/BOLD»")
        if open_count > 0:
            return m.group(0)
        return f"_{m.group(1)}_"

    text = re.sub(r"(?<!\*)\*(.+?)\*(?!\*)", _italic, text)
    text = text.replace("«BOLD»", "*").replace("«/BOLD»", "*")
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'#link("\2")[\1]', text)

    lines = text.splitlines()
    out: list[str] = []
    table_buffer: list[list[str]] = []

    def _flush_table():
        nonlocal table_buffer, out
        if not table_buffer:
            return
        cols = max(len(r) for r in table_buffer)
        flat = [f'"{_escape_typst(c)}"' for r in table_buffer for c in r]
        out.append(f"#table(columns: {cols}, {', '.join(flat)})")
        table_buffer = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            inner = stripped[1:-1]
            if all(c in " |:-\n\r\t" for c in inner):
                continue
            cells = [c.strip() for c in inner.split("|")]
            table_buffer.append(cells)
            continue
        else:
            _flush_table()

        if stripped.startswith("### "):
            out.append("=== " + stripped[4:])
        elif stripped.startswith("## "):
            out.append("== " + stripped[3:])
        elif stripped.startswith("# "):
            out.append("= " + stripped[2:])
        else:
            out.append(line)

    _flush_table()
    return "\n".join(out)


def _build_typst(title: str, body: str, rtl: bool) -> str:
    """Assemble a .typ source string using the embedded default template."""
    tpl_path = Path(__file__).parent.parent / "templates" / "default.typ"
    tpl = (
        tpl_path.read_text(encoding="utf-8")
        if tpl_path.is_file()
        else _DEFAULT_TYPST_TEMPLATE
    )
    dt = datetime.now().strftime("%Y-%m-%d %H:%M")
    return (
        tpl.replace("__TITLE__", _escape_typst(title))
        .replace("__DATE__", _escape_typst(dt))
        .replace("__BODY__", body)
        .replace("__RTL__", "true" if rtl else "false")
    )


_DEFAULT_TYPST_TEMPLATE = """#let rtl = __RTL__
#set page(margin: (x: 2cm, y: 2cm))
#set text(size: 11pt)
#set heading(numbering: none)
#if rtl {
  set text(dir: rtl, lang: "he")
}
#align(center)[
  #text(size: 18pt, weight: "bold")[__TITLE__]
  #linebreak()
  #text(size: 10pt, style: "italic")[__DATE__]
]
#v(1em)
__BODY__
"""
