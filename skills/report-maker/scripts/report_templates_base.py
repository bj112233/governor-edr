"""Report Maker base templates — Markdown, HTML, CSV table, list formatting.

Extracted from report_templates.py (SRP).
"""
import html
from datetime import datetime


def md_template(title, content):
    return f"""---
title: {title}
date: {datetime.now().isoformat()}
---

# {title}

{content}
"""


def html_template(title, content, rtl=False, escape_content: bool = True):
    """Wrap title+content in HTML. If escape_content=True, content is treated as
    plaintext/Markdown-source (HTML-escaped); set False only when content is
    already safe HTML (e.g. table_from_csv output)."""
    dir_attr = 'dir="rtl"' if rtl else ""
    safe_title = html.escape(str(title))
    if escape_content:
        body = html.escape(str(content)).replace("\n", "<br>\n")
    else:
        body = str(content)
    return f"""<!DOCTYPE html>
<html lang="he" {dir_attr}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{safe_title}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.6; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background: #f5f5f5; }}
</style>
</head>
<body>
<h1>{safe_title}</h1>
<p><em>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}</em></p>
{body}
</body>
</html>
"""


def table_from_csv(path):
    import csv

    rows = []
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        for row in reader:
            rows.append(row)
    if not rows:
        return ""
    esc = html.escape
    out = ["<table>"]
    out.append("<tr>" + "".join(f"<th>{esc(c)}</th>" for c in rows[0]) + "</tr>")
    for row in rows[1:]:
        out.append("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>")
    out.append("</table>")
    return "\n".join(out)


def _format_list_item(item) -> str:
    """Format a JSON list item as a readable bullet line."""
    if isinstance(item, dict):
        for key in ("title", "name", "headline", "subject"):
            if key in item:
                head = str(item[key])
                rest = {k: v for k, v in item.items() if k != key}
                if rest:
                    tail = ", ".join(f"**{k}**: {v}" for k, v in rest.items())
                    return f"- {head} — {tail}"
                return f"- {head}"
        return "- " + ", ".join(f"**{k}**: {v}" for k, v in item.items())
    return f"- {item}"
