# services/telegram/formatting.py
"""Text formatting and chunking for Telegram output (Markdown → Entities)."""

import html
import logging
import re

logger = logging.getLogger(__name__)


def _md_link_to_html(m: "re.Match[str]") -> str:
    title = m.group(1)
    url = html.unescape(m.group(2).strip())
    if not url or not re.match(r"^(https?|tg)://", url, re.I):
        return title
    url_safe = html.escape(url, quote=True)
    return f'<a href="{url_safe}">{title}</a>'


def _hdr_to_bold(m: "re.Match[str]") -> str:
    return f"<b>{m.group(1)}</b>"


def _bold_to_html(m: "re.Match[str]") -> str:
    return f"<b>{m.group(1)}</b>"


def _italic_to_html(m: "re.Match[str]") -> str:
    return f"<i>{m.group(1)}</i>"


def _bt_to_code(m: "re.Match[str]") -> str:
    return f"<code>{m.group(1)}</code>"


def _format_table_rows(table_rows: list[str]) -> list[str]:
    """Convert collected markdown table rows to bullet-list lines."""
    data_rows = [r for r in table_rows if not re.match(r"^[\s|:\-]+$", r)]
    if not data_rows or len(data_rows) <= 1:
        return []
    headers = [c.strip() for c in data_rows[0][1:-1].split("|")]
    out = [""]
    for row in data_rows[1:]:
        cells = [c.strip() for c in row[1:-1].split("|")]
        row_parts = [f"{headers[i]}: {cell}" if i < len(headers) else cell for i, cell in enumerate(cells)]
        out.append("• " + " | ".join(row_parts))
    out.append("")
    return out


def _md_table_to_plaintext(text: str) -> str:
    """Convert pipe-delimited markdown tables to plain text bullet list."""
    lines = text.splitlines()
    out_lines: list[str] = []
    table_rows: list[str] = []
    in_table = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("|") and stripped.endswith("|"):
            in_table = True
            table_rows.append(stripped)
        else:
            if in_table and table_rows:
                out_lines.extend(_format_table_rows(table_rows))
                table_rows = []
                in_table = False
            out_lines.append(line)

    if in_table and table_rows:
        out_lines.extend(_format_table_rows(table_rows))

    return "\n".join(out_lines)


def strip_markdown(text: str) -> str:
    """Remove Markdown formatting for Telegram, but preserve links by
    converting ``[title](url)`` → ``<a href="url">title</a>`` so they remain
    clickable under parse_mode='HTML'."""

    text = html.escape(text, quote=False)
    text = re.sub(r"\[([^\]\n]+)\]\(([^)\s]+)\)", _md_link_to_html, text)
    text = re.sub(r"^#{1,6}\s+(.+)$", _hdr_to_bold, text, flags=re.MULTILINE)
    text = re.sub(r"\*{2,3}(.*?)\*{2,3}", _bold_to_html, text, flags=re.DOTALL)
    text = re.sub(r"\*([^\*\n]+)\*", _italic_to_html, text)
    text = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", _italic_to_html, text)
    text = re.sub(r"`{3}(.*?)`{3}", _bt_to_code, text, flags=re.DOTALL)
    text = re.sub(r"`([^`\n]+)`", _bt_to_code, text)
    text = _md_table_to_plaintext(text)
    text = re.sub(r"^\|.*\|$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^[\s|:\-]+$", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _chunk_newline_mode(text: str, limit: int) -> list[str]:
    """Split text on paragraphs, hard-split oversized paragraphs."""
    chunks: list[str] = []
    current = ""
    for para in text.split("\n\n"):
        if len(para) > limit:
            if current:
                chunks.append(current.strip())
                current = ""
            for i in range(0, len(para), limit):
                piece = para[i : i + limit]
                if i + limit >= len(para):
                    current = piece + "\n\n"
                else:
                    chunks.append(piece)
            continue
        if len(current) + len(para) + 2 <= limit:
            current += para + "\n\n"
        else:
            if current:
                chunks.append(current.strip())
            current = para + "\n\n"
    if current:
        chunks.append(current.strip())
    return chunks


def chunk_text(text: str, limit: int, mode: str) -> list[str]:
    """Split text into chunks based on config."""
    if len(text) <= limit:
        return [text]
    if mode == "newline":
        chunks = _chunk_newline_mode(text, limit)
    else:
        chunks = [text[i : i + limit] for i in range(0, len(text), limit)]
    return chunks if chunks else [text]


# Re-export entity conversion for centralised imports.
from services.telegram.entities import markdown_to_entities  # noqa: E402,F401
