"""
Report Maker — thin CLI wrapper.

Parses args, selects a content template (report_templates), converts to the
requested output format (FormatConverter), then writes to disk or stdout.
All template/format logic lives in report_templates.py + format_converter.py.
"""

import argparse
import json
import sys
from pathlib import Path

from format_converter import BackendUnavailable, FormatConverter
from report_templates import (
    _briefing_template,
    _contract_template,
    _daily_digest_template,
    _format_list_item,
    _incident_report_template,
    _security_audit_template,
    _timeline_template,
    _watchlist_template,
    table_from_csv,
)

_TEMPLATES = [
    "default",
    "table",
    "briefing",
    "timeline",
    "daily_digest",
    "contract",
    "watchlist",
    "incident_report",
    "security_audit",
]


def _read_raw(args) -> str:
    """Resolve raw input text from --stdin / --inputs / --input."""
    if args.stdin:
        return sys.stdin.read()
    if args.inputs:
        parts = []
        for p in [s.strip() for s in args.inputs.split(",") if s.strip()]:
            try:
                parts.append(f"# {p}\n\n" + Path(p).read_text(encoding="utf-8"))
            except OSError as e:
                parts.append(f"# {p}\n\n❌ read error: {e}")
        return "\n\n---\n\n".join(parts)
    if args.input:
        input_path = Path(args.input)
        if input_path.exists():
            try:
                with open(args.input, encoding="utf-8") as f:
                    return f.read()
            except (PermissionError, OSError) as exc:
                print(f"❌ ERROR: Cannot read '{args.input}': {exc}. Do not retry with this tool.")
                sys.exit(3)
        # Fallback: treat as inline JSON / raw data
        try:
            json.loads(args.input)
            return args.input
        except json.JSONDecodeError:
            print(
                f"❌ --input must be a path to an existing file, or valid inline JSON. "
                f"Got: '{args.input}'"
            )
            sys.exit(1)
    print("❌ --input, --inputs, or --stdin required")
    sys.exit(1)


def _build_content(args, raw: str) -> str:
    """Render the requested content template into a Markdown/text body."""
    data = None
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            content = "\n".join(_format_list_item(item) for item in data)
        else:
            content = json.dumps(data, ensure_ascii=False, indent=2)
    except json.JSONDecodeError:
        content = raw

    t = args.template
    if t == "table" and args.input and args.input.endswith(".csv"):
        content = table_from_csv(args.input)
    elif t == "briefing":
        content = _briefing_template(data if isinstance(data, list) else None, raw)
    elif t == "timeline":
        content = _timeline_template(data if isinstance(data, list) else None, raw)
    elif t == "daily_digest":
        content = _daily_digest_template(data if isinstance(data, dict) else None, raw)
    elif t == "contract":
        content = _contract_template(data if isinstance(data, dict) else None, raw)
    elif t == "watchlist":
        content = _watchlist_template(data if isinstance(data, list) else None, raw)
    elif t == "incident_report":
        content = _incident_report_template(
            data if isinstance(data, dict) else None, raw
        )
    elif t == "security_audit":
        content = _security_audit_template(
            data if isinstance(data, dict) else None, raw
        )
    return content


def main():
    # Force UTF-8 stdout on Windows to avoid cp1255 encoding errors
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser()
    parser.add_argument("--input")
    parser.add_argument(
        "--inputs",
        help="Comma-separated list of files to merge (Markdown/JSON/text)",
    )
    parser.add_argument("--stdin", action="store_true")
    parser.add_argument("--template", choices=_TEMPLATES, default="default")
    parser.add_argument(
        "--format", choices=["markdown", "html", "pdf", "typst-pdf"], default="markdown"
    )
    parser.add_argument("--output")
    parser.add_argument("--title", default="Report")
    args = parser.parse_args()

    raw = _read_raw(args)

    # Detect RTL
    rtl = any(0x0590 <= ord(c) <= 0x08FF for c in raw)

    content = _build_content(args, raw)

    # `table` template emits raw HTML via table_from_csv → safe to render verbatim.
    is_safe_html = (
        args.template == "table" and args.input and args.input.endswith(".csv")
    )

    conv = FormatConverter()

    if args.format in ("html", "pdf"):
        out = conv.to_html(
            args.title, content, rtl=rtl, escape_content=not is_safe_html
        )
    else:
        out = conv.to_markdown(args.title, content)

    if args.format == "pdf":
        if not args.output:
            print("❌ --output required for PDF format")
            sys.exit(1)
        try:
            conv.to_pdf(out, args.output)
        except BackendUnavailable as e:
            print(
                f"❌ WeasyPrint לא זמין: {e}\n"
                "   pip install weasyprint\n"
                "   Windows: גם נדרשים GTK3 binaries (MSYS2: pacman -S mingw-w64-x86_64-pango mingw-w64-x86_64-gdk-pixbuf2)\n"
                "   הגדר GTK_BIN למיקום bin של GTK אם אינו ב־PATH."
            )
            sys.exit(2)
        except Exception as e:
            print(f"❌ PDF generation failed: {e}")
            sys.exit(3)
        print(f"✅ PDF saved to {args.output}")
        return

    if args.format == "typst-pdf":
        if not args.output:
            print("❌ --output required for typst-pdf format")
            sys.exit(1)
        try:
            conv.to_typst_pdf(args.title, content, rtl, args.output)
        except BackendUnavailable:
            print(
                "❌ Typst binary not found.\n"
                "   Download from https://github.com/typst/typst/releases\n"
                "   Place typst.exe in the project bin/ directory."
            )
            sys.exit(2)
        except Exception as e:
            print(f"❌ Typst compilation failed:\n{e}")
            sys.exit(3)
        print(f"✅ Typst PDF saved to {args.output}")
        return

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except (FileNotFoundError, PermissionError, OSError) as exc:
            print(f"❌ ERROR: Cannot write to '{args.output}': {exc}. Do not retry with this tool.")
            sys.exit(3)
        print(f"✅ Report saved to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
