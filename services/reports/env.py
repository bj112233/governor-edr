# services/reports/env.py
"""Shared Jinja2 Environment for batch-job report templates (SITREP,
reflection, daily digest, news).

autoescape=False: reports are Markdown text destined for the Telegram
pipeline (services.telegram.formatting.strip_markdown → html.escape),
NOT raw HTML. Jinja2's HTML autoescaping would double-escape/corrupt
`&`, `<`, `>` before they ever reach that pipeline.
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from services.telegram.headers import format_header

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env: Environment | None = None


def get_report_env() -> Environment:
    """Return the shared Jinja2 Environment (lazy singleton).

    Registers format_header() as a template global so base.j2 stays the
    single source of header formatting — no duplicated separator/layout
    logic between Python and Jinja2.
    """
    global _env
    if _env is None:
        _env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=False,  # noqa: S701 — Markdown output, not HTML (see module docstring)
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        _env.globals["format_header"] = format_header
    return _env
