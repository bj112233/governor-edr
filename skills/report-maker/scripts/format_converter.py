"""Report Maker — synchronous format conversion layer.

FormatConverter owns the output-format concern: Markdown / HTML / PDF (WeasyPrint
inline) / Typst-PDF (typst.exe subprocess). NO async / ProcessPool: this script
already runs as an isolated OS subprocess under the SkillsEngine executor, so the
agent event loop is never blocked. Adding internal pooling would only add IPC
overhead and zombie-process risk for a single one-shot conversion.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from report_templates import _build_typst, _md_to_typst, html_template, md_template


class BackendUnavailable(Exception):
    """Raised when a required conversion backend (WeasyPrint / Typst) is missing."""


def _ensure_gtk_on_path() -> None:
    """Inject MSYS2 GTK3 bin into PATH on Windows so WeasyPrint can locate libgobject/pango/cairo."""
    if sys.platform != "win32":
        return
    candidates = [
        os.environ.get("GTK_BIN"),
        r"C:\msys64\mingw64\bin",
        r"C:\Program Files\GTK3-Runtime Win64\bin",
    ]
    for c in candidates:
        if (
            c
            and os.path.isdir(c)
            and c.lower() not in os.environ.get("PATH", "").lower()
        ):
            os.environ["PATH"] = c + os.pathsep + os.environ.get("PATH", "")
            return


def _find_typst() -> str | None:
    """Locate typst binary: project bin/ → PATH → None."""
    candidates = [
        Path(__file__).resolve().parents[3] / "bin" / "typst.exe",
        Path(__file__).resolve().parents[3] / "bin" / "typst",
        shutil.which("typst"),
    ]
    for c in candidates:
        if c and os.path.isfile(str(c)):
            return str(c)
    return None


class FormatConverter:
    """Stateless, synchronous output-format converter."""

    def to_markdown(self, title: str, content: str) -> str:
        return md_template(title, content)

    def to_html(
        self, title: str, content: str, rtl: bool = False, escape_content: bool = True
    ) -> str:
        return html_template(title, content, rtl=rtl, escape_content=escape_content)

    def to_pdf(self, html_str: str, output_path: str) -> None:
        """Render HTML → PDF via WeasyPrint (inline, in this subprocess).

        Raises BackendUnavailable if WeasyPrint/GTK is missing; other exceptions
        propagate as generation failures.
        """
        _ensure_gtk_on_path()
        try:
            from weasyprint import HTML  # type: ignore
        except (ImportError, OSError) as e:
            raise BackendUnavailable(str(e)) from e
        HTML(string=html_str).write_pdf(output_path)

    def to_typst_pdf(
        self, title: str, content: str, rtl: bool, output_path: str
    ) -> None:
        """Render content → Typst → PDF via typst.exe (subprocess).

        Raises BackendUnavailable if typst binary not found; RuntimeError on
        compilation failure.
        """
        typst_bin = _find_typst()
        if not typst_bin:
            raise BackendUnavailable("typst")
        typ_body = _md_to_typst(content)
        typ_src = _build_typst(title, typ_body, rtl)
        tmpdir = Path(tempfile.gettempdir()) / "report_maker_typst"
        tmpdir.mkdir(parents=True, exist_ok=True)
        typ_path = tmpdir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.typ"
        typ_path.write_text(typ_src, encoding="utf-8")
        try:
            result = subprocess.run(
                [typst_bin, "compile", str(typ_path), output_path],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr)
        finally:
            try:
                typ_path.unlink()
            except OSError:
                pass
