"""
CLI output writer — render results and write to file or stdout.
"""

from pathlib import Path


def render_results(results) -> str:
    """Join (path, content) tuples into a single markdown string."""
    out_lines = []
    for p, content in results:
        out_lines.append(f"## {p}\n")
        out_lines.append(content)
        out_lines.append("")
    return "\n".join(out_lines)


def write_output(results, output_path) -> None:
    """Render ``results`` and either write to ``output_path`` or stdout."""
    final = render_results(results)
    if output_path:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(final)
        print(f"✅ Written to {out_path}")
        print(f"[FILE_EXPORT: {out_path}]")
    else:
        print(final)
