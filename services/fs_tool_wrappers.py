"""Filesystem tool wrappers — high-level convenience functions for the agent tool map.

Extracted from fs_tools.py (SRP). Each wrapper builds a request, calls the
corresponding FilesystemTools method, and formats the response as a string.
"""

from services.fs_models import ListDirRequest, ReadFileRequest, SearchFilesRequest
from services.fs_tools import FilesystemTools
from services.security_utils import wrap_untrusted_content


def read_file_tool(path: str, max_lines: int = 100) -> str:
    """Tool wrapper for agent."""
    try:
        req = ReadFileRequest(path=path, max_lines=max_lines)
        resp = FilesystemTools.read_file(req)
        # Only wrap actual file content (lines_read > 0), not system error messages
        if resp.lines_read > 0:
            safe_content = wrap_untrusted_content(resp.content, source_name=resp.path)
        else:
            safe_content = resp.content
        if resp.truncated:
            return f"📄 {resp.path} ({resp.lines_read}/{resp.total_lines} lines):\n{safe_content}\n...(truncated)"
        return f"📄 {resp.path} ({resp.lines_read} lines):\n{safe_content}"
    except Exception as e:
        return f"❌ Error: {e}"


def list_directory_tool(path: str = ".", show_hidden: bool = False) -> str:
    """Tool wrapper for agent."""
    req = ListDirRequest(path=path, show_hidden=show_hidden)
    resp = FilesystemTools.list_directory(req)

    if not resp.entries:
        return f"📁 {resp.path}: Empty or not found"

    lines = [f"📁 {resp.path} ({resp.total} items):"]
    for e in resp.entries:
        icon = "📂" if e.type == "directory" else "📄"
        size_str = f" ({e.size:,}B)" if e.size else ""
        lines.append(f"  {icon} {e.name}{size_str}")

    return "\n".join(lines)


def search_files_tool(pattern: str, path: str = ".") -> str:
    """Tool wrapper for agent."""
    req = SearchFilesRequest(pattern=pattern, path=path, recursive=True)
    resp = FilesystemTools.search_files(req)

    if not resp.matches:
        return f"🔍 No files matching '{resp.pattern}'"

    lines = [f"🔍 Found {resp.total} files matching '{resp.pattern}':"]
    for m in resp.matches[:20]:
        lines.append(f"  • {m}")
    if resp.total > 20:
        lines.append(f"  ... and {resp.total - 20} more")

    return "\n".join(lines)
