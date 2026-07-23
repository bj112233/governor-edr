# services/fs_tools.py
"""
Level 150: Filesystem Tools — Pure Python stdlib

pathlib + os + glob — אין תלותיות חיצוניות.
Models + sandbox: fs_models.py. Tool wrappers: fs_tool_wrappers.py.
"""

import glob
import hashlib
from pathlib import Path

from services.fs_models import (
    _BINARY_EXTS,
    _READ_BLOCKED_SENSITIVE,
    FileInfo,
    ListDirRequest,
    ListDirResponse,
    ReadFileRequest,
    ReadFileResponse,
    SearchFilesRequest,
    SearchFilesResponse,
    _enforce_sandbox,
)


class FilesystemTools:
    """כלי filesystem מינימליסטיים — stdlib בלבד."""

    @staticmethod
    def read_file(req: ReadFileRequest) -> ReadFileResponse:
        """Read file contents with line limit."""
        p = Path(req.path)

        if not p.exists():
            return ReadFileResponse(
                path=str(p),
                content=f"❌ File not found: {req.path}",
                lines_read=0,
                truncated=False,
            )
        if not p.is_file():
            return ReadFileResponse(
                path=str(p),
                content=f"❌ Not a file: {req.path}",
                lines_read=0,
                truncated=False,
            )
        if p.suffix.lower() in _BINARY_EXTS:
            return ReadFileResponse(
                path=str(p.resolve()),
                content=f"📎 הקובץ {p.name} הוא פורמט בינארי ({p.suffix}). לא ניתן לקרוא כטקסט.",
                lines_read=0,
                total_lines=0,
                truncated=False,
            )
        if p.suffix.lower() in _READ_BLOCKED_SENSITIVE or p.name.lower() in _READ_BLOCKED_SENSITIVE:
            return ReadFileResponse(
                path=str(p.resolve()),
                content=f"🛡️ קובץ '{p.name}' מוגן (סיומת/שם רגיש). קריאה חסומה.",
                lines_read=0,
                total_lines=0,
                truncated=False,
            )

        # Probe first 4 KiB for null bytes (heuristic binary detection)
        try:
            with open(p, "rb") as probe:
                if b"\x00" in probe.read(4096):
                    return ReadFileResponse(
                        path=str(p.resolve()),
                        content=f"📎 הקובץ {p.name} זוהה כבינארי (null bytes). לא ניתן לקרוא כטקסט.",
                        lines_read=0,
                        total_lines=0,
                        truncated=False,
                    )
        except Exception:
            pass

        try:
            with open(p, encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                total = len(lines)
                if total > req.max_lines:
                    content_lines = lines[: req.max_lines]
                    truncated = True
                else:
                    content_lines = lines
                    truncated = False
                return ReadFileResponse(
                    path=str(p.resolve()),
                    content="".join(content_lines),
                    lines_read=len(content_lines),
                    total_lines=total,
                    truncated=truncated,
                )
        except Exception as e:
            return ReadFileResponse(
                path=str(p),
                content=f"❌ Error reading file: {e}",
                lines_read=0,
                truncated=False,
            )

    @staticmethod
    def list_directory(req: ListDirRequest) -> ListDirResponse:
        """List directory contents."""
        p = Path(req.path)
        if not p.exists() or not p.is_dir():
            return ListDirResponse(path=str(p), entries=[], total=0)

        entries = []
        try:
            for item in p.iterdir():
                if not req.show_hidden and item.name.startswith("."):
                    continue
                stat = item.stat()
                entries.append(
                    FileInfo(
                        name=item.name,
                        type="directory" if item.is_dir() else "file",
                        size=stat.st_size if item.is_file() else None,
                        modified=__import__("datetime")
                        .datetime.fromtimestamp(stat.st_mtime)
                        .strftime("%Y-%m-%d %H:%M"),
                    )
                )
            entries.sort(key=lambda x: (0 if x.type == "directory" else 1, x.name.lower()))
            return ListDirResponse(path=str(p.resolve()), entries=entries, total=len(entries))
        except Exception as e:
            return ListDirResponse(
                path=str(p),
                entries=[FileInfo(name=f"Error: {e}", type="file")],
                total=0,
            )

    @staticmethod
    def search_files(req: SearchFilesRequest) -> SearchFilesResponse:
        """Search files by glob pattern."""
        base = Path(req.path)
        if not base.exists() or not base.is_dir():
            return SearchFilesResponse(pattern=req.pattern, matches=[], total=0)

        try:
            pattern = f"**/{req.pattern}" if req.recursive else req.pattern
            matches = glob.glob(str(base / pattern), recursive=req.recursive)
            files = [str(Path(m).relative_to(base)) for m in matches if Path(m).is_file()]
            return SearchFilesResponse(pattern=req.pattern, matches=files, total=len(files))
        except Exception as e:
            return SearchFilesResponse(pattern=req.pattern, matches=[f"Error: {e}"], total=0)


def hash_file_tool(path: str) -> str:
    """מחשב SHA256 hash לקובץ — לבדיקת IOC מול VirusTotal."""
    try:
        safe_path = _enforce_sandbox(path)
        sha256 = hashlib.sha256()
        with open(safe_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return f"SHA256: {sha256.hexdigest()}"
    except Exception as e:
        return f"❌ Error: {e}"


# ── Re-exports for backward compatibility ──
from services.fs_tool_wrappers import (  # noqa: E402,F401
    list_directory_tool,
    read_file_tool,
    search_files_tool,
)
