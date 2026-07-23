"""Filesystem tools — Pydantic models + sandbox enforcement.

Extracted from fs_tools.py (SRP). Request/response models and the sandbox
guard that prevents path traversal outside project root / temp dirs.
"""

import tempfile
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field, field_validator


def _enforce_sandbox(path_str: str) -> str:
    """Security: ensure resolved path stays inside project root or allowed temp dirs.

    Raises ValueError if path escapes the sandbox.
    Returns the resolved path string.
    """
    p = Path(path_str).resolve()
    project_root = Path(__file__).resolve().parents[1]
    temp_dirs = [Path(tempfile.gettempdir()).resolve()]

    is_in_root = p == project_root or project_root in p.parents
    is_in_temp = any(p == t or t in p.parents for t in temp_dirs if t.exists())

    if not (is_in_root or is_in_temp):
        raise ValueError(f"Access denied: {path_str} outside project scope")
    return str(p)


# Extensions and exact file names blocked from READ (secrets, keys, config)
_READ_BLOCKED_SENSITIVE = {
    ".env",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".cert",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".toml",
    ".secret",
    ".private",
    ".token",
    ".passwd",
    ".htpasswd",
    ".credentials",
    ".vault",
    ".db",
    ".sqlite",
    ".sqlite3",
}

_BINARY_EXTS = {
    ".pdf",
    ".docx",
    ".xlsx",
    ".xls",
    ".pptx",
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tar",
    ".bz2",
    ".exe",
    ".dll",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".bmp",
    ".webp",
    ".mp3",
    ".mp4",
    ".avi",
    ".mkv",
    ".mov",
    ".wav",
}


class ReadFileRequest(BaseModel):
    """Request model for file read."""

    path: str = Field(..., description="File path (absolute or relative)")
    max_lines: int = Field(100, ge=1, le=1000, description="Max lines to read")

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        _enforce_sandbox(v)
        return v


class ListDirRequest(BaseModel):
    """Request model for directory listing."""

    path: str = Field(".", description="Directory path")
    show_hidden: bool = Field(False, description="Show hidden files")

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        _enforce_sandbox(v)
        return v


class SearchFilesRequest(BaseModel):
    """Request model for file search."""

    pattern: str = Field(..., description="Glob pattern, e.g., '*.py', '*.log'")
    path: str = Field(".", description="Base directory")
    recursive: bool = Field(True, description="Search recursively")

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        _enforce_sandbox(v)
        return v


class FileInfo(BaseModel):
    """Response model for file/directory info."""

    name: str
    type: str  # 'file' | 'directory'
    size: int | None = None
    modified: str | None = None


class ReadFileResponse(BaseModel):
    """Response model for file read."""

    path: str
    content: str
    lines_read: int
    total_lines: int | None = None
    truncated: bool = False


class ListDirResponse(BaseModel):
    """Response model for directory listing."""

    path: str
    entries: list[FileInfo]
    total: int


class SearchFilesResponse(BaseModel):
    """Response model for file search."""

    pattern: str
    matches: list[str]
    total: int
