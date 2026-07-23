# services/tools/file_tools.py
"""Filesystem tool definitions."""

from pydantic import BaseModel, Field

from services.action_tools import write_file
from services.fs_tools import (
    hash_file_tool,
    list_directory_tool,
    read_file_tool,
    search_files_tool,
)
from services.tools.registry import ToolSpec


class ReadFileArgs(BaseModel):
    path: str = Field(..., description="File path (relative or absolute)")
    max_lines: int = Field(100, description="Max lines to read (default 100)")


class ListDirectoryArgs(BaseModel):
    path: str = Field(".", description="Directory path (default: current)")
    show_hidden: bool = Field(False, description="Show hidden files")


class SearchFilesArgs(BaseModel):
    pattern: str = Field(..., description="Search pattern (glob)")
    path: str = Field(".", description="Base directory")


class HashFileArgs(BaseModel):
    path: str = Field(..., description="File path to hash")


class WriteFileArgs(BaseModel):
    path: str = Field(..., description="File path (within project root)")
    content: str = Field(..., description="Full content to write")


def get_file_tools() -> list[ToolSpec]:
    """Return all filesystem tools."""
    return [
        ToolSpec(
            name="read_file",
            description="Read file contents.",
            pydantic_model=ReadFileArgs,
            handler=lambda path, max_lines=100, **_: read_file_tool(str(path), int(max_lines)),
            safety_level="safe",
            requires_data_integrity=False,
        ),
        ToolSpec(
            name="list_directory",
            description="List directory contents.",
            pydantic_model=ListDirectoryArgs,
            handler=lambda path=".", show_hidden=False, **_: list_directory_tool(str(path), bool(show_hidden)),
        ),
        ToolSpec(
            name="search_files",
            description="Find files by glob pattern.",
            pydantic_model=SearchFilesArgs,
            handler=lambda pattern, path=".", **_: search_files_tool(str(pattern), str(path)),
        ),
        ToolSpec(
            name="hash_file",
            description="SHA256 of file (IOC check).",
            pydantic_model=HashFileArgs,
            handler=lambda path, **_: hash_file_tool(str(path)),
        ),
        ToolSpec(
            name="write_file",
            description="Write file (project dir only, no .py/.env/.db).",
            pydantic_model=WriteFileArgs,
            handler=lambda path, content, **_: write_file(str(path), str(content)),
            safety_level="critical",
            requires_data_integrity=True,
        ),
    ]
