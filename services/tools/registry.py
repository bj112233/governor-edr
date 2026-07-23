# services/tools/registry.py
"""Core registry: ToolSpec dataclass + auto-generators."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from pydantic import BaseModel


@dataclass(frozen=True)
class ToolSpec:
    """Single tool definition consumed by LLM, MCP, and agent."""

    name: str
    description: str
    handler: Callable[..., Any]
    parameters: dict[str, Any] = field(default_factory=dict)
    expose_to_llm: bool = True
    expose_to_mcp: bool = True
    requires_approval: bool = False
    aliases: list[str] = field(default_factory=list)
    pydantic_model: type[BaseModel] | None = None
    safety_level: Literal["safe", "caution", "critical"] = "safe"
    requires_data_integrity: bool = True  # Fail-safe: new tools blocked on partial data by default

    def __post_init__(self):
        if self.pydantic_model is not None and not self.parameters:
            schema = self.pydantic_model.model_json_schema()
            object.__setattr__(self, "parameters", schema)


def to_openai_tools(registry: dict[str, ToolSpec]) -> list[dict[str, Any]]:
    """OpenAI function-calling schemas."""
    return [
        {
            "type": "function",
            "function": {
                "name": s.name,
                "description": s.description,
                "parameters": s.parameters,
            },
        }
        for s in registry.values()
        if s.expose_to_llm
    ]


def to_mcp_handlers(registry: dict[str, ToolSpec]) -> dict[str, Callable[..., Any]]:
    """name → callable for the MCP HTTP server."""
    return {s.name: s.handler for s in registry.values() if s.expose_to_mcp}


def to_mcp_schemas(registry: dict[str, ToolSpec]) -> list[dict[str, Any]]:
    """MCP `tools/list` schemas (uses `inputSchema` per MCP spec)."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "inputSchema": s.parameters,
        }
        for s in registry.values()
        if s.expose_to_mcp
    ]


def to_llm_map(registry: dict[str, ToolSpec]) -> dict[str, Callable[..., Any]]:
    """In-process callable map for all LLM-visible tools."""
    return {s.name: s.handler for s in registry.values() if s.expose_to_llm}
