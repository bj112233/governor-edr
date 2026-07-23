# services/tools_registry.py
"""
Single source of truth for all tool definitions.

Auto-generates:
  - OpenAI function-calling schemas (consumed by `services.agent_tools._TOOLS`)
  - MCP HTTP server handler map     (consumed by `services.local_mcp_server._TOOL_REGISTRY`)
  - MCP HTTP server schema list     (consumed by `services.local_mcp_server._TOOL_SCHEMAS`)
  - Agent in-process callable map   (`LLM_TOOL_MAP`)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from services.tools.file_tools import get_file_tools
from services.tools.mcp_tools import get_mcp_tools
from services.tools.memory_tools import get_memory_tools
from services.tools.registry import ToolSpec
from services.tools.security_tools import get_security_tools
from services.tools.system_tools import get_system_tools

# ---------------------------------------------------------------------------
# REGISTRY
# ---------------------------------------------------------------------------

REGISTRY: dict[str, ToolSpec] = {
    s.name: s
    for s in (get_system_tools() + get_file_tools() + get_memory_tools() + get_security_tools() + get_mcp_tools())
}

# ---------------------------------------------------------------------------
# Schema compression — Token Diet for 4B SLMs
# ---------------------------------------------------------------------------


def _slim_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Strip optional params, titles, and defaults from Pydantic JSON schema.

    Keeps only *required* properties with minimal metadata (description + type).
    The full Pydantic model is still used for validation at execution time —
    optional params receive their defaults automatically.

    Token savings: ~15-25 tokens per stripped optional parameter.
    """
    if not schema:
        return {"type": "object", "properties": {}}

    props = schema.get("properties", {})
    required = set(schema.get("required", []))

    # No properties (NoArgs) or no required fields — minimal schema
    if not props or not required:
        return {"type": "object", "properties": {}}

    slim_props: dict[str, Any] = {}
    for name, prop in props.items():
        if name not in required:
            continue
        # Keep only description + type; drop title, default, $defs
        slim_prop: dict[str, Any] = {"type": prop["type"]} if "type" in prop else {}
        if "description" in prop:
            slim_prop["description"] = prop["description"]
        slim_props[name] = slim_prop

    return {
        "type": "object",
        "properties": slim_props,
        "required": sorted(required),
    }


# ---------------------------------------------------------------------------
# Auto-generators
# ---------------------------------------------------------------------------


def to_openai_tools() -> list[dict[str, Any]]:
    """OpenAI function-calling schemas — slim for LLM token budget.

    Uses _slim_schema() to strip optional params and metadata.
    Tools in FLAT_CONTRACTS get a flat 1D schema (no nesting) to prevent
    4B model flattening errors.
    Full Pydantic models are still used for validation in execute_tool().
    """
    from services.tools.flat_args import get_flat_schema

    return [
        {
            "type": "function",
            "function": {
                "name": s.name,
                "description": s.description,
                "parameters": get_flat_schema(s.name, _slim_schema(s.parameters)),
            },
        }
        for s in REGISTRY.values()
        if s.expose_to_llm
    ]


def to_mcp_handlers() -> dict[str, Callable[..., Any]]:
    """name → callable for the MCP HTTP server."""
    return {s.name: s.handler for s in REGISTRY.values() if s.expose_to_mcp}


def to_mcp_schemas() -> list[dict[str, Any]]:
    """MCP `tools/list` schemas (uses `inputSchema` per MCP spec)."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "inputSchema": s.parameters,
        }
        for s in REGISTRY.values()
        if s.expose_to_mcp
    ]


# In-process callable map for all LLM-visible tools.
LLM_TOOL_MAP: dict[str, Callable[..., Any]] = {s.name: s.handler for s in REGISTRY.values() if s.expose_to_llm}


__all__ = [
    "ToolSpec",
    "REGISTRY",
    "to_openai_tools",
    "to_mcp_handlers",
    "to_mcp_schemas",
    "LLM_TOOL_MAP",
]
