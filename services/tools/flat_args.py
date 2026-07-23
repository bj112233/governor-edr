# services/tools/flat_args.py
"""Flat argument contracts for tools with nested/multi-field schemas.

4B models on KoboldCpp tend to "flatten" complex nested arguments instead of
maintaining hierarchical structure. This module defines flat contracts for
tools that are prone to flattening — the LLM-facing schema is reduced to a
1-dimensional set of string fields, while the full Pydantic model is still
used for validation at execution time.

FLAT_CONTRACTS maps tool name → list of essential field names (1D).
Tools not in this map use their original schema unchanged.
"""

from typing import Any

# Tools with nested/multi-field args that 4B models flatten.
# Each entry: tool_name → [field_name, ...] (order = schema order).
FLAT_CONTRACTS: dict[str, list[str]] = {
    # Builtin tools with multiple required fields
    "manage_service": ["action", "name"],
    # OSINT tools — single field but model often wraps in nested dict
    "scan_infrastructure": ["domain"],
    "scan_credential_leaks": ["query"],
    "query_ioc_history": ["ioc"],
}

# Synonym map: model-emitted field name → canonical field name.
# The 4B model confuses field names (e.g. "ip" instead of "target").
_SYNONYMS: dict[str, str] = {
    "ip": "target",
    "domain": "target",
    "query": "target",
    "host": "target",
    "address": "target",
    "addr": "target",
    "url": "target",
    "filepath": "path",
    "file": "path",
    "filename": "path",
    "file_path": "path",
    "pid": "pid",  # canonical
    "process_id": "pid",
    "action_type": "action",
    "service": "name",
    "service_name": "name",
    "ioc_value": "ioc",
    "indicator": "ioc",
    "hash": "ioc",
    "domain_name": "domain",
}

# Wrapper keys that the 4B model nests around real args — strip these.
_WRAPPER_KEYS = frozenset({"input", "data", "payload", "params", "arguments", "options", "body"})


def get_flat_schema(tool_name: str, original_schema: dict[str, Any]) -> dict[str, Any]:
    """Return a flat 1D schema for the tool, or the original if not in contracts.

    Flat schema: all fields become top-level string properties with descriptions
    from the original schema. No nesting, no $defs, no arrays of objects.
    """
    if tool_name not in FLAT_CONTRACTS:
        return original_schema

    fields = FLAT_CONTRACTS[tool_name]
    original_props = original_schema.get("properties", {})
    flat_props: dict[str, Any] = {}
    for field_name in fields:
        orig = original_props.get(field_name, {})
        flat_props[field_name] = {
            "type": orig.get("type", "string"),
            "description": orig.get("description", f"{field_name} parameter"),
        }
    return {
        "type": "object",
        "properties": flat_props,
        "required": fields,
    }


def is_flat_tool(tool_name: str) -> bool:
    """True if this tool has a flat contract (schema should be flattened)."""
    return tool_name in FLAT_CONTRACTS


def normalize_flat_args(tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Normalize model-emitted args for a flat-contract tool.

    Applies 4 extraction layers:
    1. Wrapper-strip: remove input/data/payload wrappers, keep inner dict.
    2. Synonym mapping: ip/domain/query → target, etc.
    3. Positional extraction: if model emitted a bare value, assign to first field.
    4. Field filtering: keep only canonical fields from FLAT_CONTRACTS.

    Returns a dict with only canonical field names.
    """
    if tool_name not in FLAT_CONTRACTS:
        return args

    canonical_fields = FLAT_CONTRACTS[tool_name]
    normalized: dict[str, Any] = {}

    # Layer 1: Strip wrapper keys
    working = dict(args)
    for wrapper in _WRAPPER_KEYS:
        val = working.get(wrapper)
        if isinstance(val, dict):
            # Merge inner dict, remove wrapper
            for k, v in val.items():
                if k not in working:
                    working[k] = v
            working.pop(wrapper, None)

    # Layer 2: Synonym mapping
    for key, val in working.items():
        canonical = _SYNONYMS.get(key.lower(), key)
        if canonical in canonical_fields:
            if canonical not in normalized:  # don't overwrite existing canonical
                normalized[canonical] = val

    # Layer 3: Positional extraction — bare value → first field
    if not normalized and len(working) == 1:
        sole_val = next(iter(working.values()))
        if not isinstance(sole_val, dict):
            normalized[canonical_fields[0]] = sole_val

    # Layer 4: Keep only canonical fields (drop extras)
    return {k: v for k, v in normalized.items() if k in canonical_fields}
