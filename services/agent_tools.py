# services/agent_tools.py
"""
Tool schemas and execution engine for the agent.

Schemas, MCP-routing set, and in-process callable map are all derived from
`services.tools_registry` (single source of truth). To add or change a tool,
edit `services/tools_registry.py` only.
"""

import asyncio
import inspect
import json
import logging
from typing import Any

from pydantic import ValidationError

from config import TOOL_OUTPUT_MAX_CHARS
from services.skills_engine import get_skills_engine, skill_tool
from services.tools_registry import (
    LLM_TOOL_MAP,
    REGISTRY,
    to_openai_tools,
)

logger = logging.getLogger(__name__)

# Auto-generated from tools_registry — never edit by hand.
_TOOLS = to_openai_tools()
_TOOLS_BASIC = [t for t in _TOOLS if t["function"]["name"] in {"write_file", "final_answer"}]


def _try_flat_args(args: dict[str, Any], name: str) -> dict[str, Any] | None:
    """Layer 2: no 'args' key but other keys exist → treat them as skill args."""
    if args.get("args"):
        return None
    if len(args) <= 1:
        return None
    flat = {k: v for k, v in args.items() if k != "command"}
    if flat:
        logger.debug("[AGENT-TOOLS] Skill '%s': flat args detected, normalizing to dict.", name[6:])
        return flat
    return None


def _strip_wrappers(skill_args: dict[str, Any], name: str) -> dict[str, Any]:
    """Layer 4: unwrap input/data/payload wrapper keys around real args."""
    from services.tools.flat_args import _WRAPPER_KEYS

    for wrapper in _WRAPPER_KEYS:
        val = skill_args.get(wrapper)
        if not isinstance(val, dict):
            continue
        for k, v in val.items():
            if k not in skill_args:
                skill_args[k] = v
        skill_args.pop(wrapper, None)
        logger.debug("[AGENT-TOOLS] Skill '%s': wrapper key '%s' stripped.", name[6:], wrapper)
    return skill_args


def _apply_synonyms(skill_args: dict[str, Any]) -> dict[str, Any]:
    """Layer 5: synonym mapping — ip/domain → target, filepath → path."""
    from services.tools.flat_args import _SYNONYMS

    mapped: dict[str, Any] = {}
    for key, val in skill_args.items():
        canonical: str = _SYNONYMS.get(str(key).lower(), str(key))
        if canonical not in mapped:
            mapped[canonical] = val
    return mapped


def _normalize_skill_args(name: str, command: str, args: dict[str, Any]) -> Any:
    """Resilience: 4B models often flatten args instead of nesting.

    Extraction layers (applied in order):
    1. Direct: args["args"] exists → use it.
    2. Flat: args["args"] missing but other keys exist → treat them as skill args.
    3. String-to-dict: args["args"] is a string → parse JSON → CLI flags → key=value.
    4. Wrapper-strip: if a wrapper key (input/data/payload) contains a dict, unwrap it.
    5. Synonym mapping: ip/domain/query → target, filepath → path, etc.

    Also strips a duplicate "command" key from a dict to prevent a duplicate
    --command CLI flag.
    """
    skill_args = args.get("args", "")

    # Layer 2: Flat — no "args" key but other keys exist
    if not skill_args:
        flat = _try_flat_args(args, name)
        if flat is not None:
            skill_args = flat

    # Layer 3: String-to-dict — parse string args into a dict
    if isinstance(skill_args, str) and skill_args.strip():
        parsed = _parse_string_args(skill_args)
        if parsed is not None:
            skill_args = parsed
            logger.debug("[AGENT-TOOLS] Skill '%s': string args parsed to dict.", name[6:])

    # Layer 4: Wrapper-strip — unwrap input/data/payload around real args
    if isinstance(skill_args, dict):
        skill_args = _strip_wrappers(skill_args, name)

    # Layer 5: Synonym mapping — ip/domain → target, filepath → path
    if isinstance(skill_args, dict):
        skill_args = _apply_synonyms(skill_args)

    # Strip duplicate "command" key
    if isinstance(skill_args, dict) and "command" in skill_args:
        skill_args = {k: v for k, v in skill_args.items() if k != "command"}
    return skill_args


def _parse_string_args(s: str) -> dict[str, Any] | None:
    """Parse a string into a dict via 3 fallbacks: JSON → CLI flags → key=value.

    Returns None if no parsing succeeded (caller keeps original string).
    """
    s = s.strip()
    if not s:
        return None
    # Try JSON
    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    # Try CLI flags (--key value)
    try:
        from services._skills_engine._cli_utils import _cli_flags_to_json_dict

        cli_dict = _cli_flags_to_json_dict(s)
        if cli_dict:
            return cli_dict
    except Exception:
        pass
    # Try key=value pairs (space-separated)
    result: dict[str, Any] = {}
    for pair in s.split():
        if "=" in pair:
            k, _, v = pair.partition("=")
            k = k.lstrip("-").strip()
            if k:
                result[k] = v.strip().strip("\"'")
    if result:
        return result
    return None


def _coerce_skill_args_to_format(name: str, skill_args: Any) -> Any:
    """Adapter: rich-schema skills keep dict args; legacy skills get JSON string."""
    if isinstance(skill_args, dict):
        engine = get_skills_engine()
        if not engine._skills:
            engine.load()
        skill_name = name[6:]  # strip "skill_" prefix
        skill_instance = engine._skills.get(skill_name)
        if skill_instance and getattr(skill_instance, "commands_schema", None):
            # NEW FORMAT: Rich schema skill — pass dict as-is
            logger.debug(
                "[AGENT-TOOLS] Skill '%s' has commands_schema. Passing dict args.",
                skill_name,
            )
        else:
            # LEGACY FORMAT: Old skill expects JSON string
            skill_args = json.dumps(skill_args, ensure_ascii=False, separators=(",", ":"))
            logger.debug(
                "[AGENT-TOOLS] Skill '%s' is legacy. Serializing dict to JSON string.",
                skill_name,
            )
    elif not isinstance(skill_args, str):
        skill_args = str(skill_args or "")
    return skill_args


def _is_empty_value(value: Any) -> bool:
    """True if a required argument value is effectively empty."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() in ("", "{}", "null", "[]")
    if isinstance(value, (dict, list)):
        return len(value) == 0
    return False


# Backward-compat alias
_is_empty_input = _is_empty_value


def _validate_skill_input(name: str, command: str, skill_args: Any) -> str | None:
    """Fail-Fast: reject empty values for ANY required field in the skill's commands_schema.

    Generalized from input-only to all required fields (input, path, dir, etc.).
    When the 4B model omits or passes empty values for required parameters, the
    skill runs on empty data and produces hollow output. This gate catches that
    BEFORE execution and returns a semantic error so the model can retry.

    Returns error string if validation fails, None if OK (or skill has no schema).
    """
    engine = get_skills_engine()
    if not engine._skills:
        engine.load()
    skill_name = name[6:]  # strip "skill_" prefix
    skill_instance = engine._skills.get(skill_name)
    if not skill_instance:
        return None  # unknown skill — let skill_tool handle the error
    cmd_schema = getattr(skill_instance, "commands_schema", {})
    if not cmd_schema:
        return None  # legacy skill — no schema to validate against

    # Check shared schema ("*") or per-command schema
    schema = cmd_schema.get("*") or cmd_schema.get(command)
    if not isinstance(schema, dict):
        return None
    required_fields = schema.get("required", [])
    if not required_fields:
        return None  # no required fields — nothing to validate

    # Extract arg values from skill_args (dict, JSON string, or CLI-flag string).
    # The temp file bridge injects `--input <path>` as a CLI-flag string for
    # skills whose arg_template uses unquoted {args} (e.g. report-maker).
    # json.loads fails on those, so fall back to CLI-flag parsing.
    arg_values: dict[str, Any] = {}
    _parse_ok = True
    if isinstance(skill_args, dict):
        arg_values = skill_args
    elif isinstance(skill_args, str):
        try:
            parsed = json.loads(skill_args)
            if isinstance(parsed, dict):
                arg_values = parsed
            else:
                _parse_ok = False  # JSON scalar/list — not a field dict
        except json.JSONDecodeError:
            from services._skills_engine._cli_utils import _cli_flags_to_json_dict

            arg_values = _cli_flags_to_json_dict(skill_args)
            if not arg_values:
                _parse_ok = False  # neither JSON nor CLI flags — unknown format

    # Diagnostic: if we got a non-empty string but couldn't extract any fields,
    # log loudly so a future 4th format (XML/YAML/...) is caught immediately
    # instead of silently degrading to "all required fields empty".
    if not _parse_ok:
        logger.error(
            "[AGENT-TOOLS] Skill '%s' command '%s': unparseable args (not JSON dict, "
            "not CLI flags). preview=%.120s — treating all required fields as missing.",
            skill_name,
            command,
            str(skill_args),
        )

    # Check each required field
    missing: list[str] = []
    for field in required_fields:
        if field == "command":
            continue  # command is at the top level, not in args
        value = arg_values.get(field)
        if _is_empty_value(value):
            missing.append(field)

    if missing:
        logger.warning(
            "[AGENT-TOOLS] Skill '%s' command '%s': empty required fields %s rejected (Fail-Fast).",
            skill_name,
            command,
            missing,
        )
        fields_str = ", ".join(f"`{f}`" for f in missing)
        return (
            f"❌ VALIDATION ERROR: Skill '{skill_name}' command '{command}' requires non-empty {fields_str}. "
            f"You passed empty data. You MUST provide the actual value(s) for {fields_str}. "
            f"Do NOT pass '{{}}', empty string, or omit the parameter. Retry with real data."
        )
    return None


async def _execute_skill_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a skill_* tool via the skills_engine subprocess fork."""
    try:
        command = args.get("command", "")
        skill_args = _normalize_skill_args(name, command, args)
        # Fail-Fast validation: reject empty `input` before subprocess fork
        validation_err = _validate_skill_input(name, command, skill_args)
        if validation_err:
            return validation_err
        skill_args = _coerce_skill_args_to_format(name, skill_args)
        result = await skill_tool(name, command, skill_args)
        return str(result)[:TOOL_OUTPUT_MAX_CHARS]
    except Exception as e:
        return f"❌ Skill error: {e}"


async def _execute_builtin_tool(name: str, args: dict[str, Any]) -> str:
    """Execute a built-in tool via the in-process callable map (no HTTP loopback)."""
    fn = LLM_TOOL_MAP.get(name)
    if fn is None:
        return f"Unknown tool: {name}"
    # Flat-contract tools: normalize model-emitted args before validation
    from services.tools.flat_args import is_flat_tool, normalize_flat_args

    if is_flat_tool(name):
        args = normalize_flat_args(name, args)
    tool_spec = REGISTRY.get(name)
    if tool_spec and tool_spec.pydantic_model:
        try:
            validated = tool_spec.pydantic_model(**args)
            args = validated.model_dump()
        except ValidationError as ve:
            return f"❌ Argument Validation Error: {ve}. Fix your JSON arguments to match the schema."
    try:
        if asyncio.iscoroutinefunction(fn):
            result = await fn(**args) if args else await fn()
        else:
            result = await asyncio.to_thread(fn, **args) if args else await asyncio.to_thread(fn)
        if inspect.isawaitable(result):
            result = await result
        return str(result)[:TOOL_OUTPUT_MAX_CHARS]
    except (TypeError, ValueError) as val_err:
        # Provide specific feedback to LLM so it can correct its arguments
        return f"❌ Argument Validation Error: {val_err}. Fix your JSON arguments to match the schema."
    except Exception as e:
        return f"Tool error: {e}"


async def execute_tool(name: str, args: dict[str, Any]) -> str:
    """Dispatch a tool call from the in-process LLM agent.

    Path #1 in the architecture (see local_mcp_server.py header). Built-in
    tools resolve via `LLM_TOOL_MAP[name]` — a direct Python call with NO
    JSON serialization and NO HTTP loopback. `skill_*` tools fork a
    subprocess via skills_engine. This is the canonical fast path for the
    LLM; Telegram slash commands take the HTTP path #2 instead.
    """
    if name.startswith("skill_"):
        return await _execute_skill_tool(name, args)
    return await _execute_builtin_tool(name, args)
