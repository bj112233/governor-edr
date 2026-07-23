"""Temp File Bridge — Zero-Trust injection of state data for data-consuming skills.

Design principle: The model PROPOSES, the Bridge DECIDES.
For skills in _DATA_CONSUMING_SKILLS, the `input` field is ALWAYS overridden
with the real state path — regardless of what the LLM emitted. No disk
checks, no validation of model output. The truth lives in ctx._tool_outputs_buffer.
"""

import json
import logging
import os
import re
import tempfile

from .._context import _AgentContext

logger = logging.getLogger(__name__)

_DATA_CONSUMING_SKILLS = {"skill_report-maker"}


def _strip_template(fn_args: dict) -> dict:
    """Strip --template from args (arg_template already sets it)."""
    skill_args = fn_args.get("args", "")
    if isinstance(skill_args, dict):
        if "template" in skill_args:
            skill_args = {k: v for k, v in skill_args.items() if k != "template"}
            return {**fn_args, "args": skill_args}
    elif isinstance(skill_args, str):
        skill_args = re.sub(r"--template\s+\S+", "", skill_args).strip()
        return {**fn_args, "args": skill_args}
    return fn_args


def _write_temp_payload(ctx: _AgentContext, fn_name: str) -> str | None:
    """Write tool outputs buffer to temp JSON file. Returns path or None."""
    if not ctx._tool_outputs_buffer:
        logger.warning("[BRIDGE] %s needs --input but tool_outputs_buffer is empty.", fn_name)
        return None

    _payload = {
        "generated_at": ctx._task_results.get("_timestamp", ""),
        "tools": ctx._tool_outputs_buffer,
    }
    fd, _path = tempfile.mkstemp(prefix="sentinel_report_", suffix=".json", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(_payload, f, ensure_ascii=False, indent=2)
        ctx._temp_files.append(_path)
        logger.info("[BRIDGE] Wrote %d tool outputs to %s for %s", len(ctx._tool_outputs_buffer), _path, fn_name)
    except OSError:
        os.close(fd)
        raise

    return _path


def _inject_input_path(fn_args: dict, path: str) -> dict:
    """Deterministic override: inject real input path, ignore model's value."""
    if isinstance(fn_args.get("args"), dict):
        return {**fn_args, "args": {**fn_args["args"], "input": path}}
    if isinstance(fn_args.get("args"), str):
        skill_args = re.sub(r"--input\s+\S+", "", fn_args["args"]).strip()
        return {**fn_args, "args": f"{skill_args} --input {path}".strip()}
    return {**fn_args, "args": {"input": path}}


def maybe_inject_temp_file(ctx: _AgentContext, fn_name: str, fn_args: dict) -> dict:
    """For data-consuming skills: ALWAYS override `input` with the real state path.

    Zero-Trust: the model's `input` value is ignored entirely. The Bridge
    writes accumulated tool outputs to a temp JSON file and injects that path.
    Also strips conflicting --template when arg_template already sets it.

    Returns potentially mutated fn_args."""
    if fn_name not in _DATA_CONSUMING_SKILLS:
        return fn_args

    fn_args = _strip_template(fn_args)

    path = _write_temp_payload(ctx, fn_name)
    if path is None:
        return fn_args

    return _inject_input_path(fn_args, path)
