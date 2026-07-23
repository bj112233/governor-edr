"""Late Binding — resolve {{TASK_<id>_OUTPUT}} placeholders in tool args.

Extracted from _executor.py as part of Sprint 4 SRP refactor.
"""

import logging
import re

logger = logging.getLogger(__name__)

_TASK_PLACEHOLDER_RE = re.compile(r"\{\{\s*TASK_([A-Za-z0-9_]+)_OUTPUT\s*\}\}")


def resolve_task_placeholders(fn_args: dict, task_results: dict[str, str]) -> dict:
    """Replace {{TASK_<id>_OUTPUT}} placeholders with real dependency outputs.

    Walks nested dicts/lists and substitutes placeholders with resolved values.
    """

    def _sub(text: str) -> str:
        def _repl(m: "re.Match") -> str:
            key = m.group(1)
            if key in task_results:
                return str(task_results[key])
            logger.warning("[EXECUTOR] Unresolved task placeholder: %s", m.group(0))
            return m.group(0)

        return _TASK_PLACEHOLDER_RE.sub(_repl, text)

    def _walk(item):
        if isinstance(item, str):
            return _sub(item)
        if isinstance(item, dict):
            return {k: _walk(v) for k, v in item.items()}
        if isinstance(item, list):
            return [_walk(x) for x in item]
        return item

    return _walk(fn_args)
