# services/_skills_engine/executor.py
"""The Dumb Executor — runs pre-validated cmd_list with aggressive timeout.

Refactored (Phase 2): thin retry-orchestrator. Delegates:
  - Process lifecycle → _process_runner.spawn_and_wait
  - Exit-code routing  → _output_router.route_success / route_failure
  - JSON truncation    → _truncator.json_safe_truncate
"""

import asyncio
import logging
from pathlib import Path

from config import TOOL_OUTPUT_MAX_CHARS

from ._output_router import route_failure, route_success, timeout_message
from ._process_runner import TIMEOUT, spawn_and_wait
from ._truncator import json_safe_truncate

logger = logging.getLogger(__name__)

_MAX_RETRIES = 2
_DEFAULT_TIMEOUT = 30  # seconds

# Result classification
_RETRY = "retry"
_FINAL = "final"


def _classify_and_route(
    stdout_b: bytes,
    stderr_b: bytes,
    rc: object,
    attempt: int,
    timeout: int,
) -> tuple[str, str | None]:
    """Classify result and route to message. Returns (action, message).

    action = _RETRY → caller should continue loop
    action = _FINAL → caller should return message
    """
    # ── Timeout ──
    if rc is TIMEOUT:
        if attempt < _MAX_RETRIES:
            logger.warning("[Skills] Timeout (attempt %d/%d, %ds), retrying...", attempt + 1, _MAX_RETRIES + 1, timeout)
            return _RETRY, None
        return _FINAL, timeout_message(timeout)

    # ── Success ──
    if rc == 0:
        out = route_success(stdout_b)
        if len(out) > TOOL_OUTPUT_MAX_CHARS:
            out = json_safe_truncate(out, TOOL_OUTPUT_MAX_CHARS)
        return _FINAL, out

    # ── Failure: exit 1-2 = argument errors (no retry) ──
    if isinstance(rc, int) and rc in (1, 2):
        return _FINAL, route_failure(stdout_b, stderr_b, rc)

    # ── Retryable failure ──
    if attempt < _MAX_RETRIES:
        logger.warning("[Skills] Retryable error (attempt %d/%d): rc=%s", attempt + 1, _MAX_RETRIES + 1, rc)
        return _RETRY, None

    return _FINAL, route_failure(stdout_b, stderr_b, rc if isinstance(rc, int) else -1)


async def run(cmd_list: list[str], cwd: Path, timeout: int = _DEFAULT_TIMEOUT) -> str:
    """Run a fully-resolved command list with bounded timeout + retry.

    SECURITY: shell=False is mandatory. cmd_list MUST be List[str].
    Any other type raises AssertionError (Fail-Loud).
    """
    if isinstance(cmd_list, str):
        raise AssertionError("SECURITY: cmd_list must be List[str], not string")

    for attempt in range(_MAX_RETRIES + 1):
        stdout_b, stderr_b, rc = await spawn_and_wait(cmd_list, str(cwd), timeout)
        action, msg = _classify_and_route(stdout_b, stderr_b, rc, attempt, timeout)
        if action == _RETRY:
            await asyncio.sleep(1)
            continue
        return msg

    return "❌ Command failed after all retries"
