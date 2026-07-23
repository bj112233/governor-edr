"""Executor phase helpers — extracted from _executor.py (SRP).

_executor.py: orchestration
_executor_phases.py: LLM call, partition, resource guard, execution
no_tool_handler.py: no-tool-call handling (echo, thought leak, fallback)
"""

import asyncio
import json
import logging
from typing import Any

from ...agent_tools import execute_tool as _execute_tool
from ...llm_bridge import ContextOverflowError
from ...telemetry import get_telemetry
from ...tools_registry import REGISTRY
from .._context import _DANGEROUS_TOOLS, AgentState, _AgentContext
from .._helpers import _fire_and_forget
from .._json_utils import _emergency_trim_for_overflow
from ..resource_guard import ResourceGuard, is_heavy_tool
from ..utils import is_volatile_tool
from ._partition_helpers import (
    _check_authorization,
    _handle_blocked_tool,
    _handle_error_lesson,
    _is_safe_tool,
    _resolve_tool_name,
)
from ._temp_file_bridge import maybe_inject_temp_file
from .circuit_breaker import handle_tool_result
from .late_binding import resolve_task_placeholders as _resolve_task_placeholders
from .loop_controller import build_call_key, handle_loop
from .no_tool_handler import handle_no_tool_calls
from .task_completion import handle_final_answer
from .tool_runner import post_execution_pipeline

logger = logging.getLogger(__name__)


async def llm_call(ctx: _AgentContext, max_tokens: int) -> tuple[str | None, AgentState | None, str | None]:
    """Call LLM with overflow retry + empty-response nudge. Returns (content, error_state, error_msg)."""
    try:
        msg = await ctx.engine.agent_step(ctx.messages, max_tokens=max_tokens)
    except ContextOverflowError as exc:
        logger.warning("[AGENT] Context overflow step %d: %s", ctx.step_count, exc)
        ctx.messages = _emergency_trim_for_overflow(ctx.messages)
        try:
            msg = await ctx.engine.agent_step(ctx.messages, max_tokens=ctx.step_max_tokens)
        except ContextOverflowError:
            return None, AgentState.ERROR, "⚠️ ההקשר חרג מהמותר גם לאחר חיתוך אגרסיבי. נסה שאלה קצרה יותר."

    content = msg.content or ""

    # Empty-response detection: LLM returned whitespace-only output (common
    # when context is near-limit or model stalls). Nudge once and retry.
    if not content.strip() and ctx.step_count > 0:
        logger.warning(
            "[AGENT] Empty LLM response (step %d, %d chars). Nudging for real output.",
            ctx.step_count,
            len(content),
        )
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    "CRITICAL: Your previous response was empty. "
                    "You MUST produce a valid Thought/Action/Action Input block OR "
                    "call final_answer with a synthesized answer from the available tool data. "
                    "Do NOT return an empty response."
                ),
            }
        )
        try:
            msg = await ctx.engine.agent_step(ctx.messages, max_tokens=max_tokens)
            content = msg.content or ""
        except ContextOverflowError:
            ctx.messages = _emergency_trim_for_overflow(ctx.messages)
            try:
                msg = await ctx.engine.agent_step(ctx.messages, max_tokens=ctx.step_max_tokens)
                content = msg.content or ""
            except ContextOverflowError:
                return None, AgentState.ERROR, "⚠️ ההקשר חרג מהמותר גם לאחר חיתוך אגרסיבי. נסה שאלה קצרה יותר."

    return content, None, None


async def _process_single_tool_call(
    ctx: _AgentContext,
    tool_call: dict,
    thought: str,
    allowed: set[str],
) -> tuple[str, dict, Any] | None:
    """Process one tool call: resolve, authorize, error-lesson, loop-detect.

    Returns (fn_name, fn_args, call_key) if the call should be partitioned,
    or None if it was handled inline (blocked, unauthorized, auto-advanced).
    For loop-detection early exit, returns (fn_name, fn_args, (next_state, output)).
    """
    fn_name = tool_call["name"]
    fn_args = tool_call["arguments"]

    # Late Binding deref
    if isinstance(fn_args, dict) and ctx._task_results:
        fn_args = _resolve_task_placeholders(fn_args, ctx._task_results)

    # Circuit breaker — blocked tool
    if fn_name in ctx._blocked_tools:
        _handle_blocked_tool(ctx, fn_name)
        return None

    # Tool name resolution + authorization
    fn_name = _resolve_tool_name(fn_name, tool_call, allowed)
    if not await _check_authorization(ctx, fn_name, allowed):
        return None

    # Error-lesson handling
    _handle_error_lesson(ctx, fn_name, fn_args, thought)

    # final_answer is always critical (terminal)
    if fn_name == "final_answer":
        return (fn_name, fn_args, ("", ""))

    # Loop detection (must be sequential for deterministic state)
    call_key = build_call_key(fn_name, fn_args, ctx.current_subtask_idx)
    _handled, _next_state, _output = await handle_loop(ctx, fn_name, fn_args)
    if _handled:
        return (fn_name, fn_args, (_next_state, _output))

    # Cross-subtask tool cache: if same tool+args already ran in a prior subtask,
    # reuse the result instead of re-executing. Skips:
    #   - final_answer (terminal)
    #   - volatile tools (live system sensors — must always return fresh state)
    if ctx.subtasks and ctx.current_subtask_idx >= 0 and fn_name != "final_answer" and not is_volatile_tool(fn_name):
        _cross_key = (fn_name, call_key[2])  # (name, args_hash) — ignores subtask_idx
        _cached = ctx._cross_subtask_cache.get(_cross_key)
        if _cached is not None:
            logger.info(
                "[AGENT] Cross-subtask cache HIT: %s already executed in prior subtask — reusing result (%d chars).",
                fn_name,
                len(_cached),
            )
            ctx.messages.append(
                {
                    "role": "user",
                    "content": (
                        f"<tool_output>\n[SYSTEM] Tool '{fn_name}' was already executed in a prior subtask "
                        f"with the same arguments. Reusing cached result (no re-execution needed):\n"
                        f"{_cached[:2000]}\n</tool_output>"
                    ),
                }
            )
            return None  # skip execution — result already injected

    return (fn_name, fn_args, call_key)


def _is_loop_exit(call_key: Any) -> bool:
    """Check if call_key is a loop-detection early-exit signal (tuple of state+output)."""
    return isinstance(call_key, tuple) and len(call_key) == 2 and not isinstance(call_key[0], (int, str))


async def partition_tool_calls(
    ctx: _AgentContext, tool_calls: list, thought: str, allowed: set[str]
) -> tuple[list, list, AgentState | None, str | None]:
    """Phase 0: Validate and partition into safe/critical. Returns (safe, critical, early_state, early_output)."""
    _safe_calls: list = []
    _critical_calls: list = []

    for tool_call in tool_calls:
        result = await _process_single_tool_call(ctx, tool_call, thought, allowed)
        if result is None:
            continue

        fn_name, fn_args, call_key = result

        # Loop detection early exit — call_key holds (next_state, output)
        if _is_loop_exit(call_key):
            next_state, output = call_key
            return _safe_calls, _critical_calls, next_state, output

        # final_answer → critical
        if fn_name == "final_answer":
            _critical_calls.append((fn_name, fn_args, call_key))
            continue

        # Partition by safety level
        if _is_safe_tool(fn_name):
            ctx._executed_history.add(call_key)
            _safe_calls.append((fn_name, fn_args, call_key))
        else:
            _critical_calls.append((fn_name, fn_args, call_key))

    return _safe_calls, _critical_calls, None, None


def apply_resource_guard(safe_calls: list, critical_calls: list) -> tuple[list, list, bool, str]:
    """Phase 0.5: Filter heavy tools under stress. Returns (safe, critical, all_blocked, reason)."""
    _rg = ResourceGuard()
    _permitted, _rg_reason = _rg.check()
    if not _permitted:
        safe_calls = [(fn, fa, ck) for fn, fa, ck in safe_calls if not is_heavy_tool(fn)]
        critical_calls = [(fn, fa, ck) for fn, fa, ck in critical_calls if not is_heavy_tool(fn)]
        if not safe_calls and not critical_calls:
            return safe_calls, critical_calls, True, _rg_reason
        logger.warning(
            "[ResourceGuard] System stressed (%s). Heavy tools filtered; %d safe + %d critical remaining.",
            _rg_reason,
            len(safe_calls),
            len(critical_calls),
        )
    elif _rg_reason != "ok":
        logger.info("[ResourceGuard] Throttle active: %s", _rg_reason)
    return safe_calls, critical_calls, False, _rg_reason


_MAX_CONCURRENT_SAFE_TOOLS = 5
_safe_semaphore: asyncio.Semaphore | None = None


def _get_safe_semaphore() -> asyncio.Semaphore:
    """Lazy-init global semaphore — must be called inside event loop."""
    global _safe_semaphore
    if _safe_semaphore is None:
        _safe_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_SAFE_TOOLS)
    return _safe_semaphore


async def execute_safe_calls(ctx: _AgentContext, safe_calls: list) -> AgentState | None:
    """Phase 1: Execute safe calls in parallel, then post-process sequentially.

    Concurrency is capped at _MAX_CONCURRENT_SAFE_TOOLS (5) via a global
    semaphore to prevent OS starvation when the LLM requests many tools
    in a single ReAct tick. Skills have their own internal semaphore (3)
    — this semaphore covers built-in tools (web_search, file_search, etc.).
    """
    if not safe_calls:
        return None

    async def _run_safe(_fn: str, _fa: dict) -> str:
        async with _get_safe_semaphore():
            _fa = maybe_inject_temp_file(ctx, _fn, _fa)
            async with get_telemetry().measure_tool(_fn):
                try:
                    return await _execute_tool(_fn, _fa)
                except Exception as exc:
                    _exc_type = type(exc).__name__
                    logger.error("[AGENT] Tool '%s' crashed: %s: %s", _fn, _exc_type, str(exc)[:200])
                    return f"🚨 [SYSTEM CRASH] Tool '{_fn}' failed: {_exc_type}"

    _safe_coros = [_run_safe(fn, fa) for fn, fa, _ in safe_calls]
    _safe_results = await asyncio.gather(*_safe_coros)

    for (fn_name, fn_args, call_key), tool_result in zip(safe_calls, _safe_results):
        logger.info("[AGENT] Executed: %s(%s)", fn_name, fn_args)
        tool_result, _is_error, _next_state, _output = await handle_tool_result(
            ctx, fn_name, fn_args, tool_result, _execute_tool
        )
        if _next_state is not None:
            return _next_state, _output  # type: ignore[return-value]
        await post_execution_pipeline(ctx, fn_name, fn_args, tool_result, _is_error)
    return None


async def _hitl_guard(ctx: _AgentContext, fn_name: str, fn_args: Any) -> tuple[AgentState, str] | None:
    """HITL circuit breaker — dangerous tools require operator approval.

    Returns (FINALIZE, hitl_msg) if intercepted, None to continue execution.
    """
    if fn_name not in _DANGEROUS_TOOLS or ctx.state is None:
        return None
    from ...telegram.fsm_states import ExecApproval

    logger.warning("[HITL] Dangerous tool '%s' intercepted. Transferring to FSM.", fn_name)
    await ctx.state.set_state(ExecApproval.waiting_for_auth)
    await ctx.state.update_data(pending_command=fn_name, pending_args=fn_args)
    hitl_msg = (
        "⚠️ **דרוש אישור מפעיל** ⚠️\n\n"
        "הסוכן החליט לבצע פעולה קריטית:\n"
        f"🛠 כלי: `{fn_name}`\n📦 פרמטרים: `{fn_args}`\n\nהאם לאשר ביצוע? (כן/לא)"
    )
    ctx.output = hitl_msg
    return AgentState.FINALIZE, hitl_msg


async def _soft_dep_guard(ctx: _AgentContext, fn_name: str) -> AgentState | None:
    """Safety Guard: block tools requiring data integrity when soft deps failed.

    Returns EXECUTE if blocked (advance to next subtask), None to continue.
    """
    if not ctx.subtasks or not (0 <= ctx.current_subtask_idx < len(ctx.subtasks)):
        return None
    current_st = ctx.subtasks[ctx.current_subtask_idx]
    if current_st.get("dependency_type", "hard") != "soft":
        return None
    deps = current_st.get("depends_on", [])
    if not any(str(d) in ctx._failed_tasks for d in deps):
        return None
    tool_spec = REGISTRY.get(fn_name)
    if not (tool_spec and tool_spec.requires_data_integrity):
        return None
    task_id = str(current_st.get("id", ctx.current_subtask_idx))
    logger.error(
        "[SAFETY BREACH PREVENTED] Task '%s' requested tool '%s' with partial data "
        "(soft dependency). Tool requires complete data integrity. Execution blocked.",
        task_id,
        fn_name,
    )
    current_st["status"] = "failed"
    current_st["error"] = f"Safety Block: {fn_name} requires full upstream data"
    ctx._task_results[task_id] = (
        f"[SAFETY BLOCK] Tool '{fn_name}' blocked: upstream dependency failed and "
        f"tool requires complete data integrity."
    )
    ctx.current_subtask_idx += 1
    from .._dag_emitter import emit_subtask_transition

    await emit_subtask_transition(ctx, task_id, "pending", "failed")
    return AgentState.EXECUTE


async def execute_critical_calls(ctx: _AgentContext, critical_calls: list) -> tuple[AgentState, str | None]:
    """Phase 2: Execute critical calls sequentially (state-mutating / HITL)."""
    for fn_name, fn_args, call_key in critical_calls:
        if fn_name == "final_answer":
            _handled, _next_state, _output = await handle_final_answer(ctx, fn_args)
            if _handled:
                assert _next_state is not None
                return _next_state, _output
            continue

        # HITL circuit breaker
        hitl = await _hitl_guard(ctx, fn_name, fn_args)
        if hitl is not None:
            return hitl

        # Safety Guard: soft deps
        blocked = await _soft_dep_guard(ctx, fn_name)
        if blocked is not None:
            return blocked, None

        ctx._executed_history.add(call_key)
        fn_args = maybe_inject_temp_file(ctx, fn_name, fn_args)
        async with get_telemetry().measure_tool(fn_name):
            try:
                tool_result = await _execute_tool(fn_name, fn_args)
            except Exception as exc:
                _exc_type = type(exc).__name__
                logger.error("[AGENT] Tool '%s' crashed: %s: %s", fn_name, _exc_type, str(exc)[:200])
                tool_result = f"🚨 [SYSTEM CRASH] Tool '{fn_name}' failed: {_exc_type}"
        logger.info("[AGENT] Executed: %s(%s)", fn_name, fn_args)

        tool_result, _is_error, _next_state, _output = await handle_tool_result(
            ctx, fn_name, fn_args, tool_result, _execute_tool
        )
        if _next_state is not None:
            return _next_state, _output

        await post_execution_pipeline(ctx, fn_name, fn_args, tool_result, _is_error)

    return AgentState.EXECUTE, None
