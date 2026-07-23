"""Tool Runner — post-execution pipeline (memory, reflection, formatting, reminder).

Extracted from _executor.py as part of Sprint 4 SRP refactor.
Responsibility: After a tool executes successfully, handle:
  1. Episodic memory (fire-and-forget action event)
  2. Reflection (record usage for Critic review)
  3. Persist raw result for downstream subtasks
  4. Format result (strip markdown/emojis, truncate)
  5. Inject into LLM context
  6. Subtask reminder (nudge to call final_answer)
"""

import logging

from config import truncate_for_context

from .._context import _AgentContext
from .._helpers import _fire_and_forget
from .._provenance import get_registry as _get_provenance_registry
from ..utils import _strip_emojis, _strip_markdown, is_external_facing_tool, is_volatile_tool, wrap_untrusted
from .episodic_memory import _store_action_event

logger = logging.getLogger(__name__)


async def post_execution_pipeline(
    ctx: _AgentContext,
    fn_name: str,
    fn_args: dict,
    tool_result: str,
    is_error: bool,
) -> None:
    """Run the full post-execution pipeline for a single tool call."""
    # ── Episodic memory: fire-and-forget action event ──
    _fire_and_forget(
        _store_action_event(
            fn_name,
            fn_args,
            tool_result,
            getattr(ctx, "session_id", ""),
            getattr(ctx, "_current_chain_id", ""),
        )
    )

    # ── Reflection: record tool usage for Critic review ──
    ctx._tools_used.append(
        {
            "name": fn_name,
            "command": str(fn_args.get("command", "")),
            "args": str(fn_args)[:200],
            "output_summary": str(tool_result)[:200],
        }
    )
    ctx._subtask_tool_count += 1

    # CRITICAL: Persist raw tool result so downstream subtasks get real data
    # even after _sanitize_subtask_messages strips tool_output tags.
    ctx._last_raw_tool_result = str(tool_result)

    # ── Provenance: register entities (PIDs, IPs) from this tool's output ──
    # Trusted system tools → entities may drive execution actions.
    # Tainted external tools → entities marked tainted-only, blocked from
    # execution until cross-verified against a trusted tool.
    _get_provenance_registry().register(fn_name, str(tool_result))

    # ── Cross-subtask tool cache: store result for reuse in later subtasks ──
    # Key is (fn_name, args_hash) — ignores subtask_idx so same tool+args in
    # a different subtask gets a cache HIT instead of re-executing.
    # Volatile tools (live system sensors) are NEVER cached — they must always
    # return fresh state so the agent sees changes it caused (e.g. kill_process).
    if ctx.subtasks and fn_name != "final_answer" and not is_volatile_tool(fn_name):
        from .loop_controller import build_call_key as _bck

        _ck = _bck(fn_name, fn_args, ctx.current_subtask_idx)
        ctx._cross_subtask_cache[(fn_name, _ck[2])] = str(tool_result)[:2000]

    # ── Temp File Bridge: accumulate tool outputs for data-consuming skills ──
    # Truncate per-result (not per-file) so final JSON stays valid.
    _raw = str(tool_result)
    _safe = _raw[:2000] + "\n...[TRUNCATED]" if len(_raw) > 2000 else _raw
    ctx._tool_outputs_buffer.append(
        {
            "name": fn_name,
            "command": str(fn_args.get("command", "")),
            "result": _safe,
        }
    )

    # Strip rich formatting (markdown + emojis) from tool outputs before
    # injecting into LLM context, to save tokens.
    _clean_result = _strip_emojis(_strip_markdown(str(tool_result)))
    _truncated = truncate_for_context(_clean_result, max_chars=4000)
    # Zero-Trust: external-facing tools get <EXTERNAL_UNTRUSTED_DATA> delimiters
    # + injection sanitization. Internal tools stay in plain <tool_output>.
    if is_external_facing_tool(fn_name):
        fenced = f"<tool_output>\n{wrap_untrusted(_truncated)}\n</tool_output>"
    else:
        fenced = f"<tool_output>\n{_truncated}\n</tool_output>"
    ctx.messages.append({"role": "user", "content": fenced})

    # ── ReAct format tail-anchor: keeps format fresh in KV cache ──
    # After long tool chains the 4B model drifts to free-form text.
    # This micro-reminder sits immediately before the model's next turn.
    if not is_error:
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    "[SYSTEM REMINDER] Respond strictly using ReAct format: "
                    "Thought: ... | Action: <tool_name> | Action Input: {<json>}. "
                    "If you have enough data, use Action: final_answer."
                ),
            }
        )

    # Subtask mode: strong reminder to call final_answer immediately after tool output
    if ctx.subtasks and ctx.current_subtask_idx >= 0 and not is_error:
        _is_last_r = ctx.current_subtask_idx == len(ctx.subtasks) - 1
        reminder_msg = (
            (
                "Call final_answer NOW with the result. "
                "Do NOT call another tool. final_answer marks this subtask as DONE."
            )
            if _is_last_r
            else ("Do NOT call final_answer. The system will advance to the next subtask automatically.")
        )
        ctx.messages.append(
            {
                "role": "user",
                "content": (
                    f"[REMINDER — Subtask {ctx.current_subtask_idx + 1}/{len(ctx.subtasks)}] "
                    "You have received tool output. "
                    f"{reminder_msg}"
                ),
            }
        )
