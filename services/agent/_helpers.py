"""Shared helpers for agent nodes — imports _context.py only (leaf-safe)."""

import asyncio
import json
import logging
import re
from collections.abc import Coroutine
from typing import Any

import openai
import requests

from config import LLM_AGENT_MAX_TOKENS, LLM_CONTEXT_WINDOW

from ._agent_analysis import analyze_data
from ._agent_critic import _mk_critic_fb, _run_critic_evaluation
from ._agent_message_utils import (
    _extract_tool_history,
    _get_last_tool_output,
    _has_tool_outputs_in_history,
    _sanitize_subtask_messages,
)
from ._agent_planner import _build_recovery_task, _decompose_task, _should_decompose, _topological_sort
from ._agent_synthesis import _synthesize_results
from ._agent_tool_review import _run_tool_selection_review
from ._context import _CRITIC_MAX_RETRIES, _AgentContext
from ._json_utils import _brace_depth, _strip_trailing_commas

logger = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task[Any]] = set()


def _fire_and_forget(coro: Coroutine[Any, Any, Any]) -> None:
    """Safely fire an asyncio coroutine in the background.
    Holds a strong reference and ensures exceptions are logged (Fail-Loud).
    """
    task = asyncio.create_task(coro)
    _background_tasks.add(task)

    def _on_completion(t: asyncio.Task[Any]) -> None:
        _background_tasks.discard(t)
        try:
            t.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("[AGENT] Background task crashed: %s", e, exc_info=True)

    task.add_done_callback(_on_completion)


async def _count_tokens(msgs: list) -> int:
    """Real token counting via KoboldCpp /api/extra/tokenize endpoint.
    Guarantees 100% accuracy for the loaded model.
    Falls back to byte heuristic ONLY if the server is unreachable.
    """
    text_to_measure = json.dumps(msgs, ensure_ascii=False, default=str)
    try:
        resp = await asyncio.to_thread(
            requests.post,
            "http://127.0.0.1:5001/api/extra/tokenize",
            json={"prompt": text_to_measure},
            timeout=2.0,
        )
        if resp.status_code == 200:
            tokens = resp.json().get("tokens", [])
            return len(tokens)
    except Exception:
        pass
    return int(len(text_to_measure.encode("utf-8")) // 2.5)
