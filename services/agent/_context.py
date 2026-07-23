"""Agent state definitions — leaf module, zero internal imports."""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

_DANGEROUS_TOOLS = frozenset(
    {
        "block_ip",
        "kill_process",
        "restart_service",
        "manage_service",
        "defender_scan",
        "local_screenshot",
        "skill_firewall-skill",
    }
)

_CRITIC_MAX_RETRIES = 2

_FINAL_ANSWER_TOOL_SPEC = {
    "type": "function",
    "function": {
        "name": "final_answer",
        "description": "Deliver complete answer to the user.",
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Complete Hebrew response with all findings and data; keep cyber terms in English.",
                }
            },
            "required": ["text"],
        },
    },
}


@dataclass
class _AgentContext:
    """Mutable Graph State for ReAct loop (2026 LangGraph pattern).

    Carried from node to node; each tick mutates messages and
    accumulated error / execution history in-place.
    """

    user_question: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    active_tools: list[dict] = field(default_factory=list)
    step_max_tokens: int = 1024
    bypass_response: str | None = None
    is_llm_ready: bool = True
    _executed_history: set[tuple[int, str, str]] = field(default_factory=set)
    _cross_subtask_cache: dict[tuple[str, str], str] = field(default_factory=dict)
    _last_error: str | None = None
    _last_parse_error: str | None = None
    critic_rejections: int = 0
    _last_critic_feedback: dict = field(default_factory=dict)
    _critic_claims_history: list[list[str]] = field(default_factory=list)
    subtasks: list[dict] = field(default_factory=list)
    current_subtask_idx: int = -1
    _subtask_injected_for: str = ""
    _loop_nudge_idx: int = -1
    _task_results: dict[str, str] = field(default_factory=dict)
    _consecutive_tool_failures: int = 0
    _completeness_retries: int = 0
    # ── Interceptor: premature final_answer tracking per subtask ──
    _premature_fa_count: int = 0
    # ── Empty final_answer nudge: model called final_answer with no text ──
    _empty_fa_nudge_count: int = 0
    # ── Recovery nudge: injected at step max-1 to force final_answer ──
    _recovery_nudge_injected: bool = False
    # ── Emergency Step Reserve: +2 steps when critic rejects final draft ──
    # at the step boundary. Fires once per session, only on the final
    # subtask, only on a critic-retry (EXECUTE after CRITIC rejection).
    _emergency_reserve_used: bool = False
    is_emergency_mode: bool = False
    # ── Self-Healing Circuit Breaker fields ──
    _blocked_tools: set[str] = field(default_factory=set)
    _failed_tasks: set[str] = field(default_factory=set)
    _blocked_by_failure: set[str] = field(default_factory=set)
    _degraded_mode: bool = False
    _schema_nudge_injected: bool = False
    # ── Reflection: tool usage history for Critic review ──
    _tools_used: list[dict] = field(default_factory=list)
    # ── Per-subtask tool count (resets on every subtask advance) ──
    # Fixes cumulative _tools_used bug where subtask N+1 inherited N's tool count.
    _subtask_tool_count: int = 0
    # ── Temp File Bridge: tool outputs for data-consuming skills ──
    _tool_outputs_buffer: list[dict[str, str]] = field(default_factory=list)
    # ── Bypass control: when False, skip all bypass handlers (for threat hunt) ──
    allow_bypasses: bool = True
    _temp_files: list[str] = field(default_factory=list)
    # ── Raw tool result persistence (survives message sanitization) ──
    _last_raw_tool_result: str = ""
    # ── FSM runtime fields ──
    step_count: int = 0
    max_steps: int = 10
    engine: Any = field(default=None)
    state: Any = field(default=None)
    output: str = ""
    error_msg: str = ""
    draft_answer: str = ""
    # ── Critic Rollback: original draft saved before retry for graceful degradation ──
    _draft_v1: str = ""
    # ── Pre-compute hard facts (injected into system prompt) ──
    # Stored separately so the critic entity audit can verify IPs/IOCs that
    # came from deterministic enrichment, not from LLM tool calls.
    _hard_facts: str = ""


class AgentState(Enum):
    """Explicit FSM states for the agent loop."""

    INITIALIZE = "initialize"
    PLANNER = "planner"
    EXECUTE = "execute"
    CRITIC = "critic"
    FINALIZE = "finalize"
    ERROR = "error"
