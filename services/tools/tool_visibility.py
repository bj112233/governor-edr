# services/tools/tool_visibility.py
"""Context Collapse — hide tools irrelevant to the current intent mode.

The 16K token budget is the hard constraint. Every tool in `active_tools`
costs ~100-300 tokens (schema + description). OSINT tools shown to the LLM
during a system-monitoring query waste VRAM and cognitive attention.

This module filters `active_tools` based on the pre-computed intent:
  - intent == "osint"     → keep only osint_hunt (engine-in-engine) + final_answer
  - intent != "osint"     → hide all OSINT-only tools
  - intent == "security"  → hide system-monitoring tools (not relevant)
  - intent == "system"    → hide security action tools

Tools that serve multiple modes (e.g. get_system_snapshot) stay visible.
`final_answer` is ALWAYS kept — it's the termination tool.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

__all__ = ["TOOL_MODES", "PERMANENTLY_HIDDEN_TOOLS", "filter_tools_by_intent"]

# ── Permanently hidden tools ────────────────────────────────────────────────
# Tools that are NEVER sent to the LLM, regardless of intent.
# These tools have been absorbed into Pre-Compute Deterministic Enrichment —
# their logic runs at the Python engine level, so the LLM must never see them.
# If visible, a 4B model may "remember" them and hallucinate duplicate calls
# or fabricate inputs (the tool-chaining hallucination bug).
PERMANENTLY_HIDDEN_TOOLS: frozenset[str] = frozenset(
    [
        "analyze_cmdline",  # absorbed into scan_suspicious_procs (engine-level)
    ]
)

# ── Tool mode classification ────────────────────────────────────────────────
# Tools exclusive to a specific mode. Tools not listed here are "general"
# (visible in all modes). final_answer is always kept regardless.

TOOL_MODES: dict[str, frozenset[str]] = {
    "osint": frozenset(
        [
            "scan_credential_leaks",
            "scan_infrastructure",
            "query_ioc_history",
            "osint_hunt",
        ]
    ),
    "security": frozenset(
        [
            "defender_scan",
            "block_ip",
            "unblock_ip",
            "manage_service",
            "local_screenshot",
            "run_powershell",
            "scan_file_yara",
            "terminate_process",
        ]
    ),
    "system": frozenset(
        [
            "get_system_snapshot",
            "get_amd_gpu_info",
            "get_process_list",
            "get_running_processes",
            "get_external_connections",
            "get_listening_ports",
            "get_event_log",
            "get_services",
            "get_local_users",
            "get_disk_details",
            "get_startup_items",
            "get_firewall_drops",
            "get_network_adapters",
            "scan_lan",
            "get_known_devices",
            "get_active_sessions",
            "get_scheduled_tasks_detail",
            "analyze_cmdline",
            "scan_suspicious_procs",
        ]
    ),
}

# Intent → primary mode mapping (from detect_intent output)
_INTENT_TO_MODE: dict[str, str] = {
    "ioc": "osint",
    "cve": "osint",
    "hash": "osint",
    "yara": "security",
    "file": "general",  # file-analyst is a skill, not a builtin tool
    "process_list": "system",
    "process_kill": "security",
}


def _get_mode_for_intent(intent: str | None) -> str:
    """Map a detect_intent() intent string to a tool mode."""
    if intent is None:
        return "general"
    return _INTENT_TO_MODE.get(intent, "general")


def filter_tools_by_intent(
    active_tools: list[dict[str, Any]],
    intent: str | None,
) -> list[dict[str, Any]]:
    """Filter active_tools based on the pre-computed intent.

    Rules:
    1. final_answer is ALWAYS kept.
    2. If intent maps to "osint": hide system + security tools, keep osint + general.
       Exception: keep only osint_hunt from osint tools (engine-in-engine pattern —
       the LLM calls it as one tool, the internal loop uses the rest).
    3. If intent maps to "security": hide osint + system tools.
    4. If intent maps to "system": hide osint + security tools.
    5. If intent is "general" or None: hide osint tools (they're niche and costly).

    Returns filtered list preserving original order.
    """
    mode = _get_mode_for_intent(intent)
    if mode == "general":
        # General queries: hide OSINT tools (costly, niche)
        hidden = TOOL_MODES["osint"]
    elif mode == "osint":
        # OSINT intent: hide system + security; keep only osint_hunt from osint set
        hidden = TOOL_MODES["system"] | TOOL_MODES["security"]
        hidden |= TOOL_MODES["osint"] - {"osint_hunt"}
    elif mode == "security":
        hidden = TOOL_MODES["osint"] | TOOL_MODES["system"]
    elif mode == "system":
        hidden = TOOL_MODES["osint"] | TOOL_MODES["security"]
    else:
        hidden = frozenset()

    filtered: list[dict[str, Any]] = []
    removed: list[str] = []
    for tool in active_tools:
        name = tool.get("function", {}).get("name", "")
        if name == "final_answer":
            filtered.append(tool)
            continue
        # Permanently hidden: absorbed into engine-level enrichment
        if name in PERMANENTLY_HIDDEN_TOOLS:
            removed.append(name)
            continue
        if name in hidden:
            removed.append(name)
            continue
        filtered.append(tool)

    if removed:
        logger.info(
            "[TOOL-VISIBILITY] intent=%s mode=%s: hidden %d tools: %s",
            intent,
            mode,
            len(removed),
            removed,
        )
    return filtered
