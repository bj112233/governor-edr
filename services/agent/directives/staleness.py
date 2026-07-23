# services/agent/directives/staleness.py
"""Cross-cutting staleness directive — warns the LLM when conversation
history overlaps with live-data tools whose output is volatile.

NOT skill-specific: applies whenever ANY live-data tool is in scope and
the user has prior turns in the sliding window. Registered at lower
priority than skill-specific directives so a more specific match wins.
"""

from __future__ import annotations

from typing import Any, Optional

from services.agent.directives.registry import directive_registry

# Tools whose output changes second-to-second. Source of truth for any
# component that needs the same definition (kept here to avoid cycles).
LIVE_DATA_TOOLS = frozenset(
    {
        "get_system_snapshot",
        "get_process_list",
        "get_running_processes",
        "get_external_connections",
        "get_listening_ports",
        "get_active_sessions",
        "sentinel_get_system_snapshot_full",
    }
)


def _staleness_directive(user_question: str, context: dict[str, Any]) -> str | None:
    history_msgs: int = int(context.get("history_msgs", 0) or 0)
    if history_msgs <= 0:
        return None
    active: set = context.get("active_tool_names", set())
    if not (active & LIVE_DATA_TOOLS):
        return None
    return (
        "<staleness_warning>\n"
        "Content inside <previous_turn> tags above is from PRIOR conversations "
        "and is STALE. Any system metrics (CPU, RAM, disk, processes, "
        "connections, sessions, users, ports) in those tags are OUTDATED "
        "and MUST NOT be reused as your answer.\n"
        "For the current question, you MUST call the appropriate live data "
        "tool to fetch fresh values BEFORE calling final_answer.\n"
        "</staleness_warning>"
    )


directive_registry.register("staleness", _staleness_directive, priority=100)
