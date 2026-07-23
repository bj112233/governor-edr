# services/agent/directives/registry.py
"""Routing-Directive Registry — Open-Closed Principle.

Each skill (or cross-cutting concern like staleness) registers a matcher
function. Core agent code never grows when a new directive is added —
just drop a new module under `services/agent/directives/` and call
`directive_registry.register(...)` at import time.

Matcher contract:
    matcher(user_question: str, context: Dict[str, Any]) -> Optional[str]
    Returns the directive INSTRUCTION text (without the user question) to
    inject as a `system` message, or None to skip. The user question is
    appended as a separate `user` message by _inject_directive.

`context` keys (provided by core.run_agent):
    - active_tool_names: Set[str]   — names of tools currently in scope
    - history_msgs:      int        — count of injected history messages
    - has_live_tool:     bool       — True if any volatile-data tool is active
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

DirectiveMatcher = Callable[[str, dict[str, Any]], str | None]


@dataclass
class _Entry:
    name: str
    matcher: DirectiveMatcher
    priority: int = 100  # lower = checked first


@dataclass
class DirectiveRegistry:
    """First-match-wins registry. Lower priority value = higher precedence."""

    _entries: list[_Entry] = field(default_factory=list)

    def register(
        self,
        name: str,
        matcher: DirectiveMatcher,
        priority: int = 100,
    ) -> None:
        if any(e.name == name for e in self._entries):
            logger.warning("[Directives] Overriding existing directive: %s", name)
            self._entries = [e for e in self._entries if e.name != name]
        self._entries.append(_Entry(name=name, matcher=matcher, priority=priority))
        self._entries.sort(key=lambda e: e.priority)
        logger.info(
            "[Directives] Registered '%s' (priority=%d, total=%d)",
            name,
            priority,
            len(self._entries),
        )

    def match(self, user_question: str, context: dict[str, Any]) -> tuple[str, str] | None:
        """Return (directive_name, rendered_text) of first matching directive,
        or None if no directive applies."""
        for entry in self._entries:
            try:
                rendered = entry.matcher(user_question, context)
            except Exception as exc:
                logger.error("[Directives] Matcher '%s' raised: %s", entry.name, exc)
                continue
            if rendered:
                return (entry.name, rendered)
        return None

    def names(self) -> list[str]:
        return [e.name for e in self._entries]


# Module-level singleton
directive_registry = DirectiveRegistry()
