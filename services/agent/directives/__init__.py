# services/agent/directives/__init__.py
"""Routing-Directive package — auto-registers all directives on import.

Open-Closed: to add a new skill directive, drop a new module here and
call `directive_registry.register(...)` at module level. Core agent code
NEVER changes.

Import order matters only for tie-breaking when priorities are equal;
explicit `priority=` on each registration is preferred.
"""

# Side-effect imports: each module self-registers via directive_registry.register
from services.agent.directives import (
    news,  # noqa: F401, E402
    staleness,  # noqa: F401, E402
)
from services.agent.directives.registry import (  # noqa: F401
    DirectiveMatcher,
    DirectiveRegistry,
    directive_registry,
)

__all__ = [
    "DirectiveMatcher",
    "DirectiveRegistry",
    "directive_registry",
]
