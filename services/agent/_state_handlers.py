"""State handler registry — wires all nodes. Imported AFTER all nodes to avoid cycles."""

from collections.abc import Awaitable, Callable
from typing import Optional

from ._context import AgentState, _AgentContext
from ._nodes._critic import _node_critic
from ._nodes._executor import _node_execute
from ._nodes._finalizer import _node_error, _node_finalize
from ._nodes._initializer import _node_initialize
from ._nodes._planner import _node_planner

_STATE_HANDLERS: dict[
    AgentState,
    Callable[[_AgentContext], Awaitable[tuple[AgentState, str | None]]],
] = {
    AgentState.INITIALIZE: _node_initialize,
    AgentState.PLANNER: _node_planner,
    AgentState.EXECUTE: _node_execute,
    AgentState.CRITIC: _node_critic,
    AgentState.FINALIZE: _node_finalize,
    AgentState.ERROR: _node_error,
}
