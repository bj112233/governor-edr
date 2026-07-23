# tests/test_compute_allowed_tools.py
"""Direct unit tests for _compute_allowed_tools — tool filtering by mode.

Validates:
1. Normal mode: all active_tools + final_answer
2. Emergency mode: only final_answer
3. Degraded mode: critical safety_level tools blocked
4. Degraded mode keeps final_answer
5. Empty active_tools edge case
"""

from unittest.mock import MagicMock

from services.agent._context import _AgentContext
from services.agent._nodes._executor import _compute_allowed_tools


def _make_ctx(
    active_tools: list[dict],
    emergency: bool = False,
    degraded: bool = False,
) -> _AgentContext:
    """Build a minimal _AgentContext for tool filtering tests."""
    ctx = MagicMock(spec=_AgentContext)
    ctx.active_tools = active_tools
    ctx.is_emergency_mode = emergency
    ctx._degraded_mode = degraded
    return ctx


def _tool(name: str) -> dict:
    """Build a tool spec dict with the given name."""
    return {"type": "function", "function": {"name": name}}


def test_normal_mode_returns_all_tools():
    """Normal mode: all active_tools names + final_answer."""
    ctx = _make_ctx([_tool("get_process_list"), _tool("block_ip")])
    allowed = _compute_allowed_tools(ctx)
    assert "get_process_list" in allowed
    assert "block_ip" in allowed
    assert "final_answer" in allowed


def test_normal_mode_empty_tools():
    """Normal mode with empty active_tools: only final_answer."""
    ctx = _make_ctx([])
    allowed = _compute_allowed_tools(ctx)
    assert "final_answer" in allowed


def test_emergency_mode_only_final_answer():
    """Emergency mode: only final_answer allowed."""
    ctx = _make_ctx([_tool("get_process_list"), _tool("block_ip")], emergency=True)
    allowed = _compute_allowed_tools(ctx)
    assert allowed == {"final_answer"}


def test_degraded_mode_blocks_critical_tools():
    """Degraded mode: tools with safety_level='critical' must be excluded."""
    ctx = _make_ctx([_tool("block_ip"), _tool("kill_process"), _tool("get_process_list")], degraded=True)
    allowed = _compute_allowed_tools(ctx)
    # Critical tools must NOT be in allowed set
    assert "block_ip" not in allowed
    assert "kill_process" not in allowed
    # Safe tools should be present
    assert "get_process_list" in allowed


def test_degraded_mode_keeps_final_answer():
    """Degraded mode must always keep final_answer."""
    ctx = _make_ctx([_tool("block_ip")], degraded=True)
    allowed = _compute_allowed_tools(ctx)
    assert "final_answer" in allowed


def test_degraded_mode_allows_safe_tools():
    """Degraded mode should allow non-critical tools."""
    ctx = _make_ctx([_tool("get_system_snapshot"), _tool("get_process_list")], degraded=True)
    allowed = _compute_allowed_tools(ctx)
    assert "get_system_snapshot" in allowed
    assert "get_process_list" in allowed


def test_degraded_mode_filters_from_registry():
    """Degraded mode uses REGISTRY safety_level, not active_tools."""
    # Even if a critical tool is in active_tools, it should be filtered
    ctx = _make_ctx([_tool("defender_scan"), _tool("run_powershell")], degraded=True)
    allowed = _compute_allowed_tools(ctx)
    assert "defender_scan" not in allowed
    assert "run_powershell" not in allowed


def test_emergency_overrides_degraded():
    """Emergency mode takes precedence over degraded mode."""
    ctx = _make_ctx([_tool("block_ip"), _tool("get_process_list")], emergency=True, degraded=True)
    allowed = _compute_allowed_tools(ctx)
    assert allowed == {"final_answer"}


def test_normal_mode_includes_final_answer_always():
    """final_answer must always be in the allowed set, even with no tools."""
    ctx = _make_ctx([])
    allowed = _compute_allowed_tools(ctx)
    assert "final_answer" in allowed
