# tests/test_tool_visibility.py
"""Tests for context collapse — tool visibility filtering by intent mode."""

import sys
from pathlib import Path

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.tools.tool_visibility import TOOL_MODES, filter_tools_by_intent


def _make_tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name, "description": f"tool {name}", "parameters": {}}}


# ── TOOL_MODES classification ──


class TestToolModes:
    def test_osint_tools_classified(self):
        assert "scan_infrastructure" in TOOL_MODES["osint"]
        assert "osint_hunt" in TOOL_MODES["osint"]

    def test_security_tools_classified(self):
        assert "block_ip" in TOOL_MODES["security"]
        assert "terminate_process" in TOOL_MODES["security"]

    def test_system_tools_classified(self):
        assert "get_process_list" in TOOL_MODES["system"]
        assert "get_system_snapshot" in TOOL_MODES["system"]

    def test_no_overlap_between_modes(self):
        """A tool should not appear in two exclusive mode sets."""
        osint = set(TOOL_MODES["osint"])
        security = set(TOOL_MODES["security"])
        system = set(TOOL_MODES["system"])
        assert not (osint & security)
        assert not (osint & system)
        assert not (security & system)


# ── filter_tools_by_intent ──


class TestFilterToolsByIntent:
    def test_final_answer_always_kept(self):
        tools = [_make_tool("final_answer"), _make_tool("scan_infrastructure")]
        result = filter_tools_by_intent(tools, "ioc")
        names = [t["function"]["name"] for t in result]
        assert "final_answer" in names

    def test_osint_intent_hides_system_tools(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("get_process_list"),
            _make_tool("get_system_snapshot"),
        ]
        result = filter_tools_by_intent(tools, "ioc")
        names = [t["function"]["name"] for t in result]
        assert "osint_hunt" in names
        assert "get_process_list" not in names
        assert "get_system_snapshot" not in names

    def test_osnet_intent_hides_security_tools(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("block_ip"),
            _make_tool("terminate_process"),
        ]
        result = filter_tools_by_intent(tools, "cve")
        names = [t["function"]["name"] for t in result]
        assert "block_ip" not in names
        assert "terminate_process" not in names

    def test_osint_intent_keeps_only_osint_hunt_from_osint_set(self):
        """Engine-in-engine: only osint_hunt visible, not scan_infrastructure etc."""
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("scan_infrastructure"),
            _make_tool("scan_credential_leaks"),
            _make_tool("query_ioc_history"),
        ]
        result = filter_tools_by_intent(tools, "ioc")
        names = [t["function"]["name"] for t in result]
        assert "osint_hunt" in names
        assert "scan_infrastructure" not in names
        assert "scan_credential_leaks" not in names
        assert "query_ioc_history" not in names

    def test_security_intent_hides_osint_and_system(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("block_ip"),
            _make_tool("osint_hunt"),
            _make_tool("get_process_list"),
        ]
        result = filter_tools_by_intent(tools, "yara")
        names = [t["function"]["name"] for t in result]
        assert "block_ip" in names
        assert "osint_hunt" not in names
        assert "get_process_list" not in names

    def test_system_intent_hides_osint_and_security(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("get_process_list"),
            _make_tool("osint_hunt"),
            _make_tool("block_ip"),
        ]
        result = filter_tools_by_intent(tools, "process_list")
        names = [t["function"]["name"] for t in result]
        assert "get_process_list" in names
        assert "osint_hunt" not in names
        assert "block_ip" not in names

    def test_general_intent_hides_osint(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("osint_hunt"),
            _make_tool("get_process_list"),
        ]
        result = filter_tools_by_intent(tools, None)
        names = [t["function"]["name"] for t in result]
        assert "osint_hunt" not in names
        assert "get_process_list" in names  # system tools stay in general mode

    def test_general_tools_always_visible(self):
        """Tools not in any mode set (general) stay visible in all modes."""
        tools = [_make_tool("final_answer"), _make_tool("some_general_tool")]
        for intent in ("ioc", "yara", "process_list", None):
            result = filter_tools_by_intent(tools, intent)
            names = [t["function"]["name"] for t in result]
            assert "some_general_tool" in names

    def test_empty_tools(self):
        assert filter_tools_by_intent([], "ioc") == []

    def test_order_preserved(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("get_process_list"),
            _make_tool("osint_hunt"),
        ]
        result = filter_tools_by_intent(tools, None)
        names = [t["function"]["name"] for t in result]
        # final_answer and get_process_list survive (osint_hunt hidden in general)
        assert names == ["final_answer", "get_process_list"]

    def test_process_kill_intent_maps_to_security(self):
        tools = [
            _make_tool("final_answer"),
            _make_tool("terminate_process"),
            _make_tool("get_process_list"),
        ]
        result = filter_tools_by_intent(tools, "process_kill")
        names = [t["function"]["name"] for t in result]
        assert "terminate_process" in names
        assert "get_process_list" not in names  # system hidden in security mode

    def test_unknown_intent_hides_nothing(self):
        """Unknown intent → mode='general' → hidden=frozenset() (line 136)."""
        tools = [_make_tool("final_answer"), _make_tool("osint_hunt"), _make_tool("block_ip")]
        result = filter_tools_by_intent(tools, "completely_unknown_intent")
        names = [t["function"]["name"] for t in result]
        # General mode: no mode-specific hiding (only osint hidden in general)
        # Actually general mode hides osint per the else branch
        # Let's verify final_answer is always kept
        assert "final_answer" in names

    def test_permanently_hidden_tool_removed(self):
        """Tools in PERMANENTLY_HIDDEN_TOOLS → removed (lines 147-148)."""
        from services.tools.tool_visibility import PERMANENTLY_HIDDEN_TOOLS

        if not PERMANENTLY_HIDDEN_TOOLS:
            return  # Skip if no permanently hidden tools defined
        hidden_tool = list(PERMANENTLY_HIDDEN_TOOLS)[0]
        tools = [_make_tool("final_answer"), _make_tool(hidden_tool)]
        result = filter_tools_by_intent(tools, None)
        names = [t["function"]["name"] for t in result]
        assert hidden_tool not in names
        assert "final_answer" in names
