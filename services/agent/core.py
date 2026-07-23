# services/agent/core.py
"""Backward-compatibility shim for agent core.

All public symbols re-exported explicitly from internal submodules.
Prefer direct imports from _agent_loop, _bypasses, _json_utils, _react_parser.
"""

from services.agent._agent_loop import run_agent
from services.agent._bypasses import _BYPASS_HANDLERS
from services.agent._helpers import analyze_data
from services.agent._json_utils import _emergency_trim_for_overflow
from services.agent._react_parser import parse_react_response

__all__ = [
    "analyze_data",
    "run_agent",
    "_emergency_trim_for_overflow",
    "parse_react_response",
    "_BYPASS_HANDLERS",
]
