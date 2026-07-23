"""Quick validation tests — pytest version (offline, no LLM calls)."""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.agent import _AGENT_SYSTEM, _is_conversational  # noqa: E402
from services.agent_tools import _TOOLS, _TOOLS_BASIC  # noqa: E402
from services.skills_engine import get_skills_engine  # noqa: E402


# ─── Prompt integrity ──────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "keyword",
    [
        "Sentinel",
        "Hebrew",
        "REACT",
        "final_answer",
        "{tools_schema}",
        "IRON RULES",
        "thinking",
        "tool_output",
        "ENVIRONMENT",
        "CRITICAL",
    ],
)
def test_prompt_contains_keyword(keyword):
    assert keyword.lower() in _AGENT_SYSTEM.lower(), f"Missing keyword in prompt: {keyword!r}"


def test_prompt_has_os_directive():
    """OS environment directive must be present to prevent Linux path hallucination."""
    import platform

    os_name = platform.system()
    assert os_name in _AGENT_SYSTEM, f"OS name '{os_name}' not in system prompt"
    if os_name == "Windows":
        assert "Windows" in _AGENT_SYSTEM
        assert "NEVER use Linux paths" in _AGENT_SYSTEM


def test_prompt_reasonable_length():
    assert 500 < len(_AGENT_SYSTEM) < 20000, f"Unexpected prompt length: {len(_AGENT_SYSTEM)}"


# ─── Conversational detection ──────────────────────────────────────────────
@pytest.mark.parametrize(
    "query,expected_conv",
    [
        ("היי", True),
        ("שלום", True),
        ("מה שלומך", True),
        ("מי אתה", True),
        ("תודה רבה", True),
        ("מה המזג אוויר", False),
        ("תרגם לי", False),
        ("כמה שווה דולר", False),
    ],
)
def test_conversational_detection(query, expected_conv):
    is_conv = asyncio.run(_is_conversational(query))
    assert is_conv == expected_conv, f"{query!r} expected conv={expected_conv}, got {is_conv}"


# ─── Skills registry ───────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "skill",
    [
        "weather-skill",
        "currency-skill",
        "translator-skill",
        "news-monitor",
        "stocks-skill",
        "geocode-skill",
        "crypto-skill",
        "intel-skill",
    ],
)
def test_skill_loaded(skill):
    skills = get_skills_engine().list_skill_names()
    assert skill in skills, f"Skill not loaded: {skill}"


# ─── Tools registry ────────────────────────────────────────────────────────
@pytest.mark.parametrize("tool", ["get_system_snapshot", "web_search"])
def test_tool_available(tool):
    tool_names = [t.get("function", {}).get("name", "") for t in _TOOLS + _TOOLS_BASIC]
    assert tool in tool_names, f"Tool not registered: {tool}"
