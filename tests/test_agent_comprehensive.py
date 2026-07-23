"""Comprehensive Agent Validation Tests — pytest version.

Adapted to the current Sentinel/IronGrid prompt (post-refactor). Live LLM
tests are gated behind RUN_LIVE_LLM_TESTS=1 to keep CI offline by default.
"""

import asyncio
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.agent import _AGENT_SYSTEM, _is_conversational, run_agent  # noqa: E402
from services.agent_tools import _TOOLS, _TOOLS_BASIC  # noqa: E402
from services.llm_bridge import is_llm_ready  # noqa: E402
from services.skills_engine import get_skills_engine  # noqa: E402


@pytest.fixture(autouse=True, scope="session")
def _preload_skills():
    """Ensure skills are loaded before any test accesses _skills directly."""
    get_skills_engine().load()


# ─── Prompt structural integrity (Token-Diet v2 compressed prompt) ─────────
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
    ],
)
def test_prompt_contains_critical_keyword(keyword):
    assert keyword.lower() in _AGENT_SYSTEM.lower(), f"Missing critical keyword: {keyword!r}"


def test_prompt_length_within_bounds():
    length = len(_AGENT_SYSTEM)
    assert 500 < length < 20000, f"Unexpected prompt length: {length}"


# ─── Conversational classifier — chit-chat path ────────────────────────────
@pytest.mark.parametrize(
    "query",
    ["היי", "שלום", "מה שלומך", "מי אתה", "תודה", "ביי", "בוקר טוב"],
)
def test_classifier_recognizes_chitchat(query):
    assert asyncio.run(_is_conversational(query)) is True, f"{query!r} should be classified as conversational"


# ─── Conversational classifier — tool path (must NOT be conversational) ───
@pytest.mark.parametrize(
    "query",
    [
        "מה המזג אוויר בתל אביב",
        "כמה שווה דולר",
        "תרגם hello",
        "חדשות ספורט",
        "מרחק תל אביב חיפה",
        "מחיר NVDA",
        "sha256 של test",
        "בדוק אייפי 1.1.1.1",
    ],
)
def test_classifier_routes_to_tools(query):
    assert asyncio.run(_is_conversational(query)) is False, f"{query!r} should route to tools, not chit-chat"


# ─── Capability questions route to tool path ──────────────────────────────
@pytest.mark.parametrize("query", ["מה אתה יכול לעשות", "רשימת כלים", "מה היכולות שלך"])
def test_capability_query_routes_to_tools(query):
    assert asyncio.run(_is_conversational(query)) is False


# ─── Skills loaded ─────────────────────────────────────────────────────────
EXPECTED_SKILLS = [
    "weather-skill",
    "currency-skill",
    "translator-skill",
    "news-monitor",
    "stocks-skill",
    "geocode-skill",
    "crypto-skill",
    "intel-skill",
    "file-analyst",
    "firewall-skill",
    "web-scraper",
    "report-maker",
]


@pytest.mark.parametrize("skill", EXPECTED_SKILLS)
def test_skill_loaded(skill):
    assert skill in get_skills_engine()._skills, f"Skill not loaded: {skill}"


def test_skills_count_at_least_12():
    count = len(get_skills_engine()._skills)
    assert count >= 12, f"Only {count} skills loaded, expected >= 12"


# ─── Core tools available ──────────────────────────────────────────────────
EXPECTED_TOOLS = [
    "get_system_snapshot",
    "get_process_list",
    "get_disk_details",
    "run_powershell",
    "web_search",
    "read_file",
]


@pytest.mark.parametrize("tool", EXPECTED_TOOLS)
def test_core_tool_registered(tool):
    tool_names = [t.get("function", {}).get("name", "") for t in _TOOLS + _TOOLS_BASIC]
    assert tool in tool_names, f"Tool not registered: {tool}"


# ─── Skill tools schema sanity ─────────────────────────────────────────────
def test_skill_tools_have_parameters_schema():
    skill_tools = get_skills_engine().get_tools()
    assert len(skill_tools) >= 12, f"Only {len(skill_tools)} skill tools"
    missing = [t.get("function", {}).get("name", "?") for t in skill_tools if "parameters" not in t.get("function", {})]
    assert not missing, f"Skill tools missing 'parameters' schema: {missing}"


# ─── Live LLM (opt-in via env var) ─────────────────────────────────────────
LIVE_ENABLED = os.environ.get("RUN_LIVE_LLM_TESTS") == "1"


@pytest.mark.skipif(
    not LIVE_ENABLED or not is_llm_ready(),
    reason="Live LLM tests disabled (set RUN_LIVE_LLM_TESTS=1 and ensure LLM reachable)",
)
@pytest.mark.parametrize(
    "query,expected_substrings",
    [
        ("היי", ["היי", "שלום", "👋"]),
        ("תרגם לעברית: hello", ["שלום"]),
    ],
)
def test_live_agent_response(query, expected_substrings):
    result = asyncio.run(run_agent(query))
    assert any(s in result for s in expected_substrings), (
        f"Response did not contain any of {expected_substrings}: {result[:200]!r}"
    )
