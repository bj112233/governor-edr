r"""Planner Tool Catalog tests — verify active_tools injected into Planner prompt.

Run:  .venv\Scripts\python.exe -m pytest tests/test_planner_catalog.py -v -s
"""

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._helpers import _decompose_task


async def test_decompose_task_injects_tool_catalog():
    """Planner prompt contains tool names from active_tools."""
    engine = AsyncMock()
    # Capture the system_prompt passed to engine.complete
    captured_prompts = {}

    async def capture_complete(**kwargs):
        captured_prompts["system"] = kwargs.get("system_prompt", "")
        captured_prompts["user"] = kwargs.get("user_input", "")
        return json.dumps(
            [
                {"id": "T1", "description": "Scan with scan_lan", "depends_on": []},
                {"id": "T2", "description": "Analyze with skill_intel-skill", "depends_on": ["T1"]},
            ]
        )

    engine.complete = capture_complete

    active_tools = [
        {"type": "function", "function": {"name": "scan_lan", "description": "Scan local network for devices"}},
        {
            "type": "function",
            "function": {"name": "skill_intel-skill", "description": "Threat intelligence enrichment"},
        },
        {"type": "function", "function": {"name": "final_answer", "description": "Provide final answer"}},
    ]

    result = await _decompose_task(
        user_question="scan network and analyze threats",
        active_tools=active_tools,
        engine=engine,
    )

    # Verify catalog in prompt
    system_prompt = captured_prompts.get("system", "")
    assert "AVAILABLE TOOLS" in system_prompt
    assert "scan_lan" in system_prompt
    assert "skill_intel-skill" in system_prompt
    assert "final_answer" in system_prompt
    assert "Scan local network" in system_prompt  # description truncated to 120
    print("PASS: Tool Catalog injected into Planner prompt")

    # Verify DAG parsed correctly
    assert len(result) == 2
    assert result[0]["id"] == "T1"
    assert result[1]["depends_on"] == ["T1"]
    print("PASS: Planner returns correct DAG")


async def test_decompose_task_flat_dict_format():
    """Supports flat dict format (not just OpenAI nested)."""
    engine = AsyncMock()
    captured = {}

    async def capture_complete(**kwargs):
        captured["system"] = kwargs.get("system_prompt", "")
        return '[{"id":"T1","description":"test","depends_on":[]}]'

    engine.complete = capture_complete

    # Flat format (no "function" wrapper)
    flat_tools = [
        {"name": "my_tool", "description": "Does something"},
    ]

    await _decompose_task("test", flat_tools, engine)

    assert "my_tool" in captured["system"]
    assert "Does something" in captured["system"]
    print("PASS: Flat dict format supported")


async def test_decompose_task_fallback_on_empty_tools():
    """Empty tools list still works (fallback to single subtask)."""
    engine = AsyncMock()
    engine.complete.side_effect = Exception("LLM failure")

    result = await _decompose_task("simple task", [], engine)

    assert len(result) == 1
    assert result[0]["description"] == "simple task"
    print("PASS: Empty tools fallback works")


def run_all():
    asyncio.run(test_decompose_task_injects_tool_catalog())
    asyncio.run(test_decompose_task_flat_dict_format())
    asyncio.run(test_decompose_task_fallback_on_empty_tools())
    print("\n=== ALL PLANNER CATALOG TESTS PASSED ===")


if __name__ == "__main__":
    run_all()
