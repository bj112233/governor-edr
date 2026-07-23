"""Smoke tests for Planner Node."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.agent._context import _AgentContext
from services.agent._helpers import _decompose_task, _should_decompose, _synthesize_results


def test_should_decompose():
    assert _should_decompose("hi") is False
    assert _should_decompose("what is the weather") is False
    long_multi = "scan network and analyze threats then create report"
    assert _should_decompose(long_multi) is True
    long_action2 = "check the cpu usage and send me an email with the report"
    assert _should_decompose(long_action2) is True
    print("PASS: _should_decompose")


async def test_decompose_task_json():
    class MockPlanner:
        async def complete(self, **kwargs):
            return '[{"description":"scan ports"},{"description":"check threats"}]'

    subtasks = await _decompose_task("scan and analyze", [], MockPlanner())
    assert len(subtasks) == 2
    assert subtasks[0]["description"] == "scan ports"
    assert subtasks[1]["description"] == "check threats"
    print("PASS: _decompose_task JSON parse (legacy fallback)")


async def test_decompose_task_plain_text():
    """Layer 1: plain-text TASK format — primary path for 4B model on KoboldCpp.

    The model emits one TASK line per subtask with pipe-delimited fields.
    This is the format the Planner prompt now requests (no response_format).
    """
    from services.agent._agent_planner import _parse_plain_text_tasks

    # Simulate realistic 4B output: TASK lines with DEPS and TYPE
    raw = (
        "TASK: T1 | Scan LAN for active hosts using scan_lan | DEPS: [] | TYPE: hard\n"
        "TASK: T2 | Enrich found IPs with skill_intel-skill ip | DEPS: [T1] | TYPE: hard\n"
        "TASK: T3 | Analyze system snapshot using get_system_snapshot | DEPS: [] | TYPE: hard\n"
        "TASK: T4 | Generate security report using skill_report-maker | DEPS: [T2,T3] | TYPE: soft"
    )
    parsed = _parse_plain_text_tasks(raw)
    assert len(parsed) == 4
    assert parsed[0]["id"] == "T1"
    assert parsed[0]["depends_on"] == []
    assert parsed[0]["dependency_type"] == "hard"
    assert parsed[1]["depends_on"] == ["T1"]
    assert parsed[3]["depends_on"] == ["T2", "T3"]
    assert parsed[3]["dependency_type"] == "soft"
    print("PASS: _parse_plain_text_tasks — full DAG with deps + types")


async def test_decompose_task_plain_text_via_engine():
    """End-to-end: MockPlanner returns plain-text → _decompose_task parses correctly."""

    class PlainTextPlanner:
        async def complete(self, **kwargs):
            return (
                "TASK: T1 | Scan ports using get_listening_ports | DEPS: [] | TYPE: hard\n"
                "TASK: T2 | Check threats using skill_intel-skill | DEPS: [T1] | TYPE: hard"
            )

    subtasks = await _decompose_task("scan and analyze", [], PlainTextPlanner())
    assert len(subtasks) == 2
    assert subtasks[0]["id"] == "T1"
    # Unauthorized tool names are STRIPPED (not just flagged) to prevent
    # the executor LLM from hallucinating their execution.
    assert "get_listening_ports" not in subtasks[0]["description"]
    assert "UNAVAILABLE" in subtasks[0]["description"]
    assert subtasks[1]["depends_on"] == ["T1"]
    print("PASS: _decompose_task plain-text via engine (Layer 1 primary)")


async def test_decompose_task_plain_text_tolerant_missing_type():
    """Lines without TYPE segment default to 'hard'."""
    from services.agent._agent_planner import _parse_plain_text_tasks

    raw = "TASK: T1 | Do something | DEPS: []\nTASK: T2 | Do more | DEPS: [T1]"
    parsed = _parse_plain_text_tasks(raw)
    assert len(parsed) == 2
    assert parsed[0]["dependency_type"] == "hard"
    assert parsed[1]["depends_on"] == ["T1"]
    print("PASS: _parse_plain_text_tasks — tolerant of missing TYPE")


async def test_decompose_task_no_response_format():
    """Verify Planner does NOT pass response_format to engine (regression).

    The 4B model on KoboldCpp breaks when response_format=json_object is set.
    This test ensures the Planner never re-introduces that parameter.
    """
    captured_kwargs = {}

    class CapturingPlanner:
        async def complete(self, **kwargs):
            captured_kwargs.update(kwargs)
            return "TASK: T1 | Do something | DEPS: [] | TYPE: hard"

    await _decompose_task("test", [], CapturingPlanner())
    assert "response_format" not in captured_kwargs, (
        "PLANNER REGRESSION: response_format=json_object must NEVER be set "
        "(see lessons.md 2026-06-16 — KoboldCpp 4B grammar enforcement breaks JSON)"
    )
    print("PASS: _decompose_task does NOT use response_format (regression guard)")


async def test_decompose_task_fallback():
    class BadPlanner:
        async def complete(self, **kwargs):
            return "not json"

    subtasks = await _decompose_task("simple", [], BadPlanner())
    assert len(subtasks) == 1
    assert subtasks[0]["description"] == "simple"
    print("PASS: _decompose_task fallback")


async def test_decompose_task_regex_recovery():
    """Layer 3: regex extraction when JSON is broken but fragments exist."""

    class BrokenJsonPlanner:
        async def complete(self, **kwargs):
            return 'Here is the plan:\n{"description":"scan ports"}\n{"description":"check threats"}\nDone.'

    subtasks = await _decompose_task("scan and analyze", [], BrokenJsonPlanner())
    assert len(subtasks) == 2
    assert subtasks[0]["description"] == "scan ports"
    assert subtasks[1]["description"] == "check threats"
    print("PASS: _decompose_task regex recovery (Layer 3)")


async def test_synthesize_results():
    class MockSynth:
        system_prompt = ""

        async def complete(self, **kwargs):
            self.system_prompt = kwargs["system_prompt"]
            return "Combined result"

    synth = MockSynth()
    result = await _synthesize_results("q", ["A", "B"], synth)
    assert result == "Combined result"
    assert "Encoded Commands" in synth.system_prompt
    assert "Execution Policy Bypass" in synth.system_prompt
    print("PASS: _synthesize_results")

    result = await _synthesize_results("q", ["A"], MockSynth())
    assert result == "A"
    print("PASS: _synthesize_results single")

    result = await _synthesize_results("q", [], MockSynth())
    assert "failed" not in result.lower()  # Hebrew fallback
    print("PASS: _synthesize_results empty")


def test_agent_context_fields():
    ctx = _AgentContext(user_question="q", messages=[], active_tools=[], step_max_tokens=100)
    assert ctx.subtasks == []
    assert ctx.current_subtask_idx == -1
    assert ctx._subtask_injected_for == ""
    print("PASS: _AgentContext fields")


if __name__ == "__main__":
    test_should_decompose()
    asyncio.run(test_decompose_task_plain_text())
    asyncio.run(test_decompose_task_plain_text_via_engine())
    asyncio.run(test_decompose_task_plain_text_tolerant_missing_type())
    asyncio.run(test_decompose_task_no_response_format())
    asyncio.run(test_decompose_task_json())
    asyncio.run(test_decompose_task_fallback())
    asyncio.run(test_decompose_task_regex_recovery())
    asyncio.run(test_synthesize_results())
    test_agent_context_fields()
    print("\nAll planner smoke tests passed.")
