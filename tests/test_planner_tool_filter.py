# tests/test_planner_tool_filter.py
"""Regression: Planner must strip hallucinated tool names from subtasks.

Bug (bot.log 2026-06-25 09:42): Planner created a subtask requiring
'get_event_log' even though that tool was NOT in the injected catalog
(tools_sent had only 7 tools, get_event_log excluded). The executor
blocked it as unauthorized, wasting 4 steps in interceptor death-loops
until the subtask was marked FAILED.

Fix: _filter_unauthorized_tools() scans subtask descriptions for
tool-like tokens (get_*, scan_*, skill_*) and strips any that are not
in the authorized set.
"""

from services.agent._agent_planner import _filter_unauthorized_tools


def test_strips_unauthorized_tool_from_description():
    """get_event_log not in catalog → name STRIPPED + anti-hallucination note.

    The literal tool name MUST be removed (not just flagged) — leaving it in the
    text causes the 4B model to fabricate its execution during synthesis.
    """
    subtasks = [
        {"id": "T1", "description": "Get system snapshot using get_system_snapshot", "depends_on": []},
        {"id": "T2", "description": "Retrieve event logs using get_event_log", "depends_on": ["T1"]},
    ]
    authorized = {"get_system_snapshot", "final_answer"}
    result = _filter_unauthorized_tools(subtasks, authorized)
    assert "UNAVAILABLE" in result[1]["description"]
    assert "get_event_log" not in result[1]["description"]  # name STRIPPED
    assert "get_system_snapshot" in result[0]["description"]  # authorized untouched
    assert "UNAVAILABLE" not in result[0]["description"]


def test_keeps_authorized_tools():
    """All mentioned tools in catalog → no changes."""
    subtasks = [
        {"id": "T1", "description": "Scan using get_process_list and get_disk_details", "depends_on": []},
    ]
    authorized = {"get_process_list", "get_disk_details", "final_answer"}
    result = _filter_unauthorized_tools(subtasks, authorized)
    assert result[0]["description"] == subtasks[0]["description"]


def test_strips_multiple_unauthorized():
    """Two hallucinated tools in one description → both names stripped + flagged."""
    subtasks = [
        {"id": "T1", "description": "Run get_event_log and scan_lan for data", "depends_on": []},
    ]
    authorized = {"final_answer"}
    result = _filter_unauthorized_tools(subtasks, authorized)
    assert "UNAVAILABLE" in result[0]["description"]
    assert "get_event_log" not in result[0]["description"]  # stripped
    assert "scan_lan" not in result[0]["description"]  # stripped


def test_preserves_non_tool_descriptions():
    """Description without tool tokens → untouched."""
    subtasks = [
        {"id": "T1", "description": "Analyze the gathered intelligence data", "depends_on": []},
    ]
    authorized = {"final_answer"}
    result = _filter_unauthorized_tools(subtasks, authorized)
    assert result[0]["description"] == subtasks[0]["description"]


def test_skill_prefix_filtered():
    """skill_ prefix tools are also validated."""
    subtasks = [
        {"id": "T1", "description": "Enrich using skill_intel-skill", "depends_on": []},
        {"id": "T2", "description": "Report via skill_report-maker", "depends_on": ["T1"]},
    ]
    authorized = {"skill_intel-skill", "final_answer"}
    result = _filter_unauthorized_tools(subtasks, authorized)
    assert "skill_intel-skill" in result[0]["description"]  # authorized
    assert "UNAVAILABLE" not in result[0]["description"]
    assert "UNAVAILABLE" in result[1]["description"]  # skill_report-maker flagged


def test_empty_subtasks():
    """Empty list → empty list."""
    assert _filter_unauthorized_tools([], {"final_answer"}) == []


if __name__ == "__main__":
    test_strips_unauthorized_tool_from_description()
    test_keeps_authorized_tools()
    test_strips_multiple_unauthorized()
    test_preserves_non_tool_descriptions()
    test_skill_prefix_filtered()
    test_empty_subtasks()
    print("OK")
