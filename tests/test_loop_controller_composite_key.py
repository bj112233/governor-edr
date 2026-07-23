# tests/test_loop_controller_composite_key.py
"""Regression: Loop controller must use composite key (subtask_idx, tool, args).

Bug (bot.log 2026-06-25 16:51): During the final synthesis subtask (T4/4),
the LLM tried to call get_system_snapshot for fresh data. The loop
controller blocked it because the same tool was already called in
subtask T1 — even though this is a DIFFERENT subtask that legitimately
needs fresh data. The agent got stuck and finalized with empty output.

Fix: build_call_key now includes subtask_idx, so the same tool in
different subtasks produces different keys. Loops within the SAME
subtask are still detected.
"""

from services.agent._nodes.loop_controller import build_call_key


def test_same_tool_different_subtasks_produces_different_keys():
    """get_system_snapshot in T1 vs T4 → different keys (no false loop)."""
    key_t1 = build_call_key("get_system_snapshot", {}, subtask_idx=0)
    key_t4 = build_call_key("get_system_snapshot", {}, subtask_idx=3)
    assert key_t1 != key_t4


def test_same_tool_same_subtask_produces_same_key():
    """get_system_snapshot called twice in T1 → same key (loop detected)."""
    key_a = build_call_key("get_system_snapshot", {}, subtask_idx=0)
    key_b = build_call_key("get_system_snapshot", {}, subtask_idx=0)
    assert key_a == key_b


def test_different_tools_same_subtask_different_keys():
    """get_system_snapshot vs get_process_list in T1 → different keys."""
    key_a = build_call_key("get_system_snapshot", {}, subtask_idx=0)
    key_b = build_call_key("get_process_list", {}, subtask_idx=0)
    assert key_a != key_b


def test_same_tool_different_args_same_subtask_different_keys():
    """Same tool, different args → different keys (not a loop)."""
    key_a = build_call_key("skill_intel-skill", {"command": "ip", "target": "1.2.3.4"}, subtask_idx=0)
    key_b = build_call_key("skill_intel-skill", {"command": "sweep"}, subtask_idx=0)
    assert key_a != key_b


def test_default_subtask_idx_is_minus_one():
    """No subtask context (non-DAG mode) → subtask_idx=-1."""
    key = build_call_key("get_system_snapshot", {})
    assert key[0] == -1


def test_key_structure_is_tuple_of_three():
    """Composite key must be (subtask_idx, fn_name, args_hash)."""
    key = build_call_key("get_system_snapshot", {"x": 1}, subtask_idx=2)
    assert isinstance(key, tuple)
    assert len(key) == 3
    assert key[0] == 2
    assert key[1] == "get_system_snapshot"
    assert isinstance(key[2], str)


if __name__ == "__main__":
    test_same_tool_different_subtasks_produces_different_keys()
    test_same_tool_same_subtask_produces_same_key()
    test_different_tools_same_subtask_different_keys()
    test_same_tool_different_args_same_subtask_different_keys()
    test_default_subtask_idx_is_minus_one()
    test_key_structure_is_tuple_of_three()
    print("OK")
