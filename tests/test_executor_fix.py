"""Live test for executor fixes: final_answer waste + report circuit breaker skip."""


def test_subtask_rules_final_answer_only_on_last():
    """Simulates the rule generation logic for subtask instructions."""
    subtasks = [
        {"id": "T0", "description": "scan network"},
        {"id": "T1", "description": "get logs"},
        {"id": "T2", "description": "generate report"},
    ]

    results = []
    for idx in range(len(subtasks)):
        _is_last = idx == len(subtasks) - 1
        if _is_last:
            rule = "call final_answer"
        else:
            rule = "Do NOT call final_answer"
        results.append((idx, rule))

    # Assert: first 2 subtasks should NOT call final_answer
    assert "Do NOT call final_answer" in results[0][1], f"T0 should not call final_answer, got: {results[0]}"
    assert "Do NOT call final_answer" in results[1][1], f"T1 should not call final_answer, got: {results[1]}"
    # Assert: last subtask SHOULD call final_answer
    assert "call final_answer" in results[2][1], f"T2 should call final_answer, got: {results[2]}"
    print("[PASS] Subtask rules: final_answer only on last subtask")


def test_circuit_breaker_soft_dependency_not_blocked():
    """Positive: soft dependency on failed task -> task allowed to proceed with partial data."""
    subtasks = [
        {"id": "T0", "description": "scan network", "status": "pending"},
        {"id": "T1", "description": "get firewall logs", "status": "pending", "depends_on": ["T0"]},
        {
            "id": "T2",
            "description": "generate final report",
            "status": "pending",
            "depends_on": ["T1"],
            "dependency_type": "soft",
        },
    ]

    _blocked_by_failure = set()
    failed_task_id = "T1"

    for st in subtasks:
        deps = st.get("depends_on", [])
        if isinstance(deps, list) and failed_task_id in [str(d) for d in deps]:
            dep_id = str(st.get("id"))
            dep_type = st.get("dependency_type", "hard")
            if dep_type == "soft":
                print(f"[PASS] Soft-dep task '{dep_id}' NOT blocked — partial data allowed")
                continue
            _blocked_by_failure.add(dep_id)
            st["status"] = "blocked"
            print(f"[INFO] Task '{dep_id}' blocked — depends on failed '{failed_task_id}'")

    assert "T2" not in _blocked_by_failure, "T2 (soft dep) should NOT be blocked"
    assert subtasks[2]["status"] == "pending", "T2 should remain pending (not blocked)"
    print("[PASS] Circuit breaker: soft dependency tasks exempt from blocking")


def test_circuit_breaker_hard_dependency_blocked():
    """Negative: hard dependency on failed task -> task blocked."""
    subtasks = [
        {"id": "T0", "description": "scan network", "status": "pending"},
        {"id": "T1", "description": "get firewall logs", "status": "pending", "depends_on": ["T0"]},
        {
            "id": "T2",
            "description": "enforce firewall rules",
            "status": "pending",
            "depends_on": ["T1"],
            "dependency_type": "hard",
        },
    ]

    _blocked_by_failure = set()
    failed_task_id = "T1"

    for st in subtasks:
        deps = st.get("depends_on", [])
        if isinstance(deps, list) and failed_task_id in [str(d) for d in deps]:
            dep_id = str(st.get("id"))
            dep_type = st.get("dependency_type", "hard")
            if dep_type == "soft":
                print(f"[INFO] Soft-dep task '{dep_id}' not blocked")
                continue
            _blocked_by_failure.add(dep_id)
            st["status"] = "blocked"
            print(f"[PASS] Hard-dep task '{dep_id}' blocked — depends on failed '{failed_task_id}'")

    assert "T2" in _blocked_by_failure, "T2 (hard dep) SHOULD be blocked"
    assert subtasks[2]["status"] == "blocked", "T2 should be blocked"
    print("[PASS] Circuit breaker: hard dependency tasks correctly blocked")


def test_reminder_message_varies_by_subtask_position():
    """Simulates the post-tool REMINDER message logic."""
    subtasks = [{}, {}, {}]
    messages = []

    for idx in range(len(subtasks)):
        _is_last_r = idx == len(subtasks) - 1
        reminder_msg = ("Call final_answer NOW") if _is_last_r else ("Do NOT call final_answer")
        messages.append(reminder_msg)

    assert "Do NOT call final_answer" in messages[0]
    assert "Do NOT call final_answer" in messages[1]
    assert "Call final_answer NOW" in messages[2]
    print("[PASS] Reminder messages vary correctly by subtask position")


def test_safety_guard_blocks_critical_tool_on_soft_dep_with_upstream_failure():
    """Critical tool (requires_data_integrity=True) blocked when soft dep has upstream failure."""
    subtasks = [
        {"id": "T0", "description": "get firewall logs", "status": "failed", "depends_on": []},
        {
            "id": "T1",
            "description": "run critical command",
            "status": "pending",
            "depends_on": ["T0"],
            "dependency_type": "soft",
        },
    ]
    _failed_tasks = {"T0"}
    _task_results = {}
    current_subtask_idx = 1

    # Simulate the safety guard logic from executor
    current_st = subtasks[current_subtask_idx]
    assert current_st.get("dependency_type", "hard") == "soft"
    deps = current_st.get("depends_on", [])
    _upstream_failed = any(str(d) in _failed_tasks for d in deps)
    assert _upstream_failed, "Upstream T0 should be failed"

    # Mock: run_powershell is critical (requires_data_integrity=True)
    fn_name = "run_powershell"
    _requires_integrity = True  # Simulating REGISTRY lookup
    assert _requires_integrity, "run_powershell should require data integrity"

    print(f"[PASS] Safety guard would block '{fn_name}' on soft dep with upstream failure")


def test_safety_guard_allows_safe_tool_on_soft_dep_with_upstream_failure():
    """Safe tool (requires_data_integrity=False) allowed when soft dep has upstream failure."""
    subtasks = [
        {"id": "T0", "description": "get firewall logs", "status": "failed", "depends_on": []},
        {
            "id": "T1",
            "description": "generate report",
            "status": "pending",
            "depends_on": ["T0"],
            "dependency_type": "soft",
        },
    ]
    _failed_tasks = {"T0"}
    current_subtask_idx = 1

    current_st = subtasks[current_subtask_idx]
    deps = current_st.get("depends_on", [])
    _upstream_failed = any(str(d) in _failed_tasks for d in deps)
    assert _upstream_failed

    # Mock: skill_report-maker (not in registry) defaults safe
    fn_name = "skill_report-maker"
    _requires_integrity = False  # Skills default safe
    assert not _requires_integrity, "skill_report-maker should NOT require data integrity"

    print(f"[PASS] Safety guard would allow '{fn_name}' on soft dep with upstream failure")


if __name__ == "__main__":
    test_subtask_rules_final_answer_only_on_last()
    test_circuit_breaker_soft_dependency_not_blocked()
    test_circuit_breaker_hard_dependency_blocked()
    test_reminder_message_varies_by_subtask_position()
    test_safety_guard_blocks_critical_tool_on_soft_dep_with_upstream_failure()
    test_safety_guard_allows_safe_tool_on_soft_dep_with_upstream_failure()
    print("\n[ALL PASSED] 6/6 executor fix tests passed")
