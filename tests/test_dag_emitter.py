"""Tests for DAG event emitter — subtask transition serialization.

Verifies:
  1. emit_dag_initial publishes all nodes as 'pending'
  2. emit_subtask_transition publishes transition + snapshot
  3. Emitter never raises on failure (telemetry must not crash agent)
  4. Snapshot strips large result fields (SSE payload budget)
  5. Empty subtasks → no emit (guard)
"""

from unittest.mock import AsyncMock, patch

import pytest

from services.agent._dag_emitter import (
    _build_snapshot,
    emit_dag_initial,
    emit_subtask_transition,
)


def _make_ctx(subtasks=None):
    """Minimal mock context with subtasks list."""

    class _Ctx:
        def __init__(self, subs):
            self.subtasks = subs

    return _Ctx(subtasks or [])


def _sample_subtasks():
    return [
        {"id": "T1", "description": "Gather data", "depends_on": [], "status": "done", "result": "x" * 500},
        {"id": "T2", "description": "Analyze", "depends_on": ["T1"], "status": "pending"},
        {"id": "T3", "description": "Report", "depends_on": ["T2"], "status": "pending"},
    ]


# ── Snapshot builder ──


def test_snapshot_strips_large_result_fields():
    """Snapshot must not include full 'result' — only 80-char preview."""
    subs = _sample_subtasks()
    snapshot = _build_snapshot(subs)
    assert len(snapshot) == 3
    # T1 has a 500-char result → snapshot should have result_preview ≤ 80
    t1 = snapshot[0]
    assert "result" not in t1
    assert "result_preview" in t1
    assert len(t1["result_preview"]) <= 80
    # T2/T3 have no result → no result_preview key
    assert "result_preview" not in snapshot[1]
    assert "result_preview" not in snapshot[2]


def test_snapshot_includes_core_fields():
    """Snapshot must include id, description, depends_on, status."""
    snapshot = _build_snapshot(_sample_subtasks())
    for entry in snapshot:
        assert "id" in entry
        assert "description" in entry
        assert "depends_on" in entry
        assert "status" in entry


# ── emit_dag_initial ──


@pytest.mark.asyncio
async def test_emit_dag_initial_calls_send_dag_update():
    """Initial emit publishes all subtasks with transition=None."""
    ctx = _make_ctx(_sample_subtasks())
    with patch("services.agent._dag_emitter.send_dag_update_event", new_callable=AsyncMock) as mock_send:
        await emit_dag_initial(ctx)
    mock_send.assert_called_once()
    call = mock_send.call_args
    session_id = call[0][0]
    subtasks = call[0][1]
    transition = call.kwargs.get("transition")
    assert session_id.startswith("agent_")
    assert len(subtasks) == 3
    assert transition is None


@pytest.mark.asyncio
async def test_emit_dag_initial_empty_subtasks_no_emit():
    """No subtasks → no emit call."""
    ctx = _make_ctx([])
    with patch("services.agent._dag_emitter.send_dag_update_event", new_callable=AsyncMock) as mock_send:
        await emit_dag_initial(ctx)
    mock_send.assert_not_called()


# ── emit_subtask_transition ──


@pytest.mark.asyncio
async def test_emit_subtask_transition_publishes_transition():
    """Transition emit includes from_status, to_status, task_id."""
    ctx = _make_ctx(_sample_subtasks())
    with patch("services.agent._dag_emitter.send_dag_update_event", new_callable=AsyncMock) as mock_send:
        await emit_subtask_transition(ctx, "T2", "pending", "done")
    mock_send.assert_called_once()
    call = mock_send.call_args
    transition = call[0][2] if len(call[0]) > 2 else call.kwargs.get("transition")
    assert transition == {"task_id": "T2", "from_status": "pending", "to_status": "done"}


@pytest.mark.asyncio
async def test_emit_subtask_transition_never_raises():
    """If send_dag_update_event raises, emitter swallows it (telemetry)."""
    ctx = _make_ctx(_sample_subtasks())
    with patch("services.agent._dag_emitter.send_dag_update_event", new_callable=AsyncMock) as mock_send:
        mock_send.side_effect = RuntimeError("bus down")
        # Must NOT raise
        await emit_subtask_transition(ctx, "T1", "pending", "done")


@pytest.mark.asyncio
async def test_emit_subtask_transition_empty_subtasks_no_emit():
    """No subtasks → no emit (guard against noise)."""
    ctx = _make_ctx([])
    with patch("services.agent._dag_emitter.send_dag_update_event", new_callable=AsyncMock) as mock_send:
        await emit_subtask_transition(ctx, "T1", "pending", "done")
    mock_send.assert_not_called()


# ── Session ID stability ──


def test_session_id_stable_for_same_ctx():
    """Same ctx object → same session_id (id() is stable per object lifetime)."""
    ctx = _make_ctx(_sample_subtasks())
    from services.agent._dag_emitter import _session_id

    sid1 = _session_id(ctx)
    sid2 = _session_id(ctx)
    assert sid1 == sid2
    assert sid1.startswith("agent_")


def test_session_id_differs_for_different_ctx():
    """Different ctx objects → different session_ids."""
    from services.agent._dag_emitter import _session_id

    ctx1 = _make_ctx(_sample_subtasks())
    ctx2 = _make_ctx(_sample_subtasks())
    assert _session_id(ctx1) != _session_id(ctx2)
