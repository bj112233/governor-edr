"""DAG event emitter — bridges agent subtask transitions to the C2 event bus.

Single responsibility: serialize ctx.subtasks into a DAG snapshot and emit
it via the Sentinel event bus for real-time SSE consumption by the dashboard.

Design constraints:
  - NEVER raises — DAG telemetry must not crash the agent loop.
  - NEVER blocks — fire-and-forget to the in-process event bus queue.
  - session_id derived from id(ctx) — stable within a single agent run.
  - Snapshot is a shallow copy of subtask dicts (strips large result fields
    to keep SSE payload < 2KB).
"""

import logging
from typing import Any

from services.sentinel_events import send_dag_update_event

logger = logging.getLogger(__name__)

# Fields to include in the SSE snapshot — excludes 'result'/'error' which
# can be large and are not needed for graph visualization.
_SNAPSHOT_FIELDS = ("id", "description", "depends_on", "status")


def _build_snapshot(subtasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract a lightweight snapshot of subtasks for SSE transport."""
    snapshot: list[dict[str, Any]] = []
    for st in subtasks:
        entry: dict[str, Any] = {k: st.get(k) for k in _SNAPSHOT_FIELDS if k in st}
        # Include truncated result preview (first 80 chars) for tooltip
        result = st.get("result", "")
        if result:
            entry["result_preview"] = str(result)[:80]
        snapshot.append(entry)
    return snapshot


def _session_id(ctx: Any) -> str:
    """Derive a stable session ID from the agent context."""
    return f"agent_{id(ctx)}"


async def emit_subtask_transition(
    ctx: Any,
    task_id: str,
    from_status: str,
    to_status: str,
) -> None:
    """Emit a DAG state transition event.

    Called at each of the 7 subtask status change points in the executor.
    Fire-and-forget — never raises, logs on failure at debug level.
    """
    if not ctx.subtasks:
        return
    try:
        snapshot = _build_snapshot(ctx.subtasks)
        transition = {"task_id": str(task_id), "from_status": from_status, "to_status": to_status}
        await send_dag_update_event(_session_id(ctx), snapshot, transition)
    except Exception as exc:
        logger.debug("[DAG-Emitter] transition emit failed: %s", exc)


async def emit_dag_initial(ctx: Any) -> None:
    """Emit the initial DAG structure after topological sort.

    All nodes start as 'pending' — the frontend builds the graph from this.
    Called once after _topological_sort in the planner.
    """
    if not ctx.subtasks:
        return
    try:
        snapshot = _build_snapshot(ctx.subtasks)
        await send_dag_update_event(_session_id(ctx), snapshot, transition=None)
    except Exception as exc:
        logger.debug("[DAG-Emitter] initial emit failed: %s", exc)
