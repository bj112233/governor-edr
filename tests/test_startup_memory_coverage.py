# tests/test_startup_memory_coverage.py
"""Coverage tests for startup workers, broadcast, vector manager, archive,
memory summarizer, and alert history.

Uses the autouse isolated_db + stub_llm_embedding fixtures from conftest.py.
All network/LLM calls are mocked.
"""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── 1. services/startup/_workers.py ────────────────────────────────────────────
from services.startup import _workers as workers

# ── _load_soc_prompt ──


def test_load_soc_prompt_default(monkeypatch):
    """When the prompt file does not exist, the embedded default is returned."""
    monkeypatch.setattr(workers, "_SOC_PROMPT_PATH", "/nonexistent/soc_prompt.txt")
    result = workers._load_soc_prompt()
    assert "CRITICAL OUTPUT RULE" in result
    assert "Hebrew" in result


def test_load_soc_prompt_from_file(tmp_path, monkeypatch):
    """When the prompt file exists, its content is loaded."""
    prompt_file = tmp_path / "soc_prompt.txt"
    prompt_file.write_text("Custom SOC prompt content", encoding="utf-8")
    monkeypatch.setattr(workers, "_SOC_PROMPT_PATH", str(prompt_file))
    result = workers._load_soc_prompt()
    assert result == "Custom SOC prompt content"


def test_load_soc_prompt_handles_read_error(monkeypatch):
    """If reading the file raises, the default prompt is returned."""
    bad_path = Path("/nonexistent_dir/soc_prompt.txt")
    monkeypatch.setattr(workers, "_SOC_PROMPT_PATH", str(bad_path))
    result = workers._load_soc_prompt()
    assert "CRITICAL OUTPUT RULE" in result


# ── _compute_severity ──


def test_compute_severity_critical_cpu():
    assert "קריטית" in workers._compute_severity(95, 50, [], [])


def test_compute_severity_critical_ram():
    assert "קריטית" in workers._compute_severity(50, 96, [], [])


def test_compute_severity_high():
    assert "גבוהה" in workers._compute_severity(86, 50, [], [])


def test_compute_severity_high_disk():
    assert "גבוהה" in workers._compute_severity(50, 50, ["disk1"], [])


def test_compute_severity_medium():
    assert "בינונית" in workers._compute_severity(71, 50, [], [])


def test_compute_severity_medium_susp_net():
    assert "בינונית" in workers._compute_severity(50, 50, [], ["a"] * 6)


def test_compute_severity_low():
    assert "נמוכה" in workers._compute_severity(50, 50, [], [])


# ── _analyze_suspicious_net ──


def test_analyze_suspicious_net_non_standard_port():
    """Connections with non-standard ports are flagged."""
    result = workers._analyze_suspicious_net(["1.2.3.4:9999"])
    assert "לא סטנדרטיים" in result


def test_analyze_suspicious_net_standard_port_only():
    """Connections with only standard ports are categorized as external."""
    result = workers._analyze_suspicious_net(["1.2.3.4:443"])
    assert "חיצוניים" in result


def test_analyze_suspicious_net_empty():
    result = workers._analyze_suspicious_net([])
    assert "חיצוניים" in result


# ── _compute_categories ──


def test_compute_categories_all_signals():
    cats = workers._compute_categories(95, 95, ["disk_alert"], ["1.2.3.4:9999"])
    assert "עומס CPU" in cats
    assert "עומס זיכרון" in cats
    assert "אחסון" in cats
    assert any("רשת" in c for c in cats)


def test_compute_categories_empty():
    cats = workers._compute_categories(10, 10, [], [])
    assert cats == []


# ── _rule_based_analysis ──


def test_rule_based_analysis_with_signals():
    snapshot = {"cpu": 95, "mem": 96, "disk_alerts": ["alert1"], "suspicious_net": []}
    result = workers._rule_based_analysis(snapshot)
    assert "קריטית" in result
    assert "heuristic" in result


def test_rule_based_analysis_no_signals():
    snapshot = {"cpu": 10, "mem": 10, "disk_alerts": [], "suspicious_net": []}
    result = workers._rule_based_analysis(snapshot)
    assert "נמוכה" in result
    assert "כללית" in result


# ── llm_analysis_worker ──


async def test_llm_analysis_worker_rule_based_fallback():
    """When LLM is not ready, the worker uses rule-based fallback."""
    queue: asyncio.Queue = asyncio.Queue()
    snapshot = {
        "cpu": 95,
        "mem": 50,
        "disk_alerts": ["disk_full"],
        "top_procs": [{"name": "miner.exe"}, {"name": "chrome.exe"}],
        "suspicious_net": ["1.2.3.4:9999"],
        "alert_needed": True,
    }
    await queue.put(snapshot)

    # is_llm_ready is imported inside the function body via `from services.llm_bridge import is_llm_ready`
    with patch("services.llm_bridge.is_llm_ready", return_value=False):
        send_mock = AsyncMock()
        save_mock = AsyncMock()
        with (
            patch.object(workers, "send_alert_event", send_mock),
            patch.object(workers, "save_alert", save_mock),
        ):
            task = asyncio.create_task(workers.llm_analysis_worker(queue))
            await asyncio.sleep(0.3)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    send_mock.assert_awaited_once()
    save_mock.assert_awaited_once()
    # The report should contain rule-based fallback
    args = send_mock.call_args.args
    report = args[1]
    assert "heuristic" in report


async def test_llm_analysis_worker_with_llm():
    """When LLM is ready and returns a valid report, it is used."""
    queue: asyncio.Queue = asyncio.Queue()
    snapshot = {
        "cpu": 95,
        "mem": 50,
        "disk_alerts": [],
        "top_procs": [],
        "suspicious_net": [],
        "alert_needed": True,
    }
    await queue.put(snapshot)

    with (
        patch("services.llm_bridge.is_llm_ready", return_value=True),
        patch.object(workers, "analyze_data", AsyncMock(return_value="Valid LLM analysis report")),
        patch.object(workers, "send_alert_event", AsyncMock()) as send_mock,
        patch.object(workers, "save_alert", AsyncMock()) as save_mock,
    ):
        task = asyncio.create_task(workers.llm_analysis_worker(queue))
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    send_mock.assert_awaited_once()
    save_mock.assert_awaited_once()
    report = send_mock.call_args.args[1]
    assert report == "Valid LLM analysis report"


async def test_llm_analysis_worker_timeout_fallback():
    """When LLM times out, rule-based fallback is used."""
    queue: asyncio.Queue = asyncio.Queue()
    snapshot = {"cpu": 95, "mem": 50, "disk_alerts": [], "top_procs": [], "suspicious_net": []}
    await queue.put(snapshot)

    async def _timeout(*a, **kw):
        raise TimeoutError()

    with (
        patch("services.llm_bridge.is_llm_ready", return_value=True),
        patch.object(workers, "analyze_data", _timeout),
        patch.object(workers, "send_alert_event", AsyncMock()) as send_mock,
        patch.object(workers, "save_alert", AsyncMock()),
    ):
        task = asyncio.create_task(workers.llm_analysis_worker(queue))
        await asyncio.sleep(0.3)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    report = send_mock.call_args.args[1]
    assert "heuristic" in report


# ── monitor_loop ──


async def test_monitor_loop_one_iteration_legacy(monkeypatch):
    """Legacy mode (MONITOR_AI_ENABLED=False): snapshot with alert_needed is enqueued."""
    monkeypatch.setattr(workers, "MONITOR_AI_ENABLED", False)
    monkeypatch.setattr(workers, "MONITOR_INTERVAL", 0.01)

    snapshot = {"cpu": 95, "mem": 50, "disk_alerts": [], "alert_needed": True}

    put_mock = AsyncMock()
    get_snapshot_mock = AsyncMock(return_value=snapshot)
    baseline_mock = MagicMock(return_value=[])

    with (
        patch.object(workers, "get_system_snapshot", get_snapshot_mock),
        patch.object(workers, "put_alert_snapshot", put_mock),
        patch.object(workers, "_collect_net_baseline_rows", baseline_mock),
    ):
        queue: asyncio.Queue = asyncio.Queue()
        bg_tasks: set = set()
        task = asyncio.create_task(workers.monitor_loop(queue, bg_tasks))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    put_mock.assert_awaited()


async def test_monitor_loop_nominal_legacy(monkeypatch):
    """Legacy mode: nominal snapshot (no alert) does not enqueue."""
    monkeypatch.setattr(workers, "MONITOR_AI_ENABLED", False)
    monkeypatch.setattr(workers, "MONITOR_INTERVAL", 0.01)

    snapshot = {"cpu": 10, "mem": 10, "disk_alerts": [], "alert_needed": False}

    put_mock = AsyncMock()
    with (
        patch.object(workers, "get_system_snapshot", AsyncMock(return_value=snapshot)),
        patch.object(workers, "put_alert_snapshot", put_mock),
        patch.object(workers, "_collect_net_baseline_rows", MagicMock(return_value=[])),
    ):
        queue: asyncio.Queue = asyncio.Queue()
        bg_tasks: set = set()
        task = asyncio.create_task(workers.monitor_loop(queue, bg_tasks))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    put_mock.assert_not_awaited()


async def test_monitor_loop_ai_mode_no_analyzer(monkeypatch):
    """AI mode but analyzer is None: falls back to legacy threshold logic."""
    monkeypatch.setattr(workers, "MONITOR_AI_ENABLED", True)
    monkeypatch.setattr(workers, "MONITOR_INTERVAL", 0.01)

    snapshot = {"cpu": 95, "mem": 50, "disk_alerts": [], "alert_needed": True}

    put_mock = AsyncMock()
    with (
        patch.object(workers, "get_system_snapshot", AsyncMock(return_value=snapshot)),
        patch.object(workers, "put_alert_snapshot", put_mock),
        patch.object(workers, "_collect_net_baseline_rows", MagicMock(return_value=[])),
        patch.object(workers, "_get_monitor_analyzer", lambda: None),
    ):
        queue: asyncio.Queue = asyncio.Queue()
        bg_tasks: set = set()
        task = asyncio.create_task(workers.monitor_loop(queue, bg_tasks))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    put_mock.assert_awaited()


async def test_monitor_loop_ai_mode_with_analyzer_nominal(monkeypatch):
    """AI mode with analyzer returning no anomalies: nominal path."""
    monkeypatch.setattr(workers, "MONITOR_AI_ENABLED", True)
    monkeypatch.setattr(workers, "MONITOR_INTERVAL", 0.01)

    snapshot = {"cpu": 10, "mem": 10, "disk_alerts": [], "alert_needed": False}

    analyzer = MagicMock()
    analyzer.analyze = AsyncMock(return_value=([], []))

    put_mock = AsyncMock()
    with (
        patch.object(workers, "get_system_snapshot", AsyncMock(return_value=snapshot)),
        patch.object(workers, "put_alert_snapshot", put_mock),
        patch.object(workers, "_collect_net_baseline_rows", MagicMock(return_value=[])),
        patch.object(workers, "_get_monitor_analyzer", lambda: analyzer),
    ):
        queue: asyncio.Queue = asyncio.Queue()
        bg_tasks: set = set()
        task = asyncio.create_task(workers.monitor_loop(queue, bg_tasks))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    put_mock.assert_not_awaited()


async def test_monitor_loop_ai_mode_with_anomalies(monkeypatch):
    """AI mode with anomalies: dispatcher is called, critical anomalies are snapshotted."""
    monkeypatch.setattr(workers, "MONITOR_AI_ENABLED", True)
    monkeypatch.setattr(workers, "MONITOR_INTERVAL", 0.01)

    snapshot = {"cpu": 95, "mem": 50, "disk_alerts": [], "alert_needed": True}

    anomaly = MagicMock()
    anomaly.severity = "critical"
    anomaly.category = "cpu"
    anomaly.reason = "spike"

    analyzer = MagicMock()
    analyzer.analyze = AsyncMock(return_value=([anomaly], []))

    dispatch_result = MagicMock()
    dispatch_result.sent = 1
    dispatch_result.suppressed_cooldown = 0
    dispatch_result.suppressed_rate_limit = 0
    dispatch_result.suppressed_severity = 0

    dispatcher = MagicMock()
    dispatcher.dispatch = AsyncMock(return_value=dispatch_result)

    put_mock = AsyncMock()
    with (
        patch.object(workers, "get_system_snapshot", AsyncMock(return_value=snapshot)),
        patch.object(workers, "put_alert_snapshot", put_mock),
        patch.object(workers, "_collect_net_baseline_rows", MagicMock(return_value=[])),
        patch.object(workers, "_get_monitor_analyzer", lambda: analyzer),
        patch.object(workers, "_get_alert_dispatcher", lambda: dispatcher),
    ):
        queue: asyncio.Queue = asyncio.Queue()
        bg_tasks: set = set()
        task = asyncio.create_task(workers.monitor_loop(queue, bg_tasks))
        await asyncio.sleep(0.15)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    dispatcher.dispatch.assert_awaited()
    put_mock.assert_awaited()


# ── 2. services/startup/_broadcast.py ──────────────────────────────────────────


from services.startup import _broadcast as broadcast


def test_build_action_buttons_both():
    actions = {"ip": "1.2.3.4", "pid": 666, "alert_id": "42"}
    btns = broadcast._build_action_buttons(actions)
    assert len(btns) == 2
    assert btns[0].text.startswith("🔴")
    assert btns[1].text.startswith("💀")


def test_build_action_buttons_ip_only():
    actions = {"ip": "1.2.3.4", "alert_id": "10"}
    btns = broadcast._build_action_buttons(actions)
    assert len(btns) == 1
    assert "Block" in btns[0].text


def test_build_action_buttons_pid_only():
    actions = {"pid": 999, "alert_id": "11"}
    btns = broadcast._build_action_buttons(actions)
    assert len(btns) == 1
    assert "Kill" in btns[0].text


def test_build_action_buttons_empty():
    btns = broadcast._build_action_buttons({})
    assert btns == []


def test_build_auto_buttons_auto_block():
    rem = {"auto_block_queued": "abc123"}
    btns: list = []
    broadcast._build_auto_buttons(rem, btns)
    assert len(btns) == 1
    assert "Approve Block" in btns[0].text


def test_build_auto_buttons_auto_kill():
    rem = {"kill_process_queued": "task1", "kill_pid": 777}
    btns: list = []
    broadcast._build_auto_buttons(rem, btns)
    assert len(btns) == 1
    assert "Approve Kill" in btns[0].text
    assert "777" in btns[0].text


def test_build_auto_buttons_no_duplicates():
    """Auto buttons should not duplicate existing manual buttons."""
    rem = {"auto_block_queued": "abc", "kill_process_queued": "def", "kill_pid": 1}
    existing = [MagicMock(text="🔴 Block IP")]
    broadcast._build_auto_buttons(rem, existing)
    # Block button should NOT be added (already present)
    assert len(existing) == 2  # original block + auto kill
    assert "Kill" in existing[1].text


def test_build_alert_keyboard_with_actions():
    event = MagicMock()
    event.event_type = "alert"
    event.data = {
        "remediation": {
            "actions": {"ip": "1.2.3.4", "pid": 666, "alert_id": "42"},
            "auto_block_queued": "abc",
        }
    }
    kb = broadcast._build_alert_keyboard(event)
    assert kb is not None
    # Should have block + kill + ignore buttons
    assert len(kb.inline_keyboard[0]) >= 2


def test_build_alert_keyboard_no_buttons():
    event = MagicMock()
    event.event_type = "alert"
    event.data = {"remediation": {}}
    kb = broadcast._build_alert_keyboard(event)
    assert kb is None


def test_build_alert_keyboard_non_dict_remediation():
    event = MagicMock()
    event.event_type = "alert"
    event.data = {"remediation": "not a dict"}
    kb = broadcast._build_alert_keyboard(event)
    assert kb is None


def test_build_alert_keyboard_non_alert_event():
    event = MagicMock()
    event.event_type = "daily_digest"
    event.data = {}
    # Non-alert events don't get keyboards via _forward_event, but _build_alert_keyboard
    # itself still processes — verify it returns None for empty remediation
    kb = broadcast._build_alert_keyboard(event)
    assert kb is None


async def test_wait_for_bot_ready():
    tg = MagicMock()
    tg.bot = MagicMock()  # bot is not None
    result = await broadcast._wait_for_bot(tg, timeout_s=3)
    assert result is True


async def test_wait_for_bot_timeout():
    tg = MagicMock()
    tg.bot = None
    result = await broadcast._wait_for_bot(tg, timeout_s=1)
    assert result is False


async def test_forward_event_success():
    from services.sentinel_events import SentinelEvent

    tg = MagicMock()
    tg.send_message = AsyncMock(return_value=True)
    event = SentinelEvent(
        event_type="daily_digest",
        priority="normal",
        data={"report": "test", "ai_analysis": "analysis"},
    )
    await broadcast._forward_event(tg, event, "chat123")
    tg.send_message.assert_awaited_once()


async def test_forward_event_failure():
    from services.sentinel_events import SentinelEvent

    tg = MagicMock()
    tg.send_message = AsyncMock(return_value=False)
    event = SentinelEvent(
        event_type="daily_digest",
        priority="normal",
        data={"report": "test"},
    )
    await broadcast._forward_event(tg, event, "chat123")
    tg.send_message.assert_awaited_once()


async def test_telegram_event_broadcaster_no_chat_id(monkeypatch):
    """When TELEGRAM_CHAT_ID is not set, broadcaster aborts immediately."""
    monkeypatch.setattr(broadcast, "TELEGRAM_CHAT_ID", "")
    tg = MagicMock()
    await broadcast._telegram_event_broadcaster(tg)
    # Should return without subscribing


async def test_telegram_event_broadcaster_bot_not_ready(monkeypatch):
    """When bot is not ready after timeout, broadcaster aborts."""
    monkeypatch.setattr(broadcast, "TELEGRAM_CHAT_ID", "chat123")
    tg = MagicMock()
    tg.bot = None
    with patch.object(broadcast, "_wait_for_bot", AsyncMock(return_value=False)):
        await broadcast._telegram_event_broadcaster(tg)
    # Should return without subscribing


async def test_telegram_event_broadcaster_skips_dag_update(monkeypatch):
    """dag_update events are skipped (dashboard-only)."""
    monkeypatch.setattr(broadcast, "TELEGRAM_CHAT_ID", "chat123")
    tg = MagicMock()
    tg.bot = MagicMock()
    tg.send_message = AsyncMock(return_value=True)

    # Subscribe to event bus, then push a dag_update + a normal event
    from services.sentinel_events import SentinelEvent, event_bus

    bus = event_bus
    sub_queue = await bus.subscribe()

    dag_event = SentinelEvent(
        event_type="dag_update",
        priority="normal",
        data={"session_id": "s1", "subtasks": [], "transition": None},
    )

    normal_event = SentinelEvent(
        event_type="daily_digest",
        priority="normal",
        data={"report": "test digest", "ai_analysis": "analysis"},
    )

    task = asyncio.create_task(broadcast._telegram_event_broadcaster(tg))
    await asyncio.sleep(0.1)

    await bus.emit(dag_event)
    await bus.emit(normal_event)
    await asyncio.sleep(0.2)

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # send_message should only be called for the normal event, not dag_update
    assert tg.send_message.await_count == 1
    await bus.unsubscribe(sub_queue)


# ── 3. services/bot_memory/vector_manager.py ───────────────────────────────────


from services.bot_memory import vector_manager as vm


async def test_vectorlite_search_memories_unavailable():
    """When vectorlite is not available, search returns None."""
    with patch.object(vm, "_VECTORLITE_AVAILABLE", False):
        from services.bot_memory.models import MemoryQuery

        mq = MemoryQuery(query="test", limit=5)
        result = await vm._vectorlite_search_memories(mq)
    assert result is None


async def test_vectorlite_upsert_memory_unavailable():
    """When vectorlite is not available, upsert is a no-op."""
    with patch.object(vm, "_VECTORLITE_AVAILABLE", False):
        await vm._vectorlite_upsert_memory(1, b"\x00" * 32)


async def test_incremental_cluster_unavailable():
    """When vectorlite is not available, cluster returns empty string."""
    with patch.object(vm, "_VECTORLITE_AVAILABLE", False):
        result = await vm._incremental_cluster(1, b"\x00" * 32)
    assert result == ""


def test_get_init_lock():
    """_get_init_lock creates and returns a lock."""
    vm._VECTORLITE_INIT_LOCK = None
    lock1 = vm._get_init_lock()
    lock2 = vm._get_init_lock()
    assert lock1 is lock2
    assert isinstance(lock1, asyncio.Lock)


async def test_vectorlite_search_memories_exception_returns_none():
    """When vectorlite is available but an error occurs, returns None."""
    from services.bot_memory.models import MemoryQuery

    mq = MemoryQuery(query="test", limit=5)
    # Patch to be available but make the embedding service fail
    with (
        patch.object(vm, "_VECTORLITE_AVAILABLE", True),
        patch("services.embedding_service.get_embedding_service", side_effect=Exception("no svc")),
    ):
        result = await vm._vectorlite_search_memories(mq)
    assert result is None


async def test_vectorlite_upsert_memory_with_db_param():
    """When db param is provided, upsert uses the given connection."""
    mock_db = AsyncMock()
    with (
        patch.object(vm, "_VECTORLITE_AVAILABLE", True),
        patch.object(vm, "_VECTORLITE_INDEX_DIM", 8),
    ):
        await vm._vectorlite_upsert_memory(1, b"\x00" * 32, db=mock_db)
    # Should have called execute 3 times: CREATE, DELETE, INSERT
    assert mock_db.execute.await_count == 3


async def test_vectorlite_upsert_memory_with_pool():
    """When no db param, upsert uses pool and commits."""
    mock_pool = MagicMock()
    mock_db = AsyncMock()
    mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db)
    mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=None)

    with (
        patch.object(vm, "_VECTORLITE_AVAILABLE", True),
        patch.object(vm, "_VECTORLITE_INDEX_DIM", 8),
        patch.object(vm, "_pool", mock_pool),
    ):
        await vm._vectorlite_upsert_memory(1, b"\x00" * 32)
    # Should have called execute 3 times + commit
    assert mock_db.execute.await_count == 3
    mock_db.commit.assert_awaited_once()


async def test_vectorlite_upsert_memory_exception_swallowed():
    """Exceptions in upsert are caught and logged, not raised."""
    mock_db = AsyncMock()
    mock_db.execute.side_effect = Exception("DB error")
    with (
        patch.object(vm, "_VECTORLITE_AVAILABLE", True),
        patch.object(vm, "_VECTORLITE_INDEX_DIM", 8),
    ):
        # Should not raise
        await vm._vectorlite_upsert_memory(1, b"\x00" * 32, db=mock_db)


async def test_incremental_cluster_exception_returns_empty():
    """Exceptions in _incremental_cluster return empty string."""
    mock_pool = MagicMock()
    mock_pool.acquire.side_effect = Exception("pool error")
    with (
        patch.object(vm, "_VECTORLITE_AVAILABLE", True),
        patch.object(vm, "_pool", mock_pool),
    ):
        result = await vm._incremental_cluster(1, b"\x00" * 32)
    assert result == ""


# ── 4. services/bot_memory/archive.py ──────────────────────────────────────────


from services.bot_memory import archive
from services.bot_memory.models import MemoryEntry
from services.memory_store import _ensure_init as memory_init


async def _insert_test_memory(
    query: str = "test q", response: str = "test r", memory_type: str = "conversation", context: str = ""
) -> int:
    """Helper: insert a memory row and return its id."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "INSERT INTO memories (ts, query, response, context, memory_type) VALUES (?, ?, ?, ?, ?)",
            (datetime.now().isoformat(), query, response, context, memory_type),
        )
        await db.commit()
        return cursor.lastrowid


async def test_archive_memories_by_ids_empty():
    """Archiving an empty list returns 0."""
    result = await archive.archive_memories_by_ids([])
    assert result == 0


async def test_archive_memories_by_ids():
    """Archiving specific IDs marks them as archived."""
    id1 = await _insert_test_memory("q1", "r1")
    id2 = await _insert_test_memory("q2", "r2")
    result = await archive.archive_memories_by_ids([id1, id2])
    assert result == 2

    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT is_archived FROM memories WHERE id = ?", (id1,))).fetchone()
    assert row[0] == 1


async def test_archive_memories_by_ids_with_db_param():
    """Archiving with an explicit db connection does not commit."""
    from services.memory_store import get_memory_pool

    id1 = await _insert_test_memory("qdb", "rdb")
    async with get_memory_pool().acquire() as db:
        result = await archive.archive_memories_by_ids([id1], db=db)
        assert result == 1
        # Not committed yet — verify within same connection
        row = await (await db.execute("SELECT is_archived FROM memories WHERE id = ?", (id1,))).fetchone()
        assert row[0] == 1
        await db.commit()


async def test_restore_archived_memories_empty():
    result = await archive.restore_archived_memories([])
    assert result == 0


async def test_restore_archived_memories():
    """Restoring archived memories sets is_archived back to 0."""
    id1 = await _insert_test_memory("rq1", "rr1")
    await archive.archive_memories_by_ids([id1])
    result = await archive.restore_archived_memories([id1])
    assert result == 1

    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT is_archived FROM memories WHERE id = ?", (id1,))).fetchone()
    assert row[0] == 0


async def test_vacuum_archived_memories_no_rows():
    """Vacuum with no archived rows returns 0."""
    await memory_init()
    result = await archive.vacuum_archived_memories(days=7)
    assert result == 0


async def test_vacuum_archived_memories():
    """Vacuum hard-deletes archived memories older than N days."""
    old_ts = (datetime.now() - timedelta(days=10)).isoformat()
    from services.memory_store import get_memory_pool

    await memory_init()
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "INSERT INTO memories (ts, query, response, context, memory_type, is_archived) VALUES (?, ?, ?, ?, ?, 1)",
            (old_ts, "vq", "vr", "", "conversation"),
        )
        old_id = cursor.lastrowid
        await db.commit()

    result = await archive.vacuum_archived_memories(days=7)
    assert result == 1

    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT id FROM memories WHERE id = ?", (old_id,))).fetchone()
    assert row is None


async def test_clear_conversation_memory():
    """Clear conversation memory archives all conversation-type entries."""
    id1 = await _insert_test_memory("cq1", "cr1", "conversation")
    id2 = await _insert_test_memory("cq2", "cr2", "conversation")
    result = await archive.clear_conversation_memory()
    assert result >= 2

    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        rows = await (await db.execute("SELECT is_archived FROM memories WHERE id IN (?, ?)", (id1, id2))).fetchall()
    assert all(r[0] == 1 for r in rows)


async def test_cleanup_old_memories():
    """Cleanup archives memories older than specified days."""
    old_ts = (datetime.now() - timedelta(days=10)).isoformat()
    from services.memory_store import get_memory_pool

    await memory_init()
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            "INSERT INTO memories (ts, query, response, context, memory_type) VALUES (?, ?, ?, ?, ?)",
            (old_ts, "oldq", "oldr", "", "conversation"),
        )
        old_id = cursor.lastrowid
        await db.commit()

    result = await archive.cleanup_old_memories(days=7)
    assert result >= 1

    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT is_archived FROM memories WHERE id = ?", (old_id,))).fetchone()
    assert row[0] == 1


async def test_fetch_old_memories_for_compaction():
    """Fetch old memories groups by topic and chunks by char limit."""
    old_ts = (datetime.now() - timedelta(days=31)).isoformat()
    from services.memory_store import get_memory_pool

    await memory_init()
    async with get_memory_pool().acquire() as db:
        # Insert entries with different topics
        for i in range(3):
            ctx = json.dumps({"topic": "cyber"})
            await db.execute(
                "INSERT INTO memories (ts, query, response, context, memory_type) VALUES (?, ?, ?, ?, ?)",
                (old_ts, f"q{i}", "r" * 100, ctx, "conversation"),
            )
        # One with different topic
        ctx2 = json.dumps({"topic": "economy"})
        await db.execute(
            "INSERT INTO memories (ts, query, response, context, memory_type) VALUES (?, ?, ?, ?, ?)",
            (old_ts, "qe", "re", ctx2, "conversation"),
        )
        await db.commit()

    chunks = await archive.fetch_old_memories_for_compaction(days_old=30, max_chunk_chars=250)
    assert len(chunks) >= 1
    # All entries should be MemoryEntry instances
    for chunk in chunks:
        for entry in chunk:
            assert isinstance(entry, MemoryEntry)


async def test_fetch_old_memories_for_compaction_empty():
    """No old memories returns empty list."""
    await memory_init()
    chunks = await archive.fetch_old_memories_for_compaction(days_old=30)
    assert chunks == []


async def test_fetch_old_memories_compaction_invalid_context():
    """Entries with invalid JSON context default to 'general' topic."""
    old_ts = (datetime.now() - timedelta(days=31)).isoformat()
    from services.memory_store import get_memory_pool

    await memory_init()
    async with get_memory_pool().acquire() as db:
        await db.execute(
            "INSERT INTO memories (ts, query, response, context, memory_type) VALUES (?, ?, ?, ?, ?)",
            (old_ts, "q", "r", "invalid json{", "conversation"),
        )
        await db.commit()

    chunks = await archive.fetch_old_memories_for_compaction(days_old=30)
    assert len(chunks) >= 1


# ── 5. services/memory_summarizer.py ───────────────────────────────────────────


from services import memory_summarizer as ms


def test_build_summary_prompt_with_profile():
    prompt = ms._build_summary_prompt({"preferences": ["x"]}, ["user: hello", "assistant: hi"])
    assert "user: hello" in prompt
    assert "assistant: hi" in prompt
    assert "preferences" in prompt


def test_build_summary_prompt_no_profile():
    prompt = ms._build_summary_prompt(None, ["user: test"])
    assert "user: test" in prompt
    assert "{}" in prompt


def test_build_summary_prompt_empty_conversations():
    prompt = ms._build_summary_prompt(None, [])
    assert "Instructions" in prompt


async def test_fetch_latest_profile_empty():
    """No profiles in DB returns None."""
    await memory_init()
    result = await ms._fetch_latest_profile()
    assert result is None


async def test_fetch_latest_profile_valid():
    """A valid profile dict is returned."""
    await memory_init()
    from services.memory_store import get_memory_pool

    profile = {"preferences": ["sports"], "topics": ["news"]}
    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO user_profiles (profile_json) VALUES (?)", (json.dumps(profile),))
        await db.commit()

    result = await ms._fetch_latest_profile()
    assert result is not None
    assert result["preferences"] == ["sports"]


async def test_fetch_latest_profile_malformed_json():
    """Malformed JSON returns None."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO user_profiles (profile_json) VALUES (?)", ("not json{",))
        await db.commit()

    result = await ms._fetch_latest_profile()
    assert result is None


async def test_fetch_latest_profile_legacy_list():
    """Legacy list-format profile is normalized to first dict item."""
    await memory_init()
    from services.memory_store import get_memory_pool

    profile_list = [{"preferences": ["x"]}, {"preferences": ["y"]}]
    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO user_profiles (profile_json) VALUES (?)", (json.dumps(profile_list),))
        await db.commit()

    result = await ms._fetch_latest_profile()
    assert result is not None
    assert result["preferences"] == ["x"]


async def test_fetch_latest_profile_non_dict():
    """Non-dict, non-list profile returns None."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO user_profiles (profile_json) VALUES (?)", ('"just a string"',))
        await db.commit()

    result = await ms._fetch_latest_profile()
    assert result is None


async def test_fetch_last_24h_conversations_empty():
    """No conversations returns empty list."""
    await memory_init()
    result = await ms._fetch_last_24h_conversations()
    assert result == []


async def test_fetch_last_24h_conversations():
    """Recent conversations are returned."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("user", "hello"))
        await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("assistant", "hi there"))
        await db.commit()

    result = await ms._fetch_last_24h_conversations()
    assert len(result) == 2
    assert "user: hello" in result
    assert "assistant: hi there" in result


async def test_run_daily_summarization_no_conversations():
    """With no conversations, summarization is skipped."""
    await memory_init()
    # Should return without error
    await ms.run_daily_summarization()


async def test_run_daily_summarization_llm_failure():
    """When LLM call fails, summarization returns without saving."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("user", "test"))
        await db.commit()

    with patch.object(ms, "LLMBridge") as MockBridge:
        instance = MockBridge.get_instance.return_value
        instance.complete = AsyncMock(side_effect=Exception("LLM down"))
        await ms.run_daily_summarization()


async def test_run_daily_summarization_unparseable_json():
    """When LLM returns unparseable JSON, no profile is saved."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("user", "test"))
        await db.commit()

    with patch.object(ms, "LLMBridge") as MockBridge:
        instance = MockBridge.get_instance.return_value
        instance.complete = AsyncMock(return_value="not json at all {{{")
        await ms.run_daily_summarization()

    # Verify no profile was saved
    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT COUNT(*) FROM user_profiles")).fetchone()
    assert row[0] == 0


async def test_run_daily_summarization_success():
    """Successful summarization saves a profile."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("user", "I like sports"))
        await db.commit()

    profile = {"preferences": ["sports"], "topics": ["news"], "patterns": [], "entities": []}
    with patch.object(ms, "LLMBridge") as MockBridge:
        instance = MockBridge.get_instance.return_value
        instance.complete = AsyncMock(return_value=json.dumps(profile))
        await ms.run_daily_summarization()

    async with get_memory_pool().acquire() as db:
        row = await (await db.execute("SELECT COUNT(*) FROM user_profiles")).fetchone()
    assert row[0] == 1


async def test_get_latest_user_profile_empty():
    """No profile returns empty string."""
    await memory_init()
    result = await ms.get_latest_user_profile()
    assert result == ""


async def test_get_latest_user_profile_returns_json():
    """Existing profile is returned as JSON string."""
    await memory_init()
    from services.memory_store import get_memory_pool

    profile = {"preferences": ["x"]}
    async with get_memory_pool().acquire() as db:
        await db.execute("INSERT INTO user_profiles (profile_json) VALUES (?)", (json.dumps(profile),))
        await db.commit()

    result = await ms.get_latest_user_profile()
    parsed = json.loads(result)
    assert parsed["preferences"] == ["x"]


async def test_run_daily_summarization_caps_conversations():
    """More than 15 conversations are capped to 15."""
    await memory_init()
    from services.memory_store import get_memory_pool

    async with get_memory_pool().acquire() as db:
        for i in range(20):
            await db.execute("INSERT INTO conversations (role, content) VALUES (?, ?)", ("user", f"msg {i}"))
        await db.commit()

    captured_prompt = []

    async def fake_complete(**kwargs):
        captured_prompt.append(kwargs.get("user_input", ""))
        return json.dumps({"preferences": [], "topics": [], "patterns": [], "entities": []})

    with patch.object(ms, "LLMBridge") as MockBridge:
        instance = MockBridge.get_instance.return_value
        instance.complete = fake_complete
        await ms.run_daily_summarization()

    # The prompt should contain at most 15 conversations
    assert len(captured_prompt) == 1
    # Count "msg" occurrences — should be capped
    prompt_text = captured_prompt[0]
    msg_count = prompt_text.count("msg ")
    assert msg_count <= 15


# ── 6. services/alert_history.py ───────────────────────────────────────────────


import services.alert_history as ah


@pytest.fixture(autouse=True)
def _patch_alert_pool(monkeypatch):
    """Patch alert_history._pool to use the temp alerts DB from conftest.

    The conftest's isolated_db fixture registers the temp alerts path but does
    not patch alert_history._pool (which was bound at import time to the real
    alerts.db). This fixture rebinds it to the temp pool.
    """
    from services.db_pool import get_pool

    pool = get_pool(db_type="alerts", max_connections=4)
    monkeypatch.setattr(ah, "_pool", pool)
    import services.alert_history_query as ahq

    monkeypatch.setattr(ahq, "_pool", pool)


async def test_init_db():
    """_init_db creates the alerts and audit_log tables."""
    await ah._init_db()
    from services.db_pool import get_db_path

    db_path = get_db_path("alerts")
    with sqlite3.connect(db_path) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "alerts" in tables
    assert "audit_log" in tables


async def test_save_alert():
    """save_alert inserts a row into the alerts table."""
    await ah._init_db()
    await ah.save_alert("test_trigger", "test report content")

    recent = await ah.get_recent_alerts(limit=5)
    assert len(recent) >= 1
    assert recent[0][1] == "test_trigger"
    assert recent[0][2] == "test report content"


async def test_save_alert_embedding_failure():
    """save_alert handles embedding failure gracefully (stores None)."""
    await ah._init_db()
    with patch.object(ah, "LLMBridge") as MockBridge:
        instance = MockBridge.get_instance.return_value
        instance.embed = AsyncMock(side_effect=Exception("embed failed"))
        await ah.save_alert("trigger_no_emb", "report no embedding")

    recent = await ah.get_recent_alerts(limit=5)
    found = [r for r in recent if r[1] == "trigger_no_emb"]
    assert len(found) == 1


async def test_get_recent_alerts_limit():
    """get_recent_alerts respects the limit parameter."""
    await ah._init_db()
    for i in range(5):
        await ah.save_alert(f"trigger_{i}", f"report_{i}")

    recent = await ah.get_recent_alerts(limit=3)
    assert len(recent) == 3


async def test_get_recent_alerts_empty():
    """get_recent_alerts on empty DB returns empty list."""
    await ah._init_db()
    recent = await ah.get_recent_alerts(limit=10)
    assert recent == []


async def test_async_save_audit_log():
    """async_save_audit_log inserts a row into audit_log."""
    await ah._init_db()
    await ah.async_save_audit_log("test_tool", '{"arg": 1}', '{"result": "ok"}', "127.0.0.1", 42)

    from services.db_pool import get_db_path

    db_path = get_db_path("alerts")
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT tool, args, result, client_ip, duration_ms FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert row[0] == "test_tool"
    assert row[3] == "127.0.0.1"
    assert row[4] == 42


async def test_get_latest_intel_alerts():
    """get_latest_intel_alerts returns recent alerts with ISO timestamps."""
    await ah._init_db()
    await ah.save_alert("intel_trigger", "intel report")

    alerts = await ah.get_latest_intel_alerts(limit=5)
    assert len(alerts) >= 1
    assert any(a["trigger"] == "intel_trigger" for a in alerts)


async def test_get_latest_intel_alerts_legacy_timestamp():
    """get_latest_intel_alerts handles legacy 'DD/MM HH:MM' timestamps."""
    await ah._init_db()
    # Insert a row with legacy timestamp format directly
    from services.db_pool import get_db_path

    db_path = get_db_path("alerts")
    now = datetime.now()
    legacy_ts = now.strftime("%d/%m %H:%M")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO alerts (ts, trigger, report) VALUES (?, ?, ?)", (legacy_ts, "legacy", "legacy report")
        )
        conn.commit()

    alerts = await ah.get_latest_intel_alerts(limit=5)
    found = [a for a in alerts if a["trigger"] == "legacy"]
    assert len(found) == 1


async def test_get_latest_intel_alerts_empty():
    """get_latest_intel_alerts on empty DB returns empty list."""
    await ah._init_db()
    alerts = await ah.get_latest_intel_alerts(limit=5)
    assert alerts == []


async def test_get_latest_system_metrics():
    """get_latest_system_metrics returns baseline rows with stats."""
    from services.metrics_db import _ensure_init as metrics_init

    await metrics_init()
    from services.metrics_db import get_metrics_pool

    async with get_metrics_pool().acquire() as db:
        await db.execute(
            "INSERT INTO system_baselines (metric, value, timestamp, hour) VALUES (?, ?, ?, ?)",
            ("cpu", 50.0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), datetime.now().hour),
        )
        await db.commit()

    metrics = await ah.get_latest_system_metrics()
    assert len(metrics) >= 1
    assert any(m["metric"] == "cpu" for m in metrics)


async def test_get_latest_intel_alerts_empty():
    """get_latest_intel_alerts on empty DB returns empty list."""
    await ah._init_db()
    alerts = await ah.get_latest_intel_alerts(limit=5)
    assert alerts == []


async def test_get_latest_system_metrics():
    """get_latest_system_metrics returns baseline rows with stats."""
    from services.metrics_db import _ensure_init as metrics_init

    await metrics_init()
    from services.metrics_db import get_metrics_pool

    async with get_metrics_pool().acquire() as db:
        await db.execute(
            "INSERT INTO system_baselines (metric, value, timestamp, hour) VALUES (?, ?, ?, ?)",
            ("cpu", 50.0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), datetime.now().hour),
        )
        await db.commit()

    metrics = await ah.get_latest_system_metrics()
    assert len(metrics) >= 1
    assert any(m["metric"] == "cpu" for m in metrics)


async def test_get_latest_intel_alerts_empty():
    """get_latest_intel_alerts on empty DB returns empty list."""
    await ah._init_db()
    alerts = await ah.get_latest_intel_alerts(limit=5)
    assert alerts == []


async def test_get_latest_system_metrics():
    """get_latest_system_metrics returns baseline rows with stats."""
    from services.metrics_db import _ensure_init as metrics_init

    await metrics_init()
    from services.metrics_db import get_metrics_pool

    async with get_metrics_pool().acquire() as db:
        await db.execute(
            "INSERT INTO system_baselines (metric, value, timestamp, hour) VALUES (?, ?, ?, ?)",
            ("cpu", 50.0, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), datetime.now().hour),
        )
        await db.commit()

    metrics = await ah.get_latest_system_metrics()
    assert len(metrics) >= 1
    assert any(m["metric"] == "cpu" for m in metrics)
