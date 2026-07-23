# tests/test_misc_coverage.py
"""Coverage tests for misc service modules.

Covers uncovered functions/branches in:
- services/web_c2_data.py
- services/web_c2_routes.py
- services/system_intel.py
- services/sentinel_events.py
- services/threat_feeds.py
- services/llm_bridge/completion.py
- services/local_mcp_server.py
- services/_skills_engine/cli_builder.py
- services/intel_enricher.py
"""

import asyncio
import json
import time
from subprocess import CompletedProcess
from unittest.mock import AsyncMock, MagicMock, patch

# ── web_c2_data ─────────────────────────────────────────────────────────


class TestParseTriggerBranches:
    def test_disk_metric_with_value(self):
        from services.web_c2_data import parse_trigger

        cat, val = parse_trigger("disk:75.5%")
        assert cat == "disk"
        assert val == 75.5

    def test_continuous_no_value(self):
        from services.web_c2_data import parse_trigger

        cat, val = parse_trigger("cpu:spike")
        assert cat == "cpu"
        assert val is None

    def test_continuous_value_parse_error(self):
        from services.web_c2_data import parse_trigger

        # The % regex matches but float() fails on non-numeric — covered by
        # the ValueError branch when value is like "abc%"
        cat, val = parse_trigger("cpu:abc%")
        assert cat == "cpu"
        assert val is None

    def test_empty_string(self):
        from services.web_c2_data import parse_trigger

        cat, val = parse_trigger("")
        assert cat is None
        assert val is None

    def test_unknown_category(self):
        from services.web_c2_data import parse_trigger

        cat, val = parse_trigger("foo:bar")
        assert cat == "foo"
        assert val is None


class TestExtractReasonBranches:
    def test_only_header_lines_fallback(self):
        from services.web_c2_data import extract_reason

        # All lines are header prefixes → fallback to last len>=5 line
        report = "\U0001f7e0 warn\n\u05d4\u05ea\u05e8\u05d0\u05ea Sentinel"
        reason = extract_reason(report)
        assert reason  # fallback returns last long line

    def test_all_short_lines_returns_empty(self):
        from services.web_c2_data import extract_reason

        assert extract_reason("ab\ncd") == ""

    def test_strips_box_drawing_chars(self):
        from services.web_c2_data import extract_reason

        report = "\u2501\u2501\u2500\u2500real content here"
        reason = extract_reason(report)
        assert "real content here" in reason


class TestGetMetrics:
    async def test_metrics_query_failure_returns_empty(self):
        from services.web_c2_data import get_metrics

        with (
            patch("services.metrics_db._ensure_init", new_callable=AsyncMock),
            patch("services.metrics_db.get_metrics_pool", side_effect=Exception("boom")),
        ):
            rows = await get_metrics(limit=5)
        assert rows == []

    async def test_metrics_returns_rows(self):
        from services.web_c2_data import get_metrics

        mock_row = {
            "metric": "cpu",
            "value": 50.0,
            "mean": 40.0,
            "std": 5.0,
            "timestamp": "2024-01-01 00:00:00",
        }

        # Build async context manager chain for: pool.acquire() → db, db.execute() → cursor
        mock_cursor = MagicMock()
        mock_cursor.fetchall = AsyncMock(return_value=[mock_row])
        cursor_ctx = MagicMock()
        cursor_ctx.__aenter__ = AsyncMock(return_value=mock_cursor)
        cursor_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_db = MagicMock()
        mock_db.row_factory = None
        mock_db.execute = MagicMock(return_value=cursor_ctx)

        db_ctx = MagicMock()
        db_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        db_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_pool = MagicMock()
        mock_pool.acquire = MagicMock(return_value=db_ctx)

        with (
            patch("services.metrics_db._ensure_init", new_callable=AsyncMock),
            patch("services.metrics_db.get_metrics_pool", return_value=mock_pool),
        ):
            rows = await get_metrics(limit=5)
        assert len(rows) == 1
        assert rows[0]["metric"] == "cpu"
        assert rows[0]["z_score"] == 2.0  # (50-40)/5


class TestGetThreats:
    async def test_threats_query_failure_returns_empty(self):
        from services.web_c2_data import get_threats

        with patch("services.web_c2_data.aiosqlite.connect", side_effect=Exception("db error")):
            rows = await get_threats()
        assert rows == []

    async def test_threats_invalid_timestamp_skipped(self):
        from services.web_c2_data import get_threats

        mock_row = {"ts": "not-a-date", "trigger": "cpu:50%", "report": "test"}

        mock_cursor = MagicMock()
        mock_cursor.fetchall = AsyncMock(return_value=[mock_row])
        cursor_ctx = MagicMock()
        cursor_ctx.__aenter__ = AsyncMock(return_value=mock_cursor)
        cursor_ctx.__aexit__ = AsyncMock(return_value=None)

        # First db.execute is awaited (PRAGMA), second is async-with
        mock_db = MagicMock()
        mock_db.execute = MagicMock(side_effect=[AsyncMock(return_value=None), cursor_ctx])

        db_ctx = MagicMock()
        db_ctx.__aenter__ = AsyncMock(return_value=mock_db)
        db_ctx.__aexit__ = AsyncMock(return_value=None)

        mock_connect = MagicMock()
        mock_connect.return_value = db_ctx

        with patch("services.web_c2_data.aiosqlite.connect", mock_connect):
            rows = await get_threats()
        assert rows == []  # invalid timestamp skipped


class TestGetHealth:
    async def test_health_psutil_failure_status_error(self):
        from services.web_c2_data import get_health

        with (
            patch("psutil.cpu_percent", side_effect=Exception("psutil fail")),
            patch(
                "services.web_c2_data.get_gpu_vram_stats",
                new_callable=AsyncMock,
                return_value={"vram_status": "no_gpu"},
            ),
        ):
            data = await get_health()
        assert data["status"] == "error"

    async def test_health_telemetry_failure_ok(self):
        from services.web_c2_data import get_health

        mock_ram = MagicMock(percent=50.0, total=8 * 1024**3, available=4 * 1024**3)
        mock_disk = MagicMock(percent=60.0, free=100 * 1024**3)

        with (
            patch("psutil.cpu_percent", return_value=30.0),
            patch("psutil.virtual_memory", return_value=mock_ram),
            patch("psutil.disk_usage", return_value=mock_disk),
            patch(
                "services.web_c2_data.get_gpu_vram_stats",
                new_callable=AsyncMock,
                return_value={"vram_status": "no_gpu"},
            ),
            patch("services.telemetry.get_telemetry", side_effect=Exception("no telemetry")),
        ):
            data = await get_health()
        assert data["status"] == "ok"
        assert data["cpu"] == 30.0


class TestReadGpuCountersSync:
    def test_no_instances_returns_no_gpu(self):
        from services.web_c2_data import _read_gpu_counters_sync

        mock_result = CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("services.web_c2_data.subprocess.run", return_value=mock_result):
            result = _read_gpu_counters_sync()
        assert result["vram_status"] == "no_gpu"

    async def test_powershell_failure_offline(self):
        from services.web_c2_data import get_gpu_vram_stats

        mock_result = CompletedProcess(args=[], returncode=1, stdout="", stderr="err")
        with (
            patch("services.web_c2_data.subprocess.run", return_value=mock_result),
            patch("services.web_c2_data.os.name", "nt"),
        ):
            result = await get_gpu_vram_stats()
        assert result["vram_status"] == "offline"

    def test_parse_valid_counters(self):
        from services.web_c2_data import _read_gpu_counters_sync

        stdout = "luid_0x00000000_0x0000bc01_phys_0|4976402432\nluid_0x00000000_0x0000bc01_phys_0|7486988288\n"
        mock_result = CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")
        with patch("services.web_c2_data.subprocess.run", return_value=mock_result):
            result = _read_gpu_counters_sync()
        assert result["vram_status"] == "ok"
        assert result["used_gb"] > 0


# ── web_c2_routes ───────────────────────────────────────────────────────


def _make_aiohttp_request(query=None, remote="127.0.0.1"):
    """Build a mock aiohttp Request for route handler tests."""
    req = MagicMock()
    req.remote = remote
    req.query = query or {}
    return req


class TestApiMetrics:
    async def test_api_metrics_returns_json(self):
        from services.web_c2_routes import api_metrics

        with patch("services.web_c2_routes.get_metrics", new_callable=AsyncMock, return_value=[{"metric": "cpu"}]):
            resp = await api_metrics(_make_aiohttp_request())
        assert resp.status == 200
        data = json.loads(resp.text)
        assert data == [{"metric": "cpu"}]


class TestApiThreats:
    async def test_api_threats_no_since(self):
        from services.web_c2_routes import api_threats

        with patch("services.web_c2_routes.get_threats", new_callable=AsyncMock, return_value=[]) as mock_gt:
            resp = await api_threats(_make_aiohttp_request())
        assert resp.status == 200
        mock_gt.assert_called_once_with(limit=50, since_ts=None)

    async def test_api_threats_with_valid_since(self):
        from services.web_c2_routes import api_threats

        with patch("services.web_c2_routes.get_threats", new_callable=AsyncMock, return_value=[]) as mock_gt:
            resp = await api_threats(_make_aiohttp_request(query={"since": "1000.5"}))
        assert resp.status == 200
        mock_gt.assert_called_once_with(limit=100, since_ts=1000.5)

    async def test_api_threats_invalid_since_returns_400(self):
        from services.web_c2_routes import api_threats

        resp = await api_threats(_make_aiohttp_request(query={"since": "abc"}))
        assert resp.status == 400
        data = json.loads(resp.text)
        assert "error" in data


class TestApiHealth:
    async def test_api_health_returns_json(self):
        from services.web_c2_routes import api_health

        with patch("services.web_c2_routes.get_health", new_callable=AsyncMock, return_value={"status": "ok"}):
            resp = await api_health(_make_aiohttp_request())
        assert resp.status == 200
        data = json.loads(resp.text)
        assert data["status"] == "ok"


class TestApiEvents:
    async def test_api_events_streams_connected(self):
        """SSE endpoint sends initial 'connected' comment."""
        from services.web_c2_routes import api_events

        mock_queue = asyncio.Queue()
        req = _make_aiohttp_request()

        written_chunks: list[bytes] = []

        async def fake_write(data):
            written_chunks.append(data)
            # After 'connected' is written, raise to stop the infinite loop
            if b": connected" in data:
                raise asyncio.CancelledError()

        async def fake_subscribe(*a, **kw):
            return mock_queue

        with (
            patch("services.web_c2_routes.event_bus.subscribe", new_callable=AsyncMock, side_effect=fake_subscribe),
            patch("services.web_c2_routes.event_bus.unsubscribe", new_callable=AsyncMock),
        ):
            with patch("aiohttp.web.StreamResponse") as mock_resp_cls:
                mock_resp = MagicMock()
                mock_resp.prepare = AsyncMock(return_value=None)
                mock_resp.write = AsyncMock(side_effect=fake_write)
                mock_resp_cls.return_value = mock_resp
                # CancelledError is caught inside api_events, function returns normally
                result = await api_events(req)
        assert any(b": connected" in c for c in written_chunks)
        assert result is mock_resp


class TestIndexRoute:
    async def test_index_serves_html(self, tmp_path):
        from services.web_c2_routes import index

        # Create static/index.html under tmp_path
        static_dir = tmp_path / "static"
        static_dir.mkdir()
        (static_dir / "index.html").write_text("<html>dashboard</html>", encoding="utf-8")

        with patch("services.web_c2_routes.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.parent.parent = tmp_path  # real Path → / "static" works
            mock_path_cls.return_value = mock_path
            resp = await index(_make_aiohttp_request())
        assert resp.status == 200
        assert "dashboard" in resp.text

    async def test_index_html_not_found_fallback(self, tmp_path):
        from services.web_c2_routes import index

        # tmp_path has no static/index.html → FileNotFoundError → fallback body
        with patch("services.web_c2_routes.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.parent.parent = tmp_path
            mock_path_cls.return_value = mock_path
            resp = await index(_make_aiohttp_request())
        assert resp.status == 200
        assert "not found" in resp.text.lower()


# ── system_intel ────────────────────────────────────────────────────────


class TestGetEventLogRaw:
    async def test_successful_output(self):
        from services.system_intel import get_event_log_raw

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"Event 1\nEvent 2", b""))
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("services.system_intel.asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await get_event_log_raw(count=5)
        assert "Event 1" in result

    async def test_timeout_returns_message(self):
        from services.system_intel import get_event_log_raw

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError)
        mock_proc.kill = MagicMock()
        mock_proc.wait = AsyncMock()

        with patch("services.system_intel.asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await get_event_log_raw(count=5)
        assert "timed out" in result.lower()

    async def test_timeout_kill_processlookup(self):
        from services.system_intel import get_event_log_raw

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError)
        mock_proc.kill = MagicMock(side_effect=ProcessLookupError)
        mock_proc.wait = AsyncMock()

        with patch("services.system_intel.asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await get_event_log_raw(count=5)
        assert "timed out" in result.lower()

    async def test_empty_output_returns_message(self):
        from services.system_intel import get_event_log_raw

        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"  ", b""))

        with patch("services.system_intel.asyncio.create_subprocess_exec", AsyncMock(return_value=mock_proc)):
            result = await get_event_log_raw(count=5)
        assert "No security events" in result

    async def test_exception_returns_error_string(self):
        from services.system_intel import get_event_log_raw

        with patch("services.system_intel.asyncio.create_subprocess_exec", AsyncMock(side_effect=OSError("fail"))):
            result = await get_event_log_raw(count=5)
        assert "Error reading event log" in result


class TestGetProcessListRaw:
    def test_processes_with_cpu(self):
        from services.system_intel import get_process_list_raw

        mock_proc1 = MagicMock()
        mock_proc1.info = {
            "pid": 100,
            "name": "chrome.exe",
            "cpu_percent": 50.0,
            "memory_percent": 5.0,
            "username": "user",
        }
        mock_proc2 = MagicMock()
        mock_proc2.info = {
            "pid": 200,
            "name": "idle.exe",
            "cpu_percent": 0.0,
            "memory_percent": 1.0,
            "username": "user",
        }

        with (
            patch("services.system_intel.psutil.process_iter", return_value=[mock_proc1, mock_proc2]),
            patch("services.system_intel.psutil.cpu_count", return_value=4),
            patch("services.system_intel.time.sleep"),
        ):
            result = get_process_list_raw()
        assert "chrome.exe" in result

    def test_no_processes_found(self):
        from services.system_intel import get_process_list_raw

        with (
            patch("services.system_intel.psutil.process_iter", return_value=[]),
            patch("services.system_intel.psutil.cpu_count", return_value=4),
            patch("services.system_intel.time.sleep"),
        ):
            result = get_process_list_raw()
        # Header line is always present; no process lines added
        assert "תהליכים" in result


class TestGetServicesRaw:
    def test_running_and_stopped(self):
        from services.system_intel import get_services_raw

        svc1 = MagicMock()
        svc1.as_dict.return_value = {"name": "Svc1", "display_name": "Service One", "status": "running"}
        svc2 = MagicMock()
        svc2.as_dict.return_value = {"name": "Svc2", "display_name": "Service Two", "status": "stopped"}

        with patch("services.system_intel.psutil.win_service_iter", return_value=[svc1, svc2]):
            result = get_services_raw()
        assert "Svc1" in result
        assert "Svc2" in result

    def test_no_services_found(self):
        from services.system_intel import get_services_raw

        with patch("services.system_intel.psutil.win_service_iter", return_value=[]):
            result = get_services_raw()
        assert "No services" in result

    def test_exception_returns_error(self):
        from services.system_intel import get_services_raw

        with patch("services.system_intel.psutil.win_service_iter", side_effect=Exception("fail")):
            result = get_services_raw()
        assert "Error gathering services" in result

    def test_svc_dict_exception_skipped(self):
        from services.system_intel import get_services_raw

        svc1 = MagicMock()
        svc1.as_dict.side_effect = Exception("boom")
        svc2 = MagicMock()
        svc2.as_dict.return_value = {"name": "Ok", "display_name": "OK", "status": "running"}

        with patch("services.system_intel.psutil.win_service_iter", return_value=[svc1, svc2]):
            result = get_services_raw()
        assert "Ok" in result


# ── sentinel_events ─────────────────────────────────────────────────────


class TestSentinelEventBus:
    async def test_emit_and_get_pending(self):
        from services.sentinel_events import SentinelEvent, SentinelEventBus

        bus = SentinelEventBus(max_size=10)
        event = SentinelEvent(event_type="alert", priority="high", data={"k": "v"})
        await bus.emit(event)
        pending = bus.get_pending_events()
        assert len(pending) == 1
        assert pending[0]["event_type"] == "alert"

    async def test_clear_queue(self):
        from services.sentinel_events import SentinelEvent, SentinelEventBus

        bus = SentinelEventBus(max_size=10)
        await bus.emit(SentinelEvent(event_type="alert", priority="normal", data={}))
        count = bus.clear_queue()
        assert count == 1
        assert bus.get_pending_events() == []

    async def test_subscribe_and_unsubscribe(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        q = await bus.subscribe()
        assert q in bus._subscribers
        await bus.unsubscribe(q)
        assert q not in bus._subscribers

    async def test_emit_alert_with_empty_analysis_uses_trigger(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_alert(
            {"alert_needed": True},
            analysis="",
            remediation={"category": "net", "metric": "new_ip"},
        )
        assert event.priority == "high"
        assert "net:new_ip" in event.data["analysis"]

    async def test_emit_alert_with_empty_analysis_no_remediation(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_alert({"trigger": "my_trigger", "alert_needed": False}, analysis=None)
        assert event.priority == "normal"
        assert event.data["analysis"] == "my_trigger"

    async def test_emit_critical_override(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_critical_override({"cpu": 90, "mem": 80})
        assert event.event_type == "critical_override"
        assert event.priority == "critical"

    async def test_emit_daily_digest(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_daily_digest("report", "analysis")
        assert event.event_type == "daily_digest"

    async def test_emit_weekly_reflection(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_weekly_reflection("reflection")
        assert event.event_type == "weekly_reflection"

    async def test_emit_threat_hunt_critical(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_threat_hunt({}, "analysis", 0.9)
        assert event.priority == "critical"

    async def test_emit_threat_hunt_high(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_threat_hunt({}, "analysis", 0.5)
        assert event.priority == "high"

    async def test_emit_dag_update(self):
        from services.sentinel_events import SentinelEventBus

        bus = SentinelEventBus()
        event = await bus.emit_dag_update("sess1", [{"id": 1}], {"task_id": 1})
        assert event.event_type == "dag_update"
        assert event.data["session_id"] == "sess1"

    async def test_subscriber_queue_full_evicts_oldest(self):
        from services.sentinel_events import SentinelEvent, SentinelEventBus

        bus = SentinelEventBus()
        q = asyncio.Queue(maxsize=1)
        bus._subscribers.append(q)
        await q.put(SentinelEvent("a", "low", {}))
        # Second emit should evict oldest
        await bus.emit(SentinelEvent("b", "low", {}))
        assert q.qsize() == 1


class TestAlertQueue:
    async def test_put_alert_snapshot_full_evicts(self):
        from services.sentinel_events import _alert_analysis_queue, put_alert_snapshot

        # Clear and set maxsize=1 for deterministic test
        original_maxsize = _alert_analysis_queue._maxsize
        while not _alert_analysis_queue.empty():
            _alert_analysis_queue.get_nowait()
        _alert_analysis_queue._maxsize = 1
        await put_alert_snapshot({"id": 1})
        # Queue full → evict + put
        await put_alert_snapshot({"id": 2})
        assert _alert_analysis_queue.qsize() == 1
        # Restore maxsize
        _alert_analysis_queue._maxsize = original_maxsize

    def test_get_alert_queue(self):
        from services.sentinel_events import get_alert_queue

        q = get_alert_queue()
        assert hasattr(q, "put_nowait")


# ── threat_feeds ────────────────────────────────────────────────────────


class TestCacheHelpers:
    def test_cache_get_missing_file(self, tmp_path, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_CACHE_DIR", tmp_path)
        assert threat_feeds._cache_get("src", "key") is None

    def test_cache_get_expired(self, tmp_path, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_CACHE_DIR", tmp_path)
        fpath = tmp_path / "src_key.json"
        fpath.write_text(json.dumps({"_ts": 0.0, "value": {"x": 1}}), encoding="utf-8")
        assert threat_feeds._cache_get("src", "key") is None

    def test_cache_get_valid(self, tmp_path, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_CACHE_DIR", tmp_path)
        fpath = tmp_path / "src_key.json"
        fpath.write_text(json.dumps({"_ts": time.time(), "value": {"x": 1}}), encoding="utf-8")
        assert threat_feeds._cache_get("src", "key") == {"x": 1}

    def test_cache_set_writes_file(self, tmp_path, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_CACHE_DIR", tmp_path)
        threat_feeds._cache_set("src", "key", {"x": 1})
        fpath = tmp_path / "src_key.json"
        assert fpath.exists()


class TestFetchUrlhaus:
    def test_cached_data_returned(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: {"rows": [{"url": "cached"}]})
        rows = threat_feeds._fetch_urlhaus_sync(limit=10)
        assert rows == [{"url": "cached"}]

    def test_network_failure_returns_empty(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: None)
        with patch("services.threat_feeds.requests.get", side_effect=Exception("net")):
            rows = threat_feeds._fetch_urlhaus_sync()
        assert rows == []

    def test_empty_response_returns_empty(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: None)
        mock_resp = MagicMock()
        mock_resp.text = ""
        mock_resp.raise_for_status = MagicMock()
        with patch("services.threat_feeds.requests.get", return_value=mock_resp):
            rows = threat_feeds._fetch_urlhaus_sync()
        assert rows == []


class TestFetchThreatfox:
    def test_cached_data_returned(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: {"iocs": [{"ioc": "x"}]})
        rows = threat_feeds._fetch_threatfox_sync(days=1)
        assert rows == [{"ioc": "x"}]

    def test_network_failure_returns_empty(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: None)
        with patch("services.threat_feeds.requests.post", side_effect=Exception("net")):
            rows = threat_feeds._fetch_threatfox_sync()
        assert rows == []

    def test_bad_query_status_returns_empty(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"query_status": "error", "data": []}
        mock_resp.raise_for_status = MagicMock()
        with patch("services.threat_feeds.requests.post", return_value=mock_resp):
            rows = threat_feeds._fetch_threatfox_sync()
        assert rows == []

    def test_filters_low_confidence(self, monkeypatch):
        from services import threat_feeds

        monkeypatch.setattr(threat_feeds, "_cache_get", lambda s, k: None)
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [
                {"ioc": "1.2.3.4", "confidence_level": 80},
                {"ioc": "5.6.7.8", "confidence_level": 10},
            ],
        }
        mock_resp.raise_for_status = MagicMock()
        with patch("services.threat_feeds.requests.post", return_value=mock_resp):
            with patch("services.threat_feeds._cache_set"):
                rows = threat_feeds._fetch_threatfox_sync()
        assert len(rows) == 1
        assert rows[0]["ioc"] == "1.2.3.4"


# ── llm_bridge/completion ───────────────────────────────────────────────


class TestFetchKoboldcppPerf:
    async def test_success_returns_dict(self):
        from services.llm_bridge.completion import _fetch_koboldcpp_perf

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "last_process_time": 10.0,
            "last_eval_time": 5.0,
            "last_input_count": 100,
            "last_token_count": 50,
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        with patch("services.llm_bridge.bridge._custom_http_client", mock_client):
            result = await _fetch_koboldcpp_perf()
        assert result["prefill_time"] == 10.0
        assert result["decode_time"] == 5.0

    async def test_non_200_returns_none(self):
        from services.llm_bridge.completion import _fetch_koboldcpp_perf

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        with patch("services.llm_bridge.bridge._custom_http_client", mock_client):
            result = await _fetch_koboldcpp_perf()
        assert result is None

    async def test_exception_returns_none(self):
        from services.llm_bridge.completion import _fetch_koboldcpp_perf

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("boom"))
        with patch("services.llm_bridge.bridge._custom_http_client", mock_client):
            result = await _fetch_koboldcpp_perf()
        assert result is None


class TestClientAcceptsExtraBody:
    def test_accepts_extra_body(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()
        client.chat.completions.create.__signature__ = None

        # inspect.signature on a MagicMock returns params including extra_body? No.
        # Use a real function with extra_body param.
        def fake_create(*, extra_body=None, **kw):  # noqa: ARG001
            del extra_body  # referenced by _client_accepts_extra_body via signature
            return None

        client.chat.completions.create = fake_create
        assert _client_accepts_extra_body(client) is True

    def test_rejects_extra_body(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()

        def fake_create(*, model, messages, **kw):  # noqa: ARG001
            return None

        client.chat.completions.create = fake_create
        assert _client_accepts_extra_body(client) is False

    def test_exception_returns_false(self):
        from services.llm_bridge.completion import _client_accepts_extra_body

        client = MagicMock()
        client.chat.completions.create = MagicMock(side_effect=Exception("x"))
        # inspect.signature raises? No, it works on MagicMock. Force it:
        with patch("services.llm_bridge.completion.inspect.signature", side_effect=Exception("boom")):
            assert _client_accepts_extra_body(client) is False


# ── local_mcp_server ────────────────────────────────────────────────────


class TestMcpHealthEndpoint:
    def test_health_with_valid_token(self):
        from fastapi.testclient import TestClient

        from services.local_mcp_server import app

        with patch("services.local_mcp_server.MCP_AUTH_TOKEN", "test-token"):
            client = TestClient(app)
            resp = client.get("/mcp/health", headers={"Authorization": "Bearer test-token"})
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}

    def test_health_no_token_configured(self):
        from fastapi.testclient import TestClient

        from services.local_mcp_server import app

        with patch("services.local_mcp_server.MCP_AUTH_TOKEN", ""):
            client = TestClient(app)
            resp = client.get("/mcp/health", headers={"Authorization": "Bearer x"})
            assert resp.status_code == 503


class TestMcpToolsEndpoint:
    def test_list_tools_with_auth(self):
        from fastapi.testclient import TestClient

        from services.local_mcp_server import app

        with patch("services.local_mcp_server.MCP_AUTH_TOKEN", "test-token"):
            client = TestClient(app)
            resp = client.get("/mcp/tools", headers={"Authorization": "Bearer test-token"})
            assert resp.status_code == 200
            assert "tools" in resp.json()


class TestMcpCallEndpoint:
    def test_call_tool_not_found(self):
        from fastapi.testclient import TestClient

        from services.local_mcp_server import app

        with (
            patch("services.local_mcp_server.MCP_AUTH_TOKEN", "test-token"),
            patch("services.local_mcp_server.async_save_audit_log", new_callable=AsyncMock),
        ):
            client = TestClient(app)
            resp = client.post(
                "/mcp/call",
                json={"tool": "nonexistent_tool", "arguments": {}},
                headers={"Authorization": "Bearer test-token"},
            )
            # HTTPException is caught by except Exception → 200 with error payload
            assert resp.status_code == 200
            assert "error" in resp.json().get("result", {})

    def test_call_tool_rate_limited(self):
        from fastapi.testclient import TestClient

        from services import local_mcp_server as mcp
        from services.local_mcp_server import app

        mcp._mcp_rate_store.clear()
        with (
            patch("services.local_mcp_server.MCP_AUTH_TOKEN", "test-token"),
            patch("services.local_mcp_server._check_mcp_rate_limit", return_value=False),
            patch("services.local_mcp_server.async_save_audit_log", new_callable=AsyncMock),
        ):
            client = TestClient(app)
            resp = client.post(
                "/mcp/call",
                json={"tool": "system", "arguments": {}},
                headers={"Authorization": "Bearer test-token"},
            )
            assert resp.status_code == 429
        mcp._mcp_rate_store.clear()


# ── cli_builder ─────────────────────────────────────────────────────────


def _make_skill(command_to_args_template=None):
    """Build a minimal Skill-like object for cli_builder tests."""
    skill = MagicMock()
    skill.command_to_args_template = command_to_args_template
    skill.name = "test-skill"
    return skill


class TestParseArgs:
    def test_dict_input(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), {"key": "val"})
        assert args == ""
        assert d == {"key": "val"}

    def test_quoted_json_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), '{"key": "val"}')
        assert args == ""
        assert d == {"key": "val"}

    def test_json_array_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), '["a", "b"]')
        assert args == ""
        assert d == {"args": ["a", "b"]}

    def test_plain_path_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), "C:\\files\\doc.pdf")
        assert args == ""
        assert d == {"path": "C:\\files\\doc.pdf"}

    def test_cli_flags_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), "--output report.txt --verbose")
        assert args == ""
        assert d["output"] == "report.txt"
        assert d["verbose"] is True

    def test_leading_double_dash(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), "--flag value")
        assert args == ""
        assert d == {"flag": "value"}

    def test_invalid_json_keeps_raw_args(self):
        from services._skills_engine.cli_builder import parse_args

        # Starts with { but invalid JSON → json.loads fails, args kept as-is
        args, d = parse_args(_make_skill(), "{invalid")
        assert args == "{invalid"
        assert d is None

    def test_non_str_non_dict_input(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), 123)
        assert args == "123"
        assert d is None

    def test_single_quoted_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), "'some text'")
        assert d == {"path": "some text"}

    def test_empty_string(self):
        from services._skills_engine.cli_builder import parse_args

        args, d = parse_args(_make_skill(), "")
        assert args == ""
        assert d is None


class TestApplyTemplate:
    def test_no_template_returns_args(self):
        from services._skills_engine.cli_builder import apply_template

        skill = _make_skill(command_to_args_template=None)
        assert apply_template(skill, "cmd", "orig") == "orig"

    def test_empty_args_uses_template(self):
        from services._skills_engine.cli_builder import apply_template

        skill = _make_skill(command_to_args_template='{"mode": "auto"}')
        result = apply_template(skill, "run", "")
        assert result == '{"mode": "auto"}'

    def test_merges_template_defaults(self):
        from services._skills_engine.cli_builder import apply_template

        skill = _make_skill(command_to_args_template='{"mode": "auto", "verbose": true}')
        result = apply_template(skill, "run", '{"verbose": false}')
        d = json.loads(result)
        assert d["verbose"] is False  # user override
        assert d["mode"] == "auto"  # from template

    def test_no_merge_when_all_keys_present(self):
        from services._skills_engine.cli_builder import apply_template

        skill = _make_skill(command_to_args_template='{"mode": "auto"}')
        result = apply_template(skill, "run", '{"mode": "manual"}')
        assert json.loads(result) == {"mode": "manual"}

    def test_invalid_json_no_merge(self):
        from services._skills_engine.cli_builder import apply_template

        skill = _make_skill(command_to_args_template='{"mode": "auto"}')
        result = apply_template(skill, "run", "not-json")
        assert result == "not-json"


class TestSanitizeArgs:
    def test_drops_leading_py_script(self):
        from services._skills_engine.cli_builder import sanitize_args

        assert sanitize_args("script.py --flag value") == ["--flag", "value"]

    def test_normal_args(self):
        from services._skills_engine.cli_builder import sanitize_args

        assert sanitize_args("--output report.txt") == ["--output", "report.txt"]

    def test_shlex_error_falls_back(self):
        from services._skills_engine.cli_builder import sanitize_args

        with patch("services._skills_engine.cli_builder.shlex.split", side_effect=ValueError("no closing quote")):
            result = sanitize_args("--path value")
        assert isinstance(result, list)
        assert "--path" in result


class TestDictToCliFlags:
    def test_bool_true(self):
        from services._skills_engine.cli_builder import dict_to_cli_flags

        assert dict_to_cli_flags({"verbose": True}) == ["--verbose"]

    def test_bool_false_omitted(self):
        from services._skills_engine.cli_builder import dict_to_cli_flags

        assert dict_to_cli_flags({"verbose": False}) == []

    def test_list_value(self):
        from services._skills_engine.cli_builder import dict_to_cli_flags

        flags = dict_to_cli_flags({"items": [1, 2]})
        assert flags == ["--items", "[1, 2]"]

    def test_string_value(self):
        from services._skills_engine.cli_builder import dict_to_cli_flags

        assert dict_to_cli_flags({"name": "test"}) == ["--name", "test"]


class TestSafeSplitArgs:
    def test_simple_split(self):
        from services._skills_engine.cli_builder import safe_split_args

        assert safe_split_args("a b c") == ["a", "b", "c"]

    def test_quoted_spaces(self):
        from services._skills_engine.cli_builder import safe_split_args

        assert safe_split_args('"a b" c') == ["a b", "c"]

    def test_single_quotes(self):
        from services._skills_engine.cli_builder import safe_split_args

        assert safe_split_args("'x y' z") == ["x y", "z"]


# ── intel_enricher ──────────────────────────────────────────────────────


class TestIsValidDomain:
    def test_valid_domain(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("example.com") is True

    def test_subdomain(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("sub.example.com") is True

    def test_version_number_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("9.2") is False

    def test_empty_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("") is False

    def test_too_long_rejected(self):
        from services.intel_enricher import _is_valid_domain

        assert _is_valid_domain("a" * 300) is False


class TestIsTrustedIsp:
    def test_microsoft(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({"isp": "Microsoft Corporation"}) is True

    def test_unknown(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({"isp": "EvoloNet"}) is False

    def test_empty(self):
        from services.intel_enricher import _is_trusted_isp

        assert _is_trusted_isp({"isp": ""}) is False


class TestIsCleanEnrichment:
    def test_score_zero_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 0}) is True

    def test_feed_hit_never_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 0, "threat_feeds": {"matched": True}}) is False

    def test_trusted_isp_override(self):
        from services.intel_enricher import is_clean_enrichment

        data = {
            "score": 30,
            "abuse": {"isp": "Microsoft Corporation"},
            "virustotal": {"available": True, "found": True, "malicious": 0},
        }
        assert is_clean_enrichment(data) is True

    def test_trusted_isp_with_vt_malicious_not_clean(self):
        from services.intel_enricher import is_clean_enrichment

        data = {
            "score": 30,
            "abuse": {"isp": "Google LLC"},
            "virustotal": {"available": True, "found": True, "malicious": 5},
        }
        assert is_clean_enrichment(data) is False

    def test_high_score_not_clean(self):
        from services.intel_enricher import is_clean_enrichment

        assert is_clean_enrichment({"score": 80}) is False


class TestEnrichDomain:
    async def test_invalid_domain_returns_none(self):
        from services.intel_enricher import enrich_domain

        result = await enrich_domain("9.2")
        assert result is None

    async def test_empty_domain_returns_none(self):
        from services.intel_enricher import enrich_domain

        result = await enrich_domain("")
        assert result is None

    async def test_timeout_returns_none(self):
        from services.intel_enricher import enrich_domain

        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_domain_sync", return_value={"score": 40}),
            patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock, side_effect=TimeoutError),
        ):
            result = await enrich_domain("example.com")
        assert result is None

    async def test_lookup_returns_none(self):
        from services.intel_enricher import enrich_domain

        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_domain_sync", return_value=None),
            patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock),
        ):
            result = await enrich_domain("example.com")
        assert result is None

    async def test_exception_returns_none(self):
        from services.intel_enricher import enrich_domain

        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_domain_sync", side_effect=Exception("boom")),
        ):
            result = await enrich_domain("example.com")
        assert result is None


class TestEnrichHash:
    async def test_empty_hash_returns_none(self):
        from services.intel_enricher import enrich_hash

        result = await enrich_hash("")
        assert result is None

    async def test_timeout_returns_none(self):
        from services.intel_enricher import enrich_hash

        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_hash_sync", return_value={"score": 40}),
            patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock, side_effect=TimeoutError),
        ):
            result = await enrich_hash("abc123def456")
        assert result is None

    async def test_successful_enrichment(self):
        from services.intel_enricher import enrich_hash

        base_data = {"score": 40, "virustotal": {"malicious": 0}, "maltiverse": {}}
        feed_hit = {"matched": True, "threatfox": True, "urlhaus": False, "malware": "Emotet"}
        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_hash_sync", return_value=base_data),
            patch("services.intel_enricher.check_target_in_feeds", new_callable=AsyncMock, return_value=feed_hit),
        ):
            result = await enrich_hash("abc123def456")
        assert result is not None
        assert result["score"] == 60  # 40 + 20
        assert result["threat_feeds"]["malware"] == "Emotet"

    async def test_exception_returns_none(self):
        from services.intel_enricher import enrich_hash

        with (
            patch("services.intel_enricher._virustotal", MagicMock()),
            patch("services.intel_enricher._lookup_hash_sync", side_effect=Exception("boom")),
        ):
            result = await enrich_hash("abc123def456")
        assert result is None


class TestLookupSync:
    def test_no_abuseipdb_returns_none(self):
        from services.intel_enricher import _lookup_sync

        with patch("services.intel_enricher._abuseipdb", None):
            assert _lookup_sync("1.2.3.4") is None

    def test_exception_returns_none(self):
        from services.intel_enricher import _lookup_sync

        with patch("services.intel_enricher._abuseipdb", MagicMock(side_effect=Exception("boom"))):
            assert _lookup_sync("1.2.3.4") is None


class TestLookupDomainSync:
    def test_no_virustotal_returns_none(self):
        from services.intel_enricher import _lookup_domain_sync

        with patch("services.intel_enricher._virustotal", None):
            assert _lookup_domain_sync("example.com") is None


class TestLookupHashSync:
    def test_no_virustotal_returns_none(self):
        from services.intel_enricher import _lookup_hash_sync

        with patch("services.intel_enricher._virustotal", None):
            assert _lookup_hash_sync("abc123") is None
