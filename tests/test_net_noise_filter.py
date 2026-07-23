# tests/test_net_noise_filter.py
"""Tests for the shared benign-connection suppression chain (net_noise_filter).

Covers: CDN/cloud CIDR whitelist (incl. Azure 13.64.0.0/11 regression),
line parsing, suppression chain ordering + fail-open, and the hunt-path
filter that keeps known-benign conns out of the LLM prompt.
"""

from unittest.mock import AsyncMock, patch

import pytest

from services.net_noise_filter import (
    apply_snapshot_noise_filter,
    filter_benign_conns,
    filter_benign_conns_tagged,
    is_cdn_whitelisted_ip,
    parse_conn_line,
    suppression_reason,
)

# ── CDN / cloud CIDR whitelist ──


def test_azure_13_range_whitelisted():
    """Regression: 13.69.x.x (Azure) flagged MALICIOUS in hunt report 2026-07-06."""
    assert is_cdn_whitelisted_ip("13.69.116.104") is True
    assert is_cdn_whitelisted_ip("13.69.239.69") is True


def test_azure_20_and_40_ranges_whitelisted():
    assert is_cdn_whitelisted_ip("20.190.1.1") is True
    assert is_cdn_whitelisted_ip("40.126.5.5") is True


def test_non_cloud_ip_not_whitelisted():
    assert is_cdn_whitelisted_ip("185.220.101.5") is False


def test_invalid_ip_not_whitelisted():
    assert is_cdn_whitelisted_ip("not-an-ip") is False
    assert is_cdn_whitelisted_ip("") is False


# ── parse_conn_line ──


def test_parse_conn_line_full_format():
    line = "13.69.116.104:443 (Microsoft Corporation / AS8075) (svchost.exe:1234)"
    assert parse_conn_line(line) == ("13.69.116.104", "svchost.exe", 443, 1234)


def test_parse_conn_line_no_parens_returns_none():
    assert parse_conn_line("13.69.116.104:443") is None
    assert parse_conn_line("") is None


def test_parse_conn_line_ipv6_bracketed():
    line = "[2603:1030::5]:443 (Microsoft / AS8075) (svchost.exe:99)"
    assert parse_conn_line(line) == ("2603:1030::5", "svchost.exe", 443, 99)


def test_parse_conn_line_no_pid_returns_none_pid():
    """Line without PID → pid=None."""
    line = "13.69.116.104:443 (Microsoft / AS8075) (svchost.exe)"
    result = parse_conn_line(line)
    assert result is not None
    assert result[3] is None  # pid is None


# ── suppression_reason chain ──


@pytest.mark.asyncio
async def test_suppression_cdn_first():
    reason = await suppression_reason("evil.exe", "13.69.116.104", 4444)
    assert reason == "cdn_whitelist"


@pytest.mark.asyncio
async def test_suppression_learned_baseline():
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=True),
    ):
        reason = await suppression_reason("myapp.exe", "185.220.101.5", 8443)
    assert reason == "learned_baseline"


@pytest.mark.asyncio
async def test_suppression_fail_open_on_db_error():
    """DB lookup failure must NOT suppress — alert survives (fail-open)."""
    with (
        patch(
            "services.net_noise_filter.is_known_combo",
            new_callable=AsyncMock,
            side_effect=Exception("db down"),
        ),
        patch(
            "services.net_noise_filter.is_intel_whitelisted",
            new_callable=AsyncMock,
            side_effect=Exception("db down"),
        ),
    ):
        reason = await suppression_reason("myapp.exe", "185.220.101.5", 8443)
    assert reason is None


@pytest.mark.asyncio
async def test_suppression_none_for_unknown_conn():
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        reason = await suppression_reason("evil.exe", "185.220.101.5", 4444)
    assert reason is None


# ── filter_benign_conns (hunt path) ──


@pytest.mark.asyncio
async def test_filter_suppresses_azure_telemetry():
    """The exact false-positive from the hunt report: svchost → Azure must vanish."""
    lines = [
        "13.69.116.104:443 (Microsoft Corporation / AS8075) (svchost.exe:1234)",
        "13.69.239.69:443 (Microsoft Corporation / AS8075) (svchost.exe:1234)",
    ]
    assert await filter_benign_conns(lines) == []


@pytest.mark.asyncio
async def test_filter_keeps_unknown_conns():
    lines = ["185.220.101.5:4444 (Some Org / AS666) (evil.exe:6666)"]
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        assert await filter_benign_conns(lines) == lines


@pytest.mark.asyncio
async def test_filter_keeps_unparseable_lines():
    """Malformed lines must NOT become an invisibility cloak."""
    lines = ["garbage with no address"]
    assert await filter_benign_conns(lines) == lines


@pytest.mark.asyncio
async def test_apply_snapshot_noise_filter_in_place():
    """Hunt entry point: snapshot['suspicious_net'] filtered in place."""
    snapshot = {
        "cpu": 10.0,
        "suspicious_net": ["13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"],
    }
    await apply_snapshot_noise_filter(snapshot)
    assert snapshot["suspicious_net"] == []
    assert snapshot["cpu"] == 10.0


@pytest.mark.asyncio
async def test_apply_snapshot_noise_filter_empty_net_noop():
    snapshot = {"suspicious_net": []}
    await apply_snapshot_noise_filter(snapshot)
    assert snapshot["suspicious_net"] == []


@pytest.mark.asyncio
async def test_filter_mixed_input():
    benign = "13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"
    threat = "185.220.101.5:4444 (Some Org / AS666) (evil.exe:6666)"
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        assert await filter_benign_conns([benign, threat]) == [threat]


# ── C1+C2: filtered_net tagging (no data deletion) ──────────────────


@pytest.mark.asyncio
async def test_apply_snapshot_creates_filtered_net_key():
    """C1+C2: suppressed connections must be preserved in filtered_net."""
    snapshot = {
        "suspicious_net": ["13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"],
    }
    await apply_snapshot_noise_filter(snapshot)
    assert snapshot["suspicious_net"] == []
    assert "filtered_net" in snapshot
    assert len(snapshot["filtered_net"]) == 1
    assert snapshot["filtered_net"][0]["reason"] == "cdn_whitelist"
    assert snapshot["filtered_net"][0]["ip"] == "13.69.116.104"


@pytest.mark.asyncio
async def test_filtered_net_contains_metadata():
    """filtered_net entries must include line, reason, ip, proc_name, port."""
    line = "13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"
    snapshot = {"suspicious_net": [line]}
    await apply_snapshot_noise_filter(snapshot)
    entry = snapshot["filtered_net"][0]
    assert entry["line"] == line
    assert entry["reason"] == "cdn_whitelist"
    assert entry["ip"] == "13.69.116.104"
    assert entry["proc_name"] == "svchost.exe"
    assert entry["port"] == 443


@pytest.mark.asyncio
async def test_filtered_net_empty_when_no_suppression():
    """No suppression → filtered_net is empty list (not missing)."""
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        snapshot = {"suspicious_net": ["185.220.101.5:4444 (Org / AS1) (evil.exe:1)"]}
        await apply_snapshot_noise_filter(snapshot)
    assert len(snapshot["suspicious_net"]) == 1
    assert snapshot["filtered_net"] == []


@pytest.mark.asyncio
async def test_filtered_net_preserves_mixed_conns():
    """Mixed input: threat survives, benign goes to filtered_net."""
    benign = "13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"
    threat = "185.220.101.5:4444 (Some Org / AS666) (evil.exe:6666)"
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        snapshot = {"suspicious_net": [benign, threat]}
        await apply_snapshot_noise_filter(snapshot)
    assert snapshot["suspicious_net"] == [threat]
    assert len(snapshot["filtered_net"]) == 1
    assert snapshot["filtered_net"][0]["ip"] == "13.69.116.104"


@pytest.mark.asyncio
async def test_filter_benign_conns_tagged_returns_tuple():
    """filter_benign_conns_tagged returns (survivors, suppressed) tuple."""
    benign = "13.69.116.104:443 (Microsoft / AS8075) (svchost.exe:1234)"
    with (
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        survivors, suppressed = await filter_benign_conns_tagged([benign])
    assert survivors == []
    assert len(suppressed) == 1
    assert suppressed[0]["reason"] == "cdn_whitelist"


@pytest.mark.asyncio
async def test_filtered_net_available_to_behavioral_escape_hatch():
    """C1+C2 integration: filtered_net counts as anomaly signal."""
    from services.behavioral_escape_hatch import count_behavioral_anomalies

    snapshot = {
        "suspicious_net": [],  # all filtered out
        "filtered_net": [{"ip": "13.69.116.104", "reason": "cdn_whitelist"}],
        "disk_alerts": [],
        "suspicious_procs": [],
    }
    alerts = [("ts", "cpu:cpu_spike", "r"), ("ts", "ram:ram_drop", "r")]
    # 3 anomalies: cpu_spike + ram_anomaly + filtered_net (cloud C2 suspect)
    count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
    assert count == 3 and has_behavioral


@pytest.mark.asyncio
async def test_empty_filtered_net_does_not_count_as_anomaly():
    """No filtered_net + no suspicious_net → no network anomaly signal."""
    from services.behavioral_escape_hatch import count_behavioral_anomalies

    snapshot = {
        "suspicious_net": [],
        "filtered_net": [],
        "disk_alerts": [],
        "suspicious_procs": [],
    }
    alerts = []
    count, has_behavioral = count_behavioral_anomalies(snapshot, alerts)
    assert count == 0 and not has_behavioral


# ── H1: Self-process PID verification ──────────────────────────────


@pytest.mark.asyncio
async def test_suppression_uses_pid_when_available():
    """H1: When PID is available, suppression_reason uses full is_self_process check."""
    with (
        patch("services.net_noise_filter.is_cdn_whitelisted_ip", return_value=False),
        patch("services.net_noise_filter.is_self_process_by_name", return_value=False),
        patch("services.net_noise_filter.is_expected_network_behavior", return_value=False),
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
    ):
        with patch("services.self_whitelist.is_self_process", return_value=True) as mock_self:
            reason = await suppression_reason("koboldcpp.exe", "1.2.3.4", 443, pid=9999)
    assert reason == "self_process"
    mock_self.assert_called_once_with(9999, "koboldcpp.exe")


@pytest.mark.asyncio
async def test_suppression_falls_back_to_name_when_pid_none():
    """H1: When PID is None, falls back to name-only check (backward compat)."""
    with (
        patch("services.net_noise_filter.is_cdn_whitelisted_ip", return_value=False),
        patch("services.net_noise_filter.is_self_process_by_name", return_value=True),
    ):
        reason = await suppression_reason("koboldcpp.exe", "1.2.3.4", 443, pid=None)
    assert reason == "self_process"


@pytest.mark.asyncio
async def test_suppression_pid_check_exception_fails_open():
    """H1: If is_self_process raises, falls back to name-only (fail-open)."""
    with (
        patch("services.net_noise_filter.is_cdn_whitelisted_ip", return_value=False),
        patch("services.net_noise_filter.is_self_process_by_name", return_value=True),
        patch("services.self_whitelist.is_self_process", side_effect=Exception("boom")),
    ):
        reason = await suppression_reason("proc.exe", "1.2.3.4", 443, pid=500)
    assert reason == "self_process"


@pytest.mark.asyncio
async def test_suppression_pid_zero_uses_name_only():
    """H1: PID=0 (kernel) → skip PID check, use name-only."""
    with (
        patch("services.net_noise_filter.is_cdn_whitelisted_ip", return_value=False),
        patch("services.net_noise_filter.is_self_process_by_name", return_value=True),
    ):
        reason = await suppression_reason("system", "1.2.3.4", 443, pid=0)
    assert reason == "self_process"


@pytest.mark.asyncio
async def test_filter_tagged_passes_pid_to_suppression():
    """H1: filter_benign_conns_tagged extracts PID and passes it through."""
    line = "1.2.3.4:443 (Org / AS1) (koboldcpp.exe:9999)"
    with (
        patch("services.net_noise_filter.is_cdn_whitelisted_ip", return_value=False),
        patch("services.net_noise_filter.is_self_process_by_name", return_value=False),
        patch("services.net_noise_filter.is_expected_network_behavior", return_value=False),
        patch("services.net_noise_filter.is_known_combo", new_callable=AsyncMock, return_value=False),
        patch("services.net_noise_filter.is_intel_whitelisted", new_callable=AsyncMock, return_value=False),
        patch("services.self_whitelist.is_self_process", return_value=True) as mock_self,
    ):
        await filter_benign_conns_tagged([line])
    mock_self.assert_called_once_with(9999, "koboldcpp.exe")


# ── H2: Baseline TTL (90-day recency window) ───────────────────────


@pytest.mark.asyncio
async def test_baseline_ttl_rejects_old_entries():
    """H2: Baseline entries older than 90 days are treated as unknown."""
    from services.net_baseline import _BASELINE_TTL_DAYS, is_known_combo

    assert _BASELINE_TTL_DAYS == 90

    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = None  # no recent row
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with patch("services.net_baseline.get_metrics_pool") as mock_pool:
        mock_pool.return_value.acquire.return_value = mock_acquire
        result = await is_known_combo("chrome.exe", "1.2.3.4", 443)

    assert result is False
    # M2: Verify the SQL includes the TTL filter using last_seen
    # First call is SELECT, second is DELETE (lazy eviction)
    select_sql = mock_db.execute.call_args_list[0][0][0]
    assert "last_seen > datetime" in select_sql
    assert "days" in select_sql
    # M2: Verify lazy eviction DELETE was called
    delete_sql = mock_db.execute.call_args_list[1][0][0]
    assert "DELETE FROM net_baselines" in delete_sql


@pytest.mark.asyncio
async def test_baseline_ttl_accepts_recent_entries():
    """H2: Recent baseline entries (within 90 days) are still valid."""
    from services.net_baseline import is_known_combo

    mock_cursor = AsyncMock()
    mock_cursor.fetchone.return_value = (1,)  # row found
    mock_db = AsyncMock()
    mock_db.execute.return_value = mock_cursor
    mock_acquire = AsyncMock()
    mock_acquire.__aenter__.return_value = mock_db
    mock_acquire.__aexit__.return_value = None

    with patch("services.net_baseline.get_metrics_pool") as mock_pool:
        mock_pool.return_value.acquire.return_value = mock_acquire
        result = await is_known_combo("chrome.exe", "1.2.3.4", 443)

    assert result is True
