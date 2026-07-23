# tests/test_render_threat_row.py
"""Unit tests for render_threat_row — covers all real alert metrics.

Verifies the unified parser path (severity, value, z, baseline) for
cpu_spike/ram_drop/disk_zscore and the tailored paths for
new_external_ip/new_heavy_process/process_cpu_spike.
"""

from services.telegram.handlers_render import render_threat_row

_HEADER = "🟠 התראת Sentinel [WARN]\n━━━━━━━━━━━━━━━━━━━━━━\n"


def _row(trigger, report, ts="2026-06-30 06:53:14"):
    return {"trigger": trigger, "report": report, "ts": ts}


def test_cpu_spike_extracts_severity_value_z_baseline():
    row = _row("cpu:cpu_spike", _HEADER + "קטגוריה: CPU\nמדד: cpu_spike\nערך נוכחי: 14.7%\nבסיס: μ=2.5, σ=2.0\n\nz=6.1")
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "🟠 מעבד" in joined
    assert "ערך: 14.7%" in joined
    assert "z=6.1" in joined
    assert "μ=2.5 σ=2.0" in joined


def test_ram_drop_shows_drop_explanation():
    row = _row("ram:ram_drop", _HEADER + "קטגוריה: RAM\nמדד: ram_drop\nערך נוכחי: 21.0%\nבסיס: μ=37.0, σ=2.0\n\nz=-8.0")
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "🟠 זיכרון" in joined
    assert "z=-8.0" in joined
    assert "צניחה" in joined


def test_new_external_ip_extracts_full_ip():
    row = _row("net:new_external_ip", _HEADER + "קטגוריה: NET\nמדד: new_external_ip\n\nחיבור חדש: 185.220.101.34")
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "185.220.101.34" in joined
    assert "🟠 רשת" in joined


def test_new_heavy_process_extracts_proc_and_cpu():
    row = _row(
        "proc:new_heavy_process", _HEADER + "קטגוריה: PROC\nמדד: new_heavy_process\n\nminer.exe (PID 666) — 85.3% CPU"
    )
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "miner.exe" in joined
    assert "85.3%" in joined


def test_critical_severity_uses_red_icon():
    crit = "🔴 התראת Sentinel [CRITICAL]\n━━━\nקטגוריה: PROC\nמדד: ttp_detected\n\nMITRE T1059.001"
    row = _row("proc:ttp_detected", crit)
    lines = render_threat_row(row)
    assert lines[0].startswith("🔴")


def test_disk_zscore_continuous_path():
    row = _row(
        "disk:disk_zscore", _HEADER + "קטגוריה: DISK\nמדד: disk_zscore\nערך נוכחי: 95.0%\nבסיס: μ=70.0, σ=5.0\n\nz=5.0"
    )
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "ערך: 95.0%" in joined
    assert "z=5.0" in joined


def test_process_cpu_spike_extracts_proc_name():
    row = _row(
        "proc:process_cpu_spike",
        _HEADER + "קטגוריה: PROC\nמדד: process_cpu_spike\n\nTiWorker.exe (PID 12840) — 16.7% CPU",
    )
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "TiWorker.exe" in joined


def test_unknown_metric_fallback_strips_separators():
    """Unknown metric without structured header → clean single-line, no ━━━."""
    row = _row("foo:bar_baz", "some raw text\n━━━━━━━━\nwith separators")
    lines = render_threat_row(row)
    joined = "\n".join(lines)
    assert "━" not in joined
    assert "some raw text" in joined


def test_empty_report_does_not_crash():
    row = _row("cpu:cpu_spike", "")
    lines = render_threat_row(row)
    assert isinstance(lines, list)
    assert lines[-1] == ""  # trailing blank line preserved
