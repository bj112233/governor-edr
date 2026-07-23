# tests/test_handlers_snapshot.py
"""Snapshot tests for handlers.py — golden record regression gate.

Captures exact output of cmd_skills and cmd_intel with mocked data.
Any refactor must preserve byte-identical output (this test must stay green).
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services._skills_engine.models import Skill
from services.telegram.handlers import cmd_intel, cmd_skills
from services.telegram.handlers_render import (
    build_skill_meta,
    render_skill_categories,
    render_threat_row,
)


# ── Mock Skill factory ──
def _make_skill(name: str, emoji: str, description: str, commands: list[str]) -> Skill:
    """Build a minimal Skill with command_override (bypasses content parsing)."""
    skill = MagicMock(spec=Skill)
    skill.name = name
    skill.emoji = emoji
    skill.description = description
    skill.command_override = commands
    skill.content = ""
    skill.path = Path(f"/fake/{name}")
    skill.metadata = {}
    skill.requires = None
    skill.install = None
    skill.arg_template = None
    skill.args_description = None
    skill.command_to_args_template = None
    return skill


# ── Canned skill registry ──
_MOCK_SKILLS = {
    "crypto-skill": _make_skill("crypto-skill", "🔐", "Cryptography tools", ["hash", "encrypt"]),
    "firewall-skill": _make_skill("firewall-skill", "🛡️", "Firewall management", ["block", "allow"]),
    "intel-skill": _make_skill("intel-skill", "🕵️", "Threat intelligence", ["lookup"]),
    "currency-skill": _make_skill("currency-skill", "💱", "Currency conversion", ["convert"]),
    "report-maker": _make_skill("report-maker", "📊", "Report generation", ["generate"]),
    "stocks-skill": _make_skill("stocks-skill", "📈", "Stock data", ["quote"]),
    "news-monitor": _make_skill("news-monitor", "📰", "News aggregation", ["fetch"]),
    "translator-skill": _make_skill("translator-skill", "🌐", "Translation", ["run"]),
    "web-scraper": _make_skill("web-scraper", "🕷️", "Web scraping", ["scrape"]),
    "file-analyst": _make_skill("file-analyst", "📄", "File analysis", ["ocr", "summarize"]),
    "geocode-skill": _make_skill("geocode-skill", "🗺️", "Geocoding", ["geocode"]),
    "weather-skill": _make_skill("weather-skill", "🌤️", "Weather data", ["forecast"]),
    "extra-skill": _make_skill("extra-skill", "🔧", "Uncategorized skill", ["run"]),
}


def _mock_engine():
    engine = MagicMock()
    engine._skills = _MOCK_SKILLS
    return engine


# ── Canned intel alerts ──
_MOCK_ALERTS = [
    {
        "ts": "2026-06-19 10:30:00",
        "trigger": "cpu:cpu_spike",
        "report": (
            "🟠 התראת Sentinel [WARN]\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "קטגוריה: CPU\nמדד: cpu_spike\nערך נוכחי: 92.5%\n"
            "בסיס: μ=45.0, σ=5.0\n\n"
            "CPU sustained spike: 92.5% (baseline μ=45.0, σ=5.0, z=9.5)"
        ),
    },
    {
        "ts": "2026-06-19 09:15:00",
        "trigger": "net:new_external_ip",
        "report": (
            "🟠 התראת Sentinel [WARN]\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "קטגוריה: NET\nמדד: new_external_ip\n\n"
            "חיבור חדש לכתובת חיצונית: 185.220.101.34"
        ),
    },
    {
        "ts": "2026-06-19 08:00:00",
        "trigger": "proc:new_heavy_process",
        "report": (
            "🟠 התראת Sentinel [WARN]\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "קטגוריה: PROC\nמדד: new_heavy_process\n\n"
            "תהליך חדש עם עומס גבוה: miner.exe (PID 666) — 85.3% CPU"
        ),
    },
    {
        "ts": "2026-06-19 07:45:00",
        "trigger": "disk:disk_zscore",
        "report": (
            "🟡 התראת Sentinel [SUSPICIOUS]\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "קטגוריה: DISK\nמדד: disk_zscore\nערך נוכחי: 95.0%\n"
            "בסיס: μ=70.0, σ=5.0\n\n"
            "Disk usage anomaly: C: 95% full (z=5.0)"
        ),
    },
    {
        "ts": "2026-06-19 06:30:00",
        "trigger": "ram:ram_drop",
        "report": (
            "🟠 התראת Sentinel [WARN]\n"
            "━━━━━━━━━━━━━━━━━━━━━━\n"
            "קטגוריה: RAM\nמדד: ram_drop\nערך נוכחי: 20.0%\n"
            "בסיס: μ=60.0, σ=5.0\n\n"
            "RAM sustained drop: 20.0% (baseline μ=60.0, σ=5.0, z=-8.0)"
        ),
    },
]


# ── Golden records (captured from pre-refactor code) ──
# These are set to None initially; first run captures them.
# To regenerate: delete the golden record files and re-run with --update-golden.
_GOLDEN_SKILLS = None
_GOLDEN_INTEL = None


def _capture_message_output():
    """Create a mock Message that captures all answer() calls."""
    message = MagicMock()
    message.from_user = MagicMock(id=12345, is_bot=False)
    message.chat = MagicMock(type="private", id=12345)
    captured = []

    async def _answer(text, **kwargs):
        captured.append(text)

    message.answer = _answer
    return message, captured


# ── Tests ──


@pytest.mark.asyncio
async def test_cmd_skills_snapshot():
    """Golden record: cmd_skills output must be byte-identical across refactors."""
    message, captured = _capture_message_output()

    with patch("services.telegram.handlers.get_skills_engine", return_value=_mock_engine()):
        await cmd_skills(message)

    output = "\n".join(captured)
    golden_path = Path(__file__).parent / "_golden_skills.txt"

    if _GOLDEN_SKILLS is not None:
        assert output == _GOLDEN_SKILLS, "cmd_skills output drifted from golden record"
    elif golden_path.exists():
        golden = golden_path.read_text(encoding="utf-8")
        assert output == golden, f"cmd_skills output drifted from golden record ({golden_path})"
    else:
        # First run — capture golden record
        golden_path.write_text(output, encoding="utf-8")
        pytest.skip(f"Golden record captured to {golden_path} — re-run to verify")


@pytest.mark.asyncio
async def test_cmd_intel_snapshot():
    """Golden record: cmd_intel output must be byte-identical across refactors."""
    message, captured = _capture_message_output()

    with patch("services.telegram.handlers_diag.get_latest_intel_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.return_value = _MOCK_ALERTS
        await cmd_intel(message)

    output = "\n".join(captured)
    golden_path = Path(__file__).parent / "_golden_intel.txt"

    if _GOLDEN_INTEL is not None:
        assert output == _GOLDEN_INTEL, "cmd_intel output drifted from golden record"
    elif golden_path.exists():
        golden = golden_path.read_text(encoding="utf-8")
        assert output == golden, f"cmd_intel output drifted from golden record ({golden_path})"
    else:
        golden_path.write_text(output, encoding="utf-8")
        pytest.skip(f"Golden record captured to {golden_path} — re-run to verify")


@pytest.mark.asyncio
async def test_cmd_intel_empty_alerts():
    """Edge case: no alerts → sector clear message."""
    message, captured = _capture_message_output()

    with patch("services.telegram.handlers_diag.get_latest_intel_alerts", new_callable=AsyncMock) as mock_alerts:
        mock_alerts.return_value = []
        await cmd_intel(message)

    assert len(captured) == 1
    assert "Sector Clear" in captured[0]
