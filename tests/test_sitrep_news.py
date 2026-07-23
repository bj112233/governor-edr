# tests/test_sitrep_news.py
"""Tests for SITREP news-only refactor (Block 7).

Verifies generate_sitrep receives news items (not alerts), builds a
news-intelligence prompt, skips when empty, and persists the LLM output.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.scheduled_news._delivery import DigestDelivery

_SAMPLE_ITEMS = {
    "cyber": [
        {
            "title": "APT38 תקף תשתיות אנרגיה באירופה",
            "source": "CyberScoop",
            "link": "https://example.com/apt38",
            "ai_summary": "קמפיין פעיל נגד SCADA — TTPs חדשים.",
            "sentiment": "negative",
        },
        {
            "title": "Microsoft פרסמה תיקון 0day",
            "source": "BleepingComputer",
            "link": "https://example.com/ms-patch",
            "ai_summary": "Patch Tuesday — 3 critical RCEs.",
            "sentiment": "neutral",
        },
    ],
    "world": [
        {
            "title": "פסגה בינלאומית לאבטחת סייבר",
            "source": "Reuters",
            "link": "https://example.com/summit",
            "ai_summary": "הסכם מסגרת חדש.",
            "sentiment": "positive",
        },
    ],
}


class _FakeBridge:
    """Captures the user_input so tests can assert prompt content."""

    def __init__(self, response: str = "# SITREP\nnews summary"):
        self._response = response
        self.captured_system: str = ""
        self.captured_user: str = ""

    async def complete(self, *, system_prompt, user_input, **kw):
        self.captured_system = system_prompt
        self.captured_user = user_input
        return self._response


@pytest.fixture
def fake_bridge():
    bridge = _FakeBridge()
    with patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge):
        yield bridge


@pytest.fixture
def delivery_no_telegram(tmp_path, monkeypatch):
    """DigestDelivery with no Telegram channel — file-only delivery."""
    monkeypatch.chdir(tmp_path)
    return DigestDelivery(telegram_channel=None, delivery_config={})


async def test_sitrep_uses_news_items_not_alerts(fake_bridge, delivery_no_telegram):
    """The LLM user_input must contain news titles, NOT alert triggers."""
    await delivery_no_telegram.generate_sitrep(_SAMPLE_ITEMS)
    assert "APT38" in fake_bridge.captured_user
    assert "Patch Tuesday" in fake_bridge.captured_user
    # Prompt must NOT pull alerts from DB (no cpu_spike/ram_spike triggers).
    assert "cpu_spike" not in fake_bridge.captured_user
    assert "ram_spike" not in fake_bridge.captured_user


async def test_sitrep_prompt_is_news_intelligence(fake_bridge, delivery_no_telegram):
    """System prompt must frame the task as news intelligence, not security alerts."""
    await delivery_no_telegram.generate_sitrep(_SAMPLE_ITEMS)
    assert "מודיעין חדשותי" in fake_bridge.captured_system
    assert "סנטימנט" in fake_bridge.captured_system
    # Old alert-prompt phrasing must be gone.
    assert "התראות האבטחה" not in fake_bridge.captured_system


async def test_sitrep_includes_sentiment_and_category(fake_bridge, delivery_no_telegram):
    await delivery_no_telegram.generate_sitrep(_SAMPLE_ITEMS)
    assert "cyber" in fake_bridge.captured_user
    assert "world" in fake_bridge.captured_user
    assert "negative" in fake_bridge.captured_user
    assert "positive" in fake_bridge.captured_user


async def test_sitrep_skips_when_no_items(fake_bridge, delivery_no_telegram):
    """Empty categorized dict → skip, no LLM call."""
    await delivery_no_telegram.generate_sitrep({})
    assert fake_bridge.captured_user == ""  # complete() never invoked


async def test_sitrep_skips_when_all_categories_empty(fake_bridge, delivery_no_telegram):
    await delivery_no_telegram.generate_sitrep({"cyber": [], "world": []})
    assert fake_bridge.captured_user == ""


async def test_sitrep_persists_file(fake_bridge, delivery_no_telegram):
    await delivery_no_telegram.generate_sitrep(_SAMPLE_ITEMS)
    files = list(Path("downloads/reports").glob("sitrep_*.md"))
    assert len(files) == 1
    assert files[0].read_text(encoding="utf-8").startswith("# SITREP")


async def test_sitrep_skips_on_empty_llm_response(delivery_no_telegram):
    """Empty/whitespace LLM output → no file written, no crash."""
    empty_bridge = _FakeBridge(response="   ")
    with patch("services.llm_bridge.LLMBridge.get_instance", return_value=empty_bridge):
        await delivery_no_telegram.generate_sitrep(_SAMPLE_ITEMS)
    files = list(Path("downloads/reports").glob("sitrep_*.md"))
    assert files == []


async def test_sitrep_truncates_large_input(fake_bridge, delivery_no_telegram):
    """Very large input block is truncated to 20000 chars."""
    big = {"cyber": [{"title": "x" * 500, "source": "s", "ai_summary": "y" * 500} for _ in range(200)]}
    await delivery_no_telegram.generate_sitrep(big)
    assert len(fake_bridge.captured_user) <= 20000 + len("\n...[truncated]")
    assert "[truncated]" in fake_bridge.captured_user
