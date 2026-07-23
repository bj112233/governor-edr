# tests/test_cti_sitrep.py
"""Tests for Daily CTI SITREP — 08:30 batch job.

Verifies:
- RSS fetch + keyword filtering → top 5 items
- LLM prompt enforces pure English output
- SITREP saved as .md + sent to Telegram
- Graceful degradation: no items → skip, LLM failure → skip
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.cti_sitrep import (
    _CTI_PROMPT,
    _build_cti_block,
    _fetch_cti_items,
    _filter_by_keywords,
    run_cti_sitrep,
)

_SAMPLE_ITEMS = [
    {
        "title": "Critical CVE-2026-1234 in Apache",
        "source": "BleepingComputer",
        "summary": "RCE exploit",
        "link": "https://example.com/1",
    },
    {
        "title": "New APT campaign targets finance",
        "source": "The Hacker News",
        "summary": "APT29 phishing",
        "link": "https://example.com/2",
    },
    {"title": "Weather report for today", "source": "Random", "summary": "Sunny", "link": "https://example.com/3"},
]


# ── _filter_by_keywords ──


def test_filter_keeps_cyber_items():
    keywords = ["cve", "apt", "exploit", "ransomware"]
    filtered = _filter_by_keywords(_SAMPLE_ITEMS, keywords)
    titles = [item["title"] for item in filtered]
    assert "Critical CVE-2026-1234 in Apache" in titles
    assert "New APT campaign targets finance" in titles
    assert "Weather report for today" not in titles


def test_filter_empty_keywords_returns_all():
    filtered = _filter_by_keywords(_SAMPLE_ITEMS, [])
    assert len(filtered) == 3


def test_filter_case_insensitive():
    items = [{"title": "RANSOMWARE attack", "summary": ""}]
    filtered = _filter_by_keywords(items, ["ransomware"])
    assert len(filtered) == 1


# ── _build_cti_block ──


def test_build_block_includes_title_and_source():
    block = _build_cti_block(_SAMPLE_ITEMS[:1])
    assert "Critical CVE-2026-1234" in block
    assert "BleepingComputer" in block


def test_build_block_empty_items():
    assert _build_cti_block([]) == ""


# ── _fetch_cti_items ──


async def test_fetch_cti_items_filters_and_limits():
    raw_items = [
        {"title": "CVE-2026 critical", "source": "BC", "summary": "exploit", "link": ""},
        {"title": "Weather today", "source": "BC", "summary": "sunny", "link": ""},
    ]
    fetcher_mock = MagicMock()
    fetcher_mock.fetch_feed = AsyncMock(return_value=raw_items)
    with (
        patch("services.cti_sitrep._load_cti_feeds", return_value=[{"name": "BC", "url": "http://x", "type": "rss"}]),
        patch("services.cti_sitrep._load_keywords", return_value=["cve", "exploit"]),
        patch("services.scheduled_news._fetcher.RssFetcher", return_value=fetcher_mock),
    ):
        items = await _fetch_cti_items()
    assert len(items) == 1
    assert "CVE" in items[0]["title"]


async def test_fetch_cti_items_no_feeds_returns_empty():
    with patch("services.cti_sitrep._load_cti_feeds", return_value=[]):
        items = await _fetch_cti_items()
    assert items == []


# ── run_cti_sitrep ──


async def test_no_items_skips_sitrep():
    with patch("services.cti_sitrep._fetch_cti_items", new_callable=AsyncMock, return_value=[]):
        result = await run_cti_sitrep()
    assert result == ""


async def test_llm_circuit_open_skips():
    bridge = MagicMock()
    bridge.should_accept_traffic.return_value = False
    with (
        patch("services.cti_sitrep._fetch_cti_items", new_callable=AsyncMock, return_value=_SAMPLE_ITEMS[:1]),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
    ):
        result = await run_cti_sitrep()
    assert result == ""


async def test_successful_sitrep_saves_and_sends():
    sitrep_text = "- CVE-2026-1234: Critical RCE in Apache\n- APT29 phishing campaign"
    bridge = MagicMock()
    bridge.should_accept_traffic.return_value = True
    bridge.complete = AsyncMock(return_value=sitrep_text)

    mock_file = MagicMock()
    mock_file.write_text = MagicMock()
    mock_file.mkdir = MagicMock(parents=True, exist_ok=True)
    mock_file.__truediv__ = MagicMock(return_value=mock_file)

    with (
        patch("services.cti_sitrep._fetch_cti_items", new_callable=AsyncMock, return_value=_SAMPLE_ITEMS[:2]),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.cti_sitrep._load_chat_id", return_value="123456"),
        patch("services.cti_sitrep.Path") as mock_path_cls,
        patch("services.interfaces.get_message_gateway") as mock_gw,
    ):
        mock_path_cls.side_effect = lambda p: mock_file
        mock_channel = MagicMock()
        mock_channel.bot = MagicMock()
        mock_channel.bot.send_document = AsyncMock()
        mock_gw.return_value = mock_channel

        result = await run_cti_sitrep()

    assert "CTI SITREP" in result
    assert sitrep_text in result
    mock_file.write_text.assert_called_once()
    mock_channel.bot.send_document.assert_called_once()


async def test_md_file_includes_source_links():
    """The .md file must include original article links for IOC drilldown."""
    sitrep_text = "- Critical CVE found"
    bridge = MagicMock()
    bridge.should_accept_traffic.return_value = True
    bridge.complete = AsyncMock(return_value=sitrep_text)

    mock_file = MagicMock()
    mock_file.write_text = MagicMock()
    mock_file.mkdir = MagicMock(parents=True, exist_ok=True)
    mock_file.__truediv__ = MagicMock(return_value=mock_file)

    items_with_links = [
        {
            "title": "Apache RCE",
            "source": "BleepingComputer",
            "summary": "exploit",
            "link": "https://bleepingcomputer.com/1",
        },
        {
            "title": "APT29 campaign",
            "source": "The Hacker News",
            "summary": "phishing",
            "link": "https://thehackernews.com/2",
        },
    ]
    with (
        patch("services.cti_sitrep._fetch_cti_items", new_callable=AsyncMock, return_value=items_with_links),
        patch("services.llm_bridge.LLMBridge.get_instance", return_value=bridge),
        patch("services.cti_sitrep._load_chat_id", return_value=""),
        patch("services.cti_sitrep.Path") as mock_path_cls,
    ):
        mock_path_cls.side_effect = lambda p: mock_file
        await run_cti_sitrep()

    # Verify write_text was called with content containing source links
    written_content = mock_file.write_text.call_args[0][0]
    assert "## Sources" in written_content
    assert "https://bleepingcomputer.com/1" in written_content
    assert "https://thehackernews.com/2" in written_content
    assert "Apache RCE" in written_content


async def test_llm_failure_returns_empty():
    with (
        patch("services.cti_sitrep._fetch_cti_items", new_callable=AsyncMock, return_value=_SAMPLE_ITEMS[:1]),
        patch("services.llm_bridge.LLMBridge.get_instance", side_effect=Exception("LLM down")),
    ):
        result = await run_cti_sitrep()
    assert result == ""


# ── Prompt verification ──


def test_prompt_enforces_english_output():
    """CTI SITREP prompt must enforce pure English (not Hebrew)."""
    assert "pure English" in _CTI_PROMPT
    assert "3 bullet points" in _CTI_PROMPT
    assert "critical vulnerabilities" in _CTI_PROMPT
    assert "active campaigns" in _CTI_PROMPT
