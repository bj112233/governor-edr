# services/cti_sitrep.py
"""Daily CTI (Cyber Threat Intelligence) SITREP — 08:30 batch job.

Fetches top cyber threat news from dedicated CTI RSS feeds (BleepingComputer,
The Hacker News, Krebs, CERT-IL), filters by keywords, and asks the LLM for
a concise English summary of critical vulnerabilities and active campaigns.

Output: pure English (eases 4B model summarization). Saved as .md file +
sent to Telegram as document via event bus.

Architecture: standalone batch job (like reflection_agent.py), NOT in
startup/ — SRP: batch job, not bootstrap. Reuses RssFetcher from
scheduled_news but has its own CTI-specific prompt + delivery.
"""

import asyncio
import json
import logging
from pathlib import Path

from config import LLM_TIMEOUT

logger = logging.getLogger(__name__)

_CTI_CONFIG_PATH = Path(__file__).parent.parent / "skills" / "news-monitor" / "config" / "feeds_cti.json"
_DELIVERY_CONFIG_PATH = Path(__file__).parent.parent / "config" / "news_feeds.json"

_CTI_PROMPT = (
    "You are a Cyber Threat Intelligence analyst. Summarize the cyber threats "
    "from the last 24 hours provided below. Output exactly 3 bullet points "
    "highlighting only critical vulnerabilities or active campaigns.\n"
    "CRITICAL: Output in pure English. Keep technical terms as-is (CVE IDs, "
    "malware names, APT groups). No preamble. Start directly with bullet points.\n"
    "Format: Markdown. Each bullet starts with '- '. Max 2 lines per bullet."
)

_MAX_ITEMS = 5  # Top 5 stories from last 24h
_ITEMS_PER_FEED = 3  # Per-feed fetch limit


def _load_cti_feeds() -> list[dict]:
    """Load CTI feed config from JSON."""
    try:
        with open(_CTI_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("feeds", [])
    except Exception as exc:
        logger.error("[CTI] Failed to load feeds config: %s", exc)
        return []


def _load_keywords() -> list[str]:
    """Load CTI keywords for filtering."""
    try:
        with open(_CTI_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("keywords", [])
    except Exception:
        return []


def _load_chat_id() -> str:
    """Load Telegram chat_id from delivery config."""
    try:
        with open(_DELIVERY_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return str(data.get("delivery", {}).get("telegram", {}).get("chat_id", ""))
    except Exception:
        return ""


def _filter_by_keywords(items: list[dict], keywords: list[str]) -> list[dict]:
    """Filter items by CTI keywords (case-insensitive, title + summary)."""
    if not keywords:
        return items
    kw_lower = [k.lower() for k in keywords]
    filtered = []
    for item in items:
        text = (item.get("title", "") + " " + item.get("summary", "")).lower()
        if any(kw in text for kw in kw_lower):
            filtered.append(item)
    return filtered


async def _fetch_cti_items() -> list[dict]:
    """Fetch + filter CTI items from all feeds. Returns top N items."""
    from services.scheduled_news._fetcher import RssFetcher

    feeds = _load_cti_feeds()
    if not feeds:
        logger.warning("[CTI] No feeds configured. Skipping.")
        return []

    fetcher = RssFetcher()
    all_items: list[dict] = []
    for feed in feeds:
        feed_with_category = {**feed, "category": "cti"}
        items = await fetcher.fetch_feed(feed_with_category, limit=_ITEMS_PER_FEED)
        all_items.extend(items)
        await asyncio.sleep(0.2)

    # Filter by keywords
    keywords = _load_keywords()
    filtered = _filter_by_keywords(all_items, keywords)

    # Sort by published (newest first) — fallback to order fetched
    # Take top N items
    top_items = filtered[:_MAX_ITEMS] if len(filtered) >= _MAX_ITEMS else filtered[:_MAX_ITEMS]

    logger.info("[CTI] Fetched %d items, filtered to %d, top %d", len(all_items), len(filtered), len(top_items))
    return top_items


def _build_cti_block(items: list[dict]) -> str:
    """Build compact text block for the LLM."""
    if not items:
        return ""
    lines = []
    for item in items:
        title = item.get("title", "").strip()
        source = item.get("source", "").strip()
        summary = item.get("summary", "").strip()[:200]
        link = item.get("link", "").strip()
        parts = [f"- [{title}]"]
        if source:
            parts.append(f"({source})")
        if summary:
            parts.append(f"— {summary}")
        if link:
            parts.append(f"| {link}")
        lines.append(" ".join(parts))
    return "\n".join(lines)


async def run_cti_sitrep() -> str:
    """Main entry: generate daily CTI SITREP.

    Returns the SITREP text (empty string on failure/no data).
    Saves .md file + sends to Telegram as document.
    """
    logger.info("[CTI] Starting daily CTI SITREP...")

    items = await _fetch_cti_items()
    if not items:
        logger.info("[CTI] No CTI items fetched. Skipping SITREP.")
        return ""

    block = _build_cti_block(items)
    if not block:
        return ""

    try:
        from services.llm_bridge import LLMBridge

        bridge = LLMBridge.get_instance()
        if not bridge.should_accept_traffic():
            logger.warning("[CTI] LLM circuit open, skipping CTI SITREP.")
            return ""

        sitrep = await bridge.complete(
            system_prompt=_CTI_PROMPT,
            user_input=block,
            temperature=0.2,
            max_tokens=512,
            timeout=float(LLM_TIMEOUT * 2),
        )
        sitrep = (sitrep or "").strip()
        if not sitrep:
            logger.warning("[CTI] LLM returned empty SITREP. Skipping.")
            return ""
    except Exception as exc:
        logger.error("[CTI] LLM call failed: %s", exc)
        return ""

    # Build full report via Jinja2 template (services.reports)
    from services.reports.env import get_report_env
    from services.time_format import format_report_date

    date_str = format_report_date()
    report = (
        get_report_env()
        .get_template("sitrep.j2")
        .render(
            emoji="🛡️",
            title=f"CTI SITREP — Cyber Threat Intelligence [{date_str}]",
            sitrep=sitrep,
        )
    )

    # Append source links to the .md file (not sent to Telegram — keeps message clean)
    source_lines = ["\n---\n## Sources"]
    for item in items:
        title = item.get("title", "").strip()
        source = item.get("source", "").strip()
        link = item.get("link", "").strip()
        if link:
            source_lines.append(f"- [{title}]({link}) ({source})")
    sources_section = "\n".join(source_lines)

    # Save .md file with sources
    out_dir = Path("downloads/reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / f"cti_sitrep_{date_str}.md"
    filepath.write_text(report + sources_section, encoding="utf-8")
    logger.info("[CTI] Saved -> %s", filepath)

    # Send to Telegram as document
    chat_id = _load_chat_id()
    if chat_id:
        try:
            from typing import Any

            from services.interfaces import get_message_gateway

            channel: Any = get_message_gateway()
            if channel and getattr(channel, "bot", None):
                from aiogram.types import FSInputFile

                await channel.bot.send_document(
                    chat_id=chat_id,
                    document=FSInputFile(str(filepath)),
                    caption="🛡️ CTI SITREP — Cyber Threat Intelligence",
                )
                logger.info("[CTI] SITREP document sent to Telegram.")
            else:
                logger.warning("[CTI] Telegram channel unavailable — SITREP not sent.")
        except Exception as tg_err:
            logger.error("[CTI] Telegram delivery failed: %s", tg_err)

    return report
