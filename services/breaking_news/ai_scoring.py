# services/breaking_news/ai_scoring.py
"""AI batch enrichment + OSINT escalation."""

import asyncio
import logging

logger = logging.getLogger(__name__)


async def enrich_items(items: list[dict]) -> list[dict]:
    """Batch enrich items with AI summary + sentiment."""
    try:
        from services.llm_bridge import LLMBridge
        from services.news_ai import bulk_enrich

        bridge = LLMBridge.get_instance()
        if bridge.should_accept_traffic():
            enriched = await bulk_enrich(items, bridge, batch_size=10)
            for item, e in zip(items, enriched):
                if e.get("summary"):
                    item["ai_summary"] = e["summary"]
                if e.get("sentiment") and e.get("sentiment") != "unknown":
                    item["sentiment"] = e["sentiment"]
            logger.info("[BreakingNews] Batch enriched %d items", len(items))
    except Exception as exc:
        logger.debug("[BreakingNews] Batch enrichment failed: %s", exc)
    return items


async def hunt_and_escalate(title: str, source_text: str, telegram_channel=None) -> None:
    """Background task: hunt and send escalation if local threat found."""
    title_lower = title.lower()
    score = 0

    # Tier 1 (Definitive Threat - Score: 3)
    if any(kw in title_lower for kw in ["cve-", "zero-day", "0-day", "apt", "ransomware", "rootkit"]):
        score += 3
    # Tier 2 (High Probability - Score: 2)
    if any(
        kw in title_lower
        for kw in [
            "סייבר",
            "האקר",
            "נוזקה",
            "רוגלה",
            "פישינג",
            "חולשה",
            "דלף",
            "הודלפו",
            "malware",
            "phishing",
            "vulnerability",
            "exploit",
            "backdoor",
        ]
    ):
        score += 2
    # Tier 3 (Contextual - Score: 1)
    if any(
        kw in title_lower
        for kw in [
            "פרצה",
            "חדירה",
            "השתלטו",
            "נגנבו",
            "מתקפת",
            "פגיעות",
            "אבטחה",
            "leaked",
            "dump",
            "ddos",
        ]
    ):
        score += 1
    # Tier 4 (False Positive - Score: -5)
    if any(
        kw in title_lower
        for kw in [
            "סרט",
            "קולנוע",
            "סדרה",
            "הוליווד",
            "משחק",
            "כנס",
            "מניה",
            "בורסה",
            "movie",
            "tv",
            "fiction",
        ]
    ):
        score -= 5

    if score < 3:
        logger.debug("[BreakingNews] Triage SKIP (Score %d < 3): %s", score, title[:40])
        return

    try:
        from services.osint_hunter import hunt_and_analyze

        result = await hunt_and_analyze(title, source_text=source_text)
        if not result.get("critical_local_threat"):
            return
        if not telegram_channel:
            return

        from config import TELEGRAM_CHAT_ID

        if not TELEGRAM_CHAT_ID:
            return

        matches = result.get("local_matches", [])
        crit_msg = (
            "🔴 **איום מקומי קריטי!**\n\n"
            f"הנושא '{title[:80]}' נמצא בבסיס הנתונים המקומי.\n"
            f"Matches: `{matches}`\n\n"
            "⚠️ בדוק מיד!"
        )
        await telegram_channel.send_message(str(TELEGRAM_CHAT_ID), crit_msg)
        logger.critical("[BreakingNews] Escalation sent for '%s...'", title[:40])
    except Exception as exc:
        logger.debug("[BreakingNews] Hunt escalation failed: %s", exc)
