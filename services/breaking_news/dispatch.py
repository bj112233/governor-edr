# services/breaking_news/dispatch.py
"""Alert formatting + Telegram dispatch (HTML parse mode).

Consolidated format: one alert per event cluster, with corroboration count
and source list. Replaces per-item dispatch that sent N alerts for the same
event reported by N feeds.
"""

import html
import logging
from typing import Any

from services.agent._helpers import _fire_and_forget
from services.news_ai import _is_title_echo
from services.time_format import format_feed_time

logger = logging.getLogger(__name__)

# Telegram photo caption hard limit — keep caption safe under this.
_CAPTION_LIMIT = 1024

# ─── Severity mapping ───────────────────────────────────────────────────────

_CRITICAL_KEYWORDS = frozenset(
    {
        "פיגוע",
        "פיגוע דקירה",
        "פיגוע דריסה",
        "פיגוע ירי",
        "פיגוע התאבדות",
        "מחבל",
        "מחבלים",
        "מחבל מתאבד",
        "טרור",
        "רקטה",
        "רקטות",
        "טיל",
        'כטב"ם',
        "רחפן",
        "מלחמה",
        "הרוג",
        "הרוגים",
        "הרוגים רבים",
        "חטיפה",
        "חטופים",
        "נפצע קשה",
        "נפגע קשה",
        "נפילה",
        "יירוט",
        "ירי רקטות",
        "אסון",
        "אסונות",
        "אסון המוני",
        "תאונה קטלנית",
        "מצב חירום לאומי",
        "מתאבדים",
        "מכונית תופת",
        "מטען חבלה",
        "מטען נפץ",
        "רימון יד",
        "מנהרת טרור",
        "חוליית טרור",
        "הפגזה",
        "ירי תלול מסלול",
    }
)

_HIGH_KEYWORDS = frozenset(
    {
        "תקיפה",
        "חדירה",
        "הסתננות",
        "ירי לעבר",
        "ירי צלפים",
        "דקירה",
        "רצח",
        "התנקשות",
        "מעצר",
        "עימותים",
        "הפגנה",
        "מהומות",
        "הסלמה",
        "הסלמה ביטחונית",
        "מבצע צבאי",
        "אזעקה",
        "צבע אדום",
        "התרעה",
        "התרעת צבע אדום",
        "צופרים",
        "פיקוד עורף",
        "חירום",
        "מצב חירום",
        "אירוע חירום",
        "אירוע חמור",
        "אירוע ביטחוני",
        "אירוע ירי",
        "אירוע פיצוץ",
        "אירוע דקירה",
        "אירוע דריסה",
        "אירוע טרור",
        "אש חיה",
        "אזור אש",
        "חמאס",
        "חיזבאללה",
        "ג'יהאד",
        "איראן",
        "סוריה",
        "לבנון",
        "גבול",
        "חציית גבול",
        "כוננות כבדה",
        "גיוס",
        "מילואים",
        "תגבורת",
        "כוחות מיוחדים",
        "פינוי",
        "פינוי המוני",
        "מקלטים",
        "בלון תבערה",
        "פצועים רבים",
        "נפגעים",
        "פגיעה",
        "מתקפה",
    }
)

_SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "moderate": "🟡"}


def _severity_for_keyword(keyword: str) -> str:
    """Map matched keyword to severity level: critical / high / moderate."""
    if keyword in _CRITICAL_KEYWORDS:
        return "critical"
    if keyword in _HIGH_KEYWORDS:
        return "high"
    return "moderate"


def severity_emoji(keyword: str) -> str:
    """Return emoji badge for keyword severity."""
    return _SEVERITY_EMOJI[_severity_for_keyword(keyword)]


# ─── HTML alert builder ─────────────────────────────────────────────────────


def format_cluster_alert(cluster: Any) -> tuple[str, dict, str]:
    """Build consolidated HTML alert for an event cluster.

    Returns (message, best_item, best_image_url).
    - message: HTML-formatted caption/body for send_photo or send_message.
    - best_item: the canonical item (title, link, time) chosen from the cluster.
    - best_image_url: best image across all items ("" if none).
    """
    best_item = cluster.best_item
    raw_title = best_item.get("title", "") or "התראה ביטחונית"
    ai_summary = best_item.get("ai_summary", "") or ""
    if ai_summary and _is_title_echo(raw_title, ai_summary):
        ai_summary = ""

    summary = (ai_summary or "")[:240]
    source_raw = best_item.get("source", "") or "מקור לא ידוע"
    keyword = best_item.get("matched_keyword", "") or "כללי"
    time_str = format_feed_time(best_item)
    sev = severity_emoji(keyword)

    title_esc = html.escape(raw_title, quote=False)
    summary_esc = html.escape(summary, quote=False)
    time_esc = html.escape(time_str, quote=False)

    src_tag = "".join(c if c.isalnum() else "_" for c in source_raw).strip("_") or "מקור"

    parts: list[str] = [f"{sev} <b>{title_esc}</b>"]
    if summary_esc:
        parts.append(f"\n<blockquote>{summary_esc}</blockquote>")
    parts.append(f"\n⏱ <b>זמן:</b> {time_esc}")

    # Corroboration line — only if >1 source
    source_names = cluster.source_names
    if len(source_names) > 1:
        sources_esc = html.escape(", ".join(source_names), quote=False)
        parts.append(f"\n📰 <b>מקורות מאשרים ({len(source_names)}):</b> {sources_esc}")

    parts.append(f"\n#{src_tag} #מבזק_ביטחוני #OSINT")
    return "\n".join(parts), best_item, cluster.best_image


# ─── Inline keyboard ────────────────────────────────────────────────────────


def _build_cluster_keyboard(cluster: Any) -> Any:
    """Build inline keyboard with source buttons.

    Single source → one button. Multiple sources → one button per source
    (Telegram allows up to 8 buttons per row, 100 total). Button text is
    the source name; URL is the article link.
    """
    from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

    links = cluster.all_links
    if not links:
        return None

    # Cap at 8 sources to keep the keyboard readable
    rows: list[list[InlineKeyboardButton]] = []
    row: list[InlineKeyboardButton] = []
    for src, link in links[:8]:
        text = f"🔗 {src}"
        row.append(InlineKeyboardButton(text=text, url=link))
        if len(row) == 2:  # 2 buttons per row
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return InlineKeyboardMarkup(inline_keyboard=rows)


# ─── Dispatch ───────────────────────────────────────────────────────────────


async def _send_photo(telegram_channel: Any, chat_id: str, image_url: str, caption: str, cluster: Any) -> bool:
    """Send alert as photo with HTML caption + inline source buttons."""
    from aiogram.enums import ParseMode
    from aiogram.types import URLInputFile

    keyboard = _build_cluster_keyboard(cluster)
    try:
        await telegram_channel.bot.send_photo(
            chat_id=chat_id,
            photo=URLInputFile(image_url),
            caption=caption[:_CAPTION_LIMIT],
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        return True
    except Exception as exc:
        reason = str(exc).split("RequestInfo(")[0].strip() or type(exc).__name__
        logger.warning("[BreakingNews] send_photo failed (%s) — falling back to text", reason[:120])
        return False


async def _send_html_text(telegram_channel: Any, chat_id: str, message: str, cluster: Any) -> bool:
    """Send HTML text message with inline source buttons."""
    from aiogram.enums import ParseMode

    keyboard = _build_cluster_keyboard(cluster)
    try:
        await telegram_channel.bot.send_message(
            chat_id=chat_id,
            text=message,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
            disable_web_page_preview=True,
        )
        return True
    except Exception as exc:
        logger.error("[BreakingNews] send_message (HTML) raised: %s", exc)
        return False


async def _dispatch_telegram(telegram_channel: Any, chat_id: str, cluster: Any, message: str, image_url: str) -> bool:
    """Send consolidated alert via Telegram — photo when image available, else HTML text."""
    title = cluster.best_item.get("title", "")

    if image_url:
        ok = await _send_photo(telegram_channel, chat_id, image_url, message, cluster)
        if ok:
            logger.info("[BreakingNews] ✅ Alert sent successfully: %s...", title[:50])
            return True
    ok = await _send_html_text(telegram_channel, chat_id, message, cluster)
    if ok:
        logger.info("[BreakingNews] ✅ Alert sent successfully: %s...", title[:50])
    else:
        logger.error("[BreakingNews] ❌ Failed to send alert: %s...", title[:50])
    return ok


async def send_cluster_alert(cluster: Any, telegram_channel: Any, bg_tasks: set | None = None) -> bool:
    """Send a consolidated alert for an event cluster. Returns True on success.

    Photo dispatch when image available (HTML caption + inline source buttons).
    Fallback: HTML text message with inline source buttons.
    """
    message, best_item, image_url = format_cluster_alert(cluster)
    title = best_item.get("title", "")
    ai_summary = best_item.get("ai_summary", "")

    logger.info("[BreakingNews] Attempting to send consolidated alert via Telegram...")
    success = False
    if not telegram_channel:
        logger.warning("[BreakingNews] ❌ Telegram channel not available")
        print(f"🚨 BREAKING NEWS ALERT:\n{message}\n")
        logger.info("[BreakingNews] Alert printed to console (no Telegram)")
        success = True
    else:
        from config import TELEGRAM_CHAT_ID

        if not TELEGRAM_CHAT_ID:
            logger.warning("[BreakingNews] ❌ TELEGRAM_CHAT_ID not configured")
        else:
            logger.info(
                "[BreakingNews] Telegram channel available, sending to chat %s",
                TELEGRAM_CHAT_ID,
            )
            success = await _dispatch_telegram(telegram_channel, str(TELEGRAM_CHAT_ID), cluster, message, image_url)

    if success and ai_summary and bg_tasks is not None:
        from .ai_scoring import hunt_and_escalate

        _fire_and_forget(hunt_and_escalate(title, ai_summary, telegram_channel))

    return success


# ─── Backward compat: per-item send_alert (kept for tests/legacy callers) ──


async def send_alert(item: dict, telegram_channel: Any, bg_tasks: set | None = None) -> bool:
    """Send a single-item alert (legacy path, wraps item in a 1-item cluster).

    New code should call send_cluster_alert directly. This wrapper exists for
    backward compatibility with tests and any external callers.
    """
    import time as _time

    from .state import EventCluster

    cluster = EventCluster(fingerprint_key="legacy")
    cluster.add(item, _time.time())
    return await send_cluster_alert(cluster, telegram_channel, bg_tasks)
