"""Delivery layer — Telegram, AI enrichment, SITREP generation."""

import asyncio
import logging
from pathlib import Path as _Path

from config import LLM_TIMEOUT

logger = logging.getLogger(__name__)

_STATE_OPEN = "open"

_TG_MAX_LEN = 4000  # Telegram limit 4096, leave margin
_CATEGORY_MARKER = "\u2500" * 25  # ─── used in A+ format category headers


def _split_for_telegram(message: str) -> list[str]:
    """Split a long digest into Telegram-safe chunks at category boundaries.

    Falls back to hard split if no category markers found.
    """
    if len(message) <= _TG_MAX_LEN:
        return [message]

    # Split at category headers (line starting with emoji + text + ───)
    import re

    # Match lines like "🛡️ ביטחון ───────────────"
    parts = re.split(r"(?m)^(?=\S[^\n]*\u2500{20,})", message)
    chunks: list[str] = []
    current = ""

    for part in parts:
        if not part.strip():
            continue
        if len(current) + len(part) > _TG_MAX_LEN:
            if current:
                chunks.append(current.strip())
            current = part
        else:
            current += part

    if current.strip():
        chunks.append(current.strip())

    return chunks if chunks else [message[:_TG_MAX_LEN]]


class DigestDelivery:
    """Send digests via Telegram and optionally enrich + generate SITREP."""

    def __init__(self, telegram_channel=None, delivery_config: dict | None = None):
        self.telegram_channel = telegram_channel
        self.delivery_config = delivery_config or {}

    async def send_digest(self, message: str, chat_id: str | None = None) -> bool:
        """Send formatted digest to Telegram or console fallback.

        Splits long messages at category boundaries to stay under
        Telegram's 4096-char limit.
        """
        cid = chat_id or self.delivery_config.get("chat_id")
        if self.telegram_channel and cid:
            chunks = _split_for_telegram(message)
            success = True
            for chunk in chunks:
                ok = await self.telegram_channel.send_message(str(cid), chunk)
                if not ok:
                    success = False
                await asyncio.sleep(0.3)  # rate-limit safety
            if success:
                logger.info("[NewsDelivery] Digest sent to Telegram (%d chunks)", len(chunks))
                return True
            logger.error("[NewsDelivery] Failed to send digest")
            return False
        # Fallback: console
        print(message)
        logger.info("[NewsDelivery] Digest printed to console (no Telegram)")
        return True

    async def ai_enrich(self, items: list[dict]) -> None:
        """Enrich items with AI summary + sentiment (in-place mutation)."""
        if not self.delivery_config.get("ai_digest"):
            return
        try:
            from services.llm_bridge import LLMBridge
            from services.news_ai import bulk_enrich

            bridge = LLMBridge.get_instance()
            if getattr(bridge, "_circuit_state", None) == _STATE_OPEN:
                logger.info("[NewsDelivery] AI digest skipped: circuit open")
                return
            if not items:
                return
            enriched = await bulk_enrich(items, bridge, batch_size=15)
            for it, e in zip(items, enriched):
                if e.get("summary"):
                    it["ai_summary"] = e["summary"]
                if e.get("sentiment") and e.get("sentiment") != "unknown":
                    it["sentiment"] = e["sentiment"]
            logger.info("[NewsDelivery] AI digest applied to %d items", len(items))
        except Exception as exc:
            logger.warning("[NewsDelivery] AI digest failed: %s", exc)

    async def generate_sitrep(self, categorized: dict[str, list[dict]]) -> None:
        """Generate daily SITREP from news items and deliver.

        Decoupled from alerts (the 08:00 daily_digest covers those). Receives
        the categorized news items just fetched + AI-enriched by
        send_daily_digest, and asks the LLM for a news-intelligence summary.
        """
        try:
            from services.llm_bridge import LLMBridge

            # Flatten + guard: skip if every category was filtered out.
            items = [it for its in categorized.values() for it in its]
            if not items:
                logger.info("[NewsDelivery] No news items — SITREP skipped")
                return

            from services.reports.env import get_report_env

            block = get_report_env().get_template("news.j2").render(categorized=categorized).rstrip("\n")
            if len(block) > 20000:
                block = block[:20000] + "\n...[truncated]"

            instructions = (
                "אתה אנליסט מודיעין חדשותי בכיר. סכם את פריטי החדשות "
                "מה-24 שעות האחרונות לדו\u05f4ח מצב יומי (SITREP) בעברית.\n"
                "קבץ לפי קטגוריה. הדגש מגמות סנטימנט, התפתחויות מרכזיות "
                "ונקודות למעקב. אל תמציא מידע שלא מופיע בפריטים.\n"
                "השתמש בשפה עניינית. "
                "חובה: פורמט Markdown חוקי בלבד, ללא הקדמות."
            )
            bridge = LLMBridge.get_instance()
            sitrep_md = await bridge.complete(
                system_prompt=instructions,
                user_input=block,
                temperature=0.2,
                max_tokens=2048,
                timeout=float(LLM_TIMEOUT * 2),  # SITREP: 2x fast-fail default
            )
            sitrep_clean = (sitrep_md or "").strip()
            if not sitrep_clean or sitrep_clean.startswith("\t"):
                logger.warning("[NewsDelivery] SITREP returned empty/invalid. Skipping.")
                return

            out_dir = _Path("downloads/reports")
            out_dir.mkdir(parents=True, exist_ok=True)
            from services.time_format import format_report_date

            filepath = out_dir / f"sitrep_{format_report_date()}.md"
            filepath.write_text(sitrep_clean, encoding="utf-8")
            logger.info("[NewsDelivery] SITREP saved -> %s", filepath)

            # Direct Telegram delivery
            chat_id = self.delivery_config.get("chat_id")
            if self.telegram_channel and self.telegram_channel.bot and chat_id:
                try:
                    from aiogram.types import FSInputFile

                    await self.telegram_channel.bot.send_document(
                        chat_id=str(chat_id),
                        document=FSInputFile(str(filepath)),
                        caption="📊 דו\u05f4ח מודיעין יומי (SITREP)",
                    )
                    logger.info("[NewsDelivery] SITREP file sent to Telegram.")
                except Exception as tg_err:
                    logger.error("[NewsDelivery] Failed to send SITREP: %s", tg_err)
            else:
                logger.warning("[NewsDelivery] Telegram unavailable — SITREP not sent.")
        except Exception as exc:
            logger.warning("[NewsDelivery] SITREP generation failed: %s", exc)
