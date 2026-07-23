# services/telegram/polling.py
"""Bot polling lifecycle — start, _poll loop, stop."""

import asyncio
import logging

from aiogram import Bot
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.types import BotCommand
from aiogram.utils.backoff import BackoffConfig

from services.telegram.commands import INTEL_COMMANDS, INTEL_COMMANDS_WITH_ARGS

logger = logging.getLogger(__name__)

# Backoff config that respects Telegram's typical RetryAfter (5s).
# Default aiogram backoff starts at 1s — less than Telegram's "retry after 5",
# causing premature retries that worsen flood control.
_FLOOD_SAFE_BACKOFF = BackoffConfig(min_delay=5.0, max_delay=60.0, factor=2.0, jitter=0.1)
_POLLING_TIMEOUT = 30  # Standard long-poll timeout (default 10 is too short)


async def start_polling(channel) -> None:
    """Start the Telegram bot."""
    token = channel._get_token()
    if not token:
        logger.warning("[Telegram] No bot token configured, skipping startup")
        return

    channel._token = token
    from aiogram import Bot, Dispatcher
    from aiogram.fsm.storage.memory import MemoryStorage

    channel.bot = Bot(token=token)
    channel.dp = Dispatcher(storage=MemoryStorage())

    try:
        me = await channel.bot.get_me()
        channel._bot_username = me.username
    except Exception as e:
        logger.warning("[Telegram] get_me failed: %s", e)

    channel.setup_routes()
    channel.dp.include_router(channel.router)

    channel._running = True
    logger.info("[Telegram] Starting bot...")

    # Drop any stale webhook + pending updates to prevent GetUpdates flood.
    # If a webhook was ever set, getUpdates throws 409 Conflict and aiogram
    # retries rapidly → flood control. drop_pending_updates clears the queue
    # so we don't re-receive a backlog burst on reconnect.
    try:
        await channel.bot.delete_webhook(drop_pending_updates=True)
        logger.info("[Telegram] Webhook cleared + pending updates dropped")
    except Exception as e:
        logger.warning("[Telegram] delete_webhook failed: %s", e)

    try:
        commands = [
            BotCommand(command="start", description="🚀 התחלת שיחה"),
            BotCommand(command="help", description="📋 תפריט פקודות"),
            BotCommand(command="skills", description="🛠️ Skills זמינים"),
            BotCommand(command="status", description="📊 סטטוס מערכת"),
            BotCommand(command="stats", description="📈 טלמטריה עצמית"),
            BotCommand(command="intel", description="🚨 איומים אחרונים"),
            BotCommand(command="threatscan", description="🛡️ ציד איומים מערכתי"),
        ]
        for slash, (_, title) in INTEL_COMMANDS.items():
            clean = title.split(" ", 1)[1] if " " in title else title
            commands.append(BotCommand(command=slash, description=clean[:64]))
        for slash, (_, title, arg_key, _) in INTEL_COMMANDS_WITH_ARGS.items():
            if slash == "intel":
                continue
            clean = title.split(" ", 1)[1] if " " in title else title
            commands.append(BotCommand(command=slash, description=f"{clean[:50]} <{arg_key}>"[:64]))
        await channel.bot.set_my_commands(commands)
        logger.info("[Telegram] Registered %d slash commands", len(commands))
    except Exception as e:
        logger.warning("[Telegram] set_my_commands failed: %s", e)

    await _poll(channel)


async def _poll(channel) -> None:
    """Run polling loop with resilient retry on network errors."""
    if not channel.bot or not channel.dp:
        return

    max_retries = 10
    base_delay = 5.0
    for attempt in range(1, max_retries + 1):
        try:
            await channel.dp.start_polling(
                channel.bot,
                polling_timeout=_POLLING_TIMEOUT,
                backoff_config=_FLOOD_SAFE_BACKOFF,
                handle_signals=False,  # Sentinel handles SIGINT/SIGTERM itself
            )
            return
        except Exception as e:
            err_text = str(e)
            is_transient = any(
                kw in err_text.lower()
                for kw in (
                    "timeout",
                    "semaphore",
                    "winerror 121",
                    "network",
                    "disconnected",
                    "connection",
                    "clientoserror",
                    "retry after",
                    "flood",
                    "bad gateway",
                    "server error",
                    "too many requests",
                )
            )
            if not is_transient:
                logger.error("[Telegram] Fatal polling error (attempt %d): %s", attempt, e)
                channel._running = False
                return

            delay = min(base_delay * (2 ** (attempt - 1)), 300)
            logger.warning(
                "[Telegram] Transient polling error (attempt %d/%d): %s — retrying in %.0fs...",
                attempt,
                max_retries,
                e,
                delay,
            )
            try:
                await asyncio.wait_for(channel._stop_event.wait(), timeout=delay)
                return
            except TimeoutError:
                pass

            # Stop dispatcher first (needs session for acks), then close session
            if channel.dp:
                try:
                    await channel.dp.stop_polling()
                except Exception:
                    pass
            if channel.bot and channel.bot.session:
                await channel.bot.session.close()
            # Fresh Dispatcher to avoid stale FSM / router state
            from aiogram import Dispatcher
            from aiogram.fsm.storage.memory import MemoryStorage

            channel.dp = Dispatcher(storage=MemoryStorage())
            channel.setup_routes()
            channel.dp.include_router(channel.router)
            new_session = AiohttpSession()
            channel.bot = Bot(token=channel._token, session=new_session)
            logger.info("[Telegram] Bot + Dispatcher recreated successfully.")


async def stop_polling(channel) -> None:
    """Stop the bot."""
    channel._running = False
    channel._stop_event.set()
    if channel.dp:
        await channel.dp.stop_polling()
    if channel.bot:
        await channel.bot.session.close()
    logger.info("[Telegram] Bot stopped")
