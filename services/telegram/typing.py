# services/telegram/typing.py
"""Typing indicator wrapper for long-running coroutines."""

import asyncio
from typing import Any

from aiogram.enums import ChatAction
from aiogram.types import Message


async def with_typing(message: Message, coro) -> Any:
    """Run a coroutine while keeping the 'typing' indicator alive."""
    stop = asyncio.Event()

    async def _typing_loop() -> None:
        bot = message.bot
        if bot is None:
            return
        chat_id = message.chat.id
        while not stop.is_set():
            try:
                await bot.send_chat_action(chat_id=chat_id, action=ChatAction.TYPING)
            except Exception:
                pass
            try:
                await asyncio.wait_for(stop.wait(), timeout=4.0)
            except TimeoutError:
                continue

    task = asyncio.create_task(_typing_loop())
    try:
        return await coro
    finally:
        stop.set()
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except TimeoutError:
            task.cancel()
