# services/telegram/permissions.py
"""Permission checks for DM and group chats."""

from typing import Optional

from aiogram.types import Message

from config import TELEGRAM_BOT_TOKEN
from services.channels_config import DmPolicy


def is_mentioned(message: Message, bot_username: str | None, bot_id: int | None) -> bool:
    """Check if bot is mentioned (reply, @username, or text_mention)."""
    if not bot_id:
        return False
    if (
        message.reply_to_message
        and message.reply_to_message.from_user
        and message.reply_to_message.from_user.id == bot_id
    ):
        return True
    text = message.text or message.caption or ""
    if message.entities:
        for entity in message.entities:
            if entity.type == "mention" and bot_username:
                try:
                    mention_text = text[entity.offset : entity.offset + entity.length]
                except Exception:
                    mention_text = ""
                if mention_text.lstrip("@").lower() == bot_username.lower():
                    return True
            elif entity.type == "text_mention":
                if entity.user and entity.user.id == bot_id:
                    return True
    return False


def should_require_mention(chat_id: int | str, groups_cfg: dict) -> bool:
    sid = str(chat_id)
    if sid in groups_cfg:
        return groups_cfg[sid].require_mention
    return True


def is_dm_allowed(user_id: int, cfg) -> bool:
    if cfg.dm_policy == DmPolicy.DISABLED:
        return False
    if cfg.dm_policy in (DmPolicy.OPEN, DmPolicy.ALLOWLIST):
        return cfg.is_dm_allowed(user_id)
    return False


async def is_group_allowed(chat_id: int, user_id: int, cfg) -> bool:
    return cfg.is_group_allowed(chat_id, user_id)


def get_response_prefix(chat_id: int | None, cfg) -> str:
    if chat_id:
        sid = str(chat_id)
        if sid in cfg.groups and cfg.groups[sid].system_prompt:
            return cfg.groups[sid].system_prompt or ""
    return cfg.response_prefix or ""
