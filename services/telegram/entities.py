"""Convert Markdown / HTML text to aiogram MessageEntity objects."""

import logging

from aiogram.enums import MessageEntityType
from aiogram.types import MessageEntity
from aiogram.utils.text_decorations import add_surrogates

logger = logging.getLogger(__name__)

_TAG_MAP = {
    "b": MessageEntityType.BOLD,
    "strong": MessageEntityType.BOLD,
    "i": MessageEntityType.ITALIC,
    "em": MessageEntityType.ITALIC,
    "code": MessageEntityType.CODE,
    "pre": MessageEntityType.PRE,
    "a": MessageEntityType.TEXT_LINK,
    "u": MessageEntityType.UNDERLINE,
    "s": MessageEntityType.STRIKETHROUGH,
    "strike": MessageEntityType.STRIKETHROUGH,
    "del": MessageEntityType.STRIKETHROUGH,
    "tg-spoiler": MessageEntityType.SPOILER,
    "blockquote": MessageEntityType.BLOCKQUOTE,
}


def _utf16_len(s: str) -> int:
    """Return UTF-16 code-unit count as required by Telegram Bot API."""
    return len(add_surrogates(s)) // 2


def _extract_pre_lang(node) -> str:
    """Extract language from <pre> node's class or language attribute."""
    lang = node.get("language") or ""
    if lang:
        return lang
    classes: list[str] | str = node.get("class") or []
    if not classes:
        return ""
    first = classes[0] if isinstance(classes, list) else str(classes)
    return first[9:] if first.startswith("language-") else ""


def _build_entity(tag_name: str, start_offset: int, length: int, node) -> MessageEntity | None:
    """Build a MessageEntity from a tag, or None if no entity type."""
    entity_type = _TAG_MAP.get(tag_name)
    if not entity_type or length <= 0:
        return None
    kwargs: dict = {"type": entity_type, "offset": start_offset, "length": length}
    if entity_type == MessageEntityType.TEXT_LINK:
        kwargs["url"] = node.get("href", "")
    if entity_type == MessageEntityType.PRE:
        lang = _extract_pre_lang(node)
        if lang:
            kwargs["language"] = lang
    return MessageEntity(**kwargs)


def _walk(node, text_parts: list[str], entities: list[MessageEntity]) -> None:
    """Recursively walk BeautifulSoup tree, collecting text + entities."""
    try:
        from bs4 import NavigableString, Tag
    except ImportError:
        return

    if isinstance(node, NavigableString):
        text_parts.append(str(node))
        return

    if not isinstance(node, Tag):
        return

    tag_name = node.name
    start_offset = sum(_utf16_len(p) for p in text_parts)

    for child in node.children:
        _walk(child, text_parts, entities)

    end_offset = sum(_utf16_len(p) for p in text_parts)
    entity = _build_entity(tag_name, start_offset, end_offset - start_offset, node)
    if entity:
        entities.append(entity)


def html_to_entities(html_text: str) -> tuple[str, list[MessageEntity]]:
    """Parse an HTML string into plain text + MessageEntity list.

    Graceful degradation: if parsing fails, returns (html_text, []).
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning("[entities] BeautifulSoup not available; sending raw text")
        return html_text, []

    try:
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception as exc:
        logger.warning("[entities] BeautifulSoup parse failed: %s", exc)
        return html_text, []

    text_parts: list[str] = []
    entities: list[MessageEntity] = []

    try:
        for child in soup.children:
            _walk(child, text_parts, entities)
    except Exception as exc:
        logger.warning("[entities] Entity tree walk failed: %s", exc)
        return html_text, []

    return "".join(text_parts), entities


def markdown_to_entities(markdown_text: str) -> tuple[str, list[MessageEntity]]:
    """Convert Markdown text -> HTML -> plain text + entities.

    Graceful degradation: if any step fails, returns (markdown_text, []).
    """
    try:
        from services.telegram.formatting import strip_markdown
    except Exception as exc:
        logger.warning("[entities] strip_markdown import failed: %s", exc)
        return markdown_text, []

    try:
        html_text = strip_markdown(markdown_text)
    except Exception as exc:
        logger.warning("[entities] strip_markdown failed: %s", exc)
        return markdown_text, []

    try:
        plain, entities = html_to_entities(html_text)
        return plain, entities
    except Exception as exc:
        logger.warning("[entities] html_to_entities failed: %s", exc)
        return markdown_text, []
