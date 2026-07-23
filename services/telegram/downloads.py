# services/telegram/downloads.py
"""Telegram attachment download helpers."""

import logging
import re
import uuid
from io import BytesIO
from pathlib import Path
from typing import Optional

from aiogram import Bot
from aiogram.types import Document, PhotoSize

logger = logging.getLogger(__name__)

#: Maximum file size to download (50 MB)
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024


def get_download_dir() -> Path:
    """Directory to save Telegram attachments."""
    d = (Path.cwd() / "downloads").resolve()
    d.mkdir(exist_ok=True)
    return d


#: Telegram mime_type → file extension mapping for documents without file_name
_MIME_EXT_MAP = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "text/plain": ".txt",
    "text/markdown": ".md",
    "application/json": ".json",
    "text/csv": ".csv",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "audio/mpeg": ".mp3",
    "audio/ogg": ".ogg",
    "video/mp4": ".mp4",
    "application/zip": ".zip",
    "application/x-7z-compressed": ".7z",
}


async def download_document(bot: Bot, document: Document, dest_dir: Path) -> Path | None:
    """Download a Telegram document and return local path."""
    try:
        raw_name = document.file_name or f"doc_{document.file_id}"
        # Sanitize: reject path separators and suspicious chars
        file_name = Path(raw_name).name
        if not re.match(r"^[\w\-. ]+$", file_name):
            file_name = f"doc_{document.file_id}"
        # If no extension, infer from Telegram mime_type
        ext = Path(file_name).suffix
        if not ext and document.mime_type:
            ext = _MIME_EXT_MAP.get(document.mime_type, "")
            if ext:
                file_name = f"{Path(file_name).stem}{ext}"
        dest = dest_dir.resolve() / f"{Path(file_name).stem}_{uuid.uuid4().hex[:8]}{Path(file_name).suffix}"
        # aiogram 3: download by file_id into BytesIO
        buf = BytesIO()
        await bot.download(document.file_id, destination=buf)
        if buf.tell() > MAX_DOWNLOAD_SIZE:
            logger.warning("[Telegram] File too large (%d bytes), dropped", buf.tell())
            return None
        buf.seek(0)
        with open(dest, "wb") as f:
            f.write(buf.read())
        logger.info("[Telegram] Downloaded attachment: %s", dest)
        return dest
    except Exception as e:
        logger.error("[Telegram] Download failed: %s", e)
        return None


async def download_photo(bot: Bot, photo: PhotoSize, dest_dir: Path) -> Path | None:
    """Download a Telegram photo (largest size) and return local path."""
    try:
        dest = dest_dir.resolve() / f"photo_{photo.file_unique_id}.jpg"
        buf = BytesIO()
        await bot.download(photo.file_id, destination=buf)
        if buf.tell() > MAX_DOWNLOAD_SIZE:
            logger.warning("[Telegram] Photo too large (%d bytes), dropped", buf.tell())
            return None
        buf.seek(0)
        with open(dest, "wb") as f:
            f.write(buf.read())
        logger.info("[Telegram] Downloaded photo: %s", dest)
        return dest
    except Exception as e:
        logger.error("[Telegram] Photo download failed: %s", e)
        return None
