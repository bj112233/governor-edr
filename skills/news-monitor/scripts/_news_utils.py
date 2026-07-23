"""News Monitor — shared infrastructure utilities.

No business logic. Pure infrastructure: Pydantic models, SQLite state,
text sanitization, and date formatting.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import aiosqlite
from pydantic import BaseModel, ConfigDict, Field


# ── Pydantic I/O Models ──


class Article(BaseModel):
    title: str
    link: str
    summary: str = ""
    category: str = "general"
    published: str = ""
    source: str = ""
    matched: str = ""
    sentiment: str = ""
    ai_summary: str = ""
    full_text: str = ""


class NewsMonitorResult(BaseModel):
    articles: list[Article]


class NewsMonitorArgs(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    feed: str | None = None
    site: str | None = None
    selector: str = "a"
    config: str | None = None
    keywords: str | None = None
    limit: int = Field(default=10, le=50)
    delay: float = Field(default=1.0, ge=0.0)
    workers: int = Field(default=5, ge=1)
    alert: bool = False
    cooldown: int = Field(default=0, ge=0)
    categorize: bool = False
    semantic_dedup: bool = False
    semantic_threshold: float = Field(default=0.92, ge=0.0, le=1.0)
    extract: bool = False
    summarize: bool = False
    sentiment: bool = False
    llm_categorize: bool = False
    cluster: bool = False
    cluster_threshold: float = Field(default=0.82, ge=0.0, le=1.0)
    output: str | None = None
    format: str = "markdown"


# ── SQLite State Helpers ──


# Repo root is 4 levels up from skills/<skill>/scripts/_news_utils.py.
# DB files now live in <repo>/data/ (see services/db_pool.py DB_DIR).
# skill_state moved to reference.db (Sprint 5 Phase 3).
_DB_PATH = str(Path(__file__).resolve().parents[3] / "data" / "reference.db")


async def _get_db() -> aiosqlite.Connection:
    conn = await aiosqlite.connect(_DB_PATH)
    await conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = aiosqlite.Row
    return conn


async def _ensure_skill_state_table(conn: aiosqlite.Connection) -> None:
    await conn.execute(
        "CREATE TABLE IF NOT EXISTS skill_state (key TEXT PRIMARY KEY, value TEXT)"
    )
    await conn.commit()


async def _get_state(conn: aiosqlite.Connection, key: str) -> dict:
    await _ensure_skill_state_table(conn)
    async with conn.execute(
        "SELECT value FROM skill_state WHERE key = ?", (key,)
    ) as cursor:
        row = await cursor.fetchone()
    if row is None:
        return {}
    try:
        return json.loads(row["value"])
    except json.JSONDecodeError:
        return {}


async def _save_state(conn: aiosqlite.Connection, key: str, data: dict) -> None:
    await _ensure_skill_state_table(conn)
    await conn.execute(
        "INSERT OR REPLACE INTO skill_state (key, value) VALUES (?, ?)",
        (key, json.dumps(data, ensure_ascii=False)),
    )
    await conn.commit()


# ── Text Helpers ──


def _sanitize_text(val) -> str:
    """Remove control chars that break JSON serialization."""
    if not isinstance(val, str):
        return str(val)
    return "".join(
        ch
        for ch in val
        if ch == "\t"
        or ch == "\n"
        or ch == "\r"
        or (ord(ch) >= 32 and ord(ch) <= 0x10FFFF)
    )


# ── Date/Time Helpers ──


def _format_published(entry) -> str:
    """Convert RSS published_parsed directly to Israel-time 'dd/mm HH:MM'."""
    parsed = entry.get("published_parsed")
    if parsed:
        try:
            dt_utc = datetime(*parsed[:6], tzinfo=timezone.utc)
            # Clamp implausible future dates (e.g. Walla feeds mislabel local
            # time as GMT → ~3h ahead; tolerate up to 6h, clamp the rest).
            now = datetime.now(timezone.utc)
            if dt_utc > now and (dt_utc - now).total_seconds() > 6 * 3600:
                dt_utc = now
            return dt_utc.astimezone(ZoneInfo("Asia/Jerusalem")).strftime("%d/%m %H:%M")
        except Exception:
            pass
    return entry.get("published", "")


def _is_recent(published: str, hours: int = 48) -> bool:
    """Check if article is within last N hours."""
    if not published:
        return True
    try:
        dt = parsedate_to_datetime(published)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        # Clamp implausible future dates (Walla feeds label local time as GMT).
        now = datetime.now(timezone.utc)
        if dt > now and (dt - now).total_seconds() > 6 * 3600:
            dt = now
        age = now - dt
        return age.total_seconds() <= hours * 3600
    except Exception:
        return True


def _fmt_date(raw: str) -> str:
    """Convert RFC822 / ISO-8601 timestamps to 'DD/MM/YYYY HH:MM'."""
    if not raw:
        return ""
    try:
        dt = parsedate_to_datetime(raw)
        if dt is not None:
            return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return raw
