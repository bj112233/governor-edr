# services/memory_summarizer.py
"""Periodic summarization job for long-term user memory (Memory Tiering).

Background APScheduler job (daily 03:00) that:
1. Pulls last 24h conversations from memory.db.
2. Loads the previous user profile (if any).
3. Prompts the LLM to MERGE previous profile + new conversations.
4. Persists updated profile_json to user_profiles table.
5. Exposes get_latest_user_profile() for core.py injection.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import aiosqlite

from services.agent._json_utils import _brace_depth, _strip_trailing_commas
from services.embedding_service import get_embedding_service
from services.llm_bridge import LLMBridge
from services.memory_store import _ensure_init as _memory_ensure_init
from services.memory_store import get_memory_pool

logger = logging.getLogger(__name__)

# ── DB Schema ────────────────────────────────────────────────────────────────


async def _ensure_user_profiles_table() -> None:
    """Delegate to memory_store (Sprint 5 Phase 2)."""
    await _memory_ensure_init()


# ── Fetch helpers ────────────────────────────────────────────────────────────


async def _fetch_last_24h_conversations() -> list[str]:
    """Return list of "role: content" strings from last 24h."""
    rows: list[str] = []
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            """
            SELECT role, content
            FROM conversations
            WHERE timestamp >= datetime('now', '-1 day')
            ORDER BY timestamp ASC
            """
        )
        async for row in cursor:
            rows.append(f"{row[0]}: {row[1]}")
    return rows


async def _fetch_latest_profile() -> dict | None:
    """Return latest user_profile as dict, or None if table empty / malformed."""
    async with get_memory_pool().acquire() as db:
        cursor = await db.execute(
            """
            SELECT profile_json FROM user_profiles
            ORDER BY id DESC LIMIT 1
            """
        )
        row = await cursor.fetchone()
    if not row:
        return None
    try:
        data = json.loads(row[0])
    except (json.JSONDecodeError, ValueError):
        return None
    # Normalize: legacy entries may be a list due to old parser bugs
    if isinstance(data, list):
        data = next((item for item in data if isinstance(item, dict)), None)
    if not isinstance(data, dict):
        return None
    return data


# ── LLM Prompting ────────────────────────────────────────────────────────────


_SUMMARY_SYSTEM_PROMPT = (
    "You are a user-profile extraction engine. "
    "Merge the existing profile with new conversations. "
    "Return ONLY a raw JSON object (no markdown ticks, no commentary)."
)


def _build_summary_prompt(
    previous_profile: dict | None,
    new_conversations: list[str],
) -> str:
    """Build merge prompt: previous profile + new 24h conversations."""
    previous = json.dumps(previous_profile, ensure_ascii=False, indent=2) if previous_profile else "{}"
    new_text = "\n\n".join(new_conversations)

    return (
        "Here is the user's current profile:\n"
        f"{previous}\n\n"
        "Here are the last 24 hours of conversations:\n"
        f"{new_text}\n\n"
        "Instructions:\n"
        "1. Merge the existing profile with new insights from conversations.\n"
        "2. Preserve existing keys; add new ones only if supported by new evidence.\n"
        "3. Update values if new conversations contradict old ones.\n"
        "4. Return ONLY a raw JSON object with these keys:\n"
        "   - preferences: list of user preferences\n"
        "   - topics: list of frequent topics\n"
        "   - patterns: list of behavioral patterns\n"
        "   - entities: list of named entities the user cares about\n"
        "\nJSON:"
    )


# ── JSON Safety (extracted to memory_summarizer_json.py) ─────────────────────
from services.memory_summarizer_json import _safe_parse_json, _strip_markdown_ticks  # noqa: E402,F401

# ── Profile normalization (regression guard + dedup) ─────────────────────────

# Canonical schema the LLM is instructed to produce. Carried over from prev
# when the LLM drops them (observed 2026-07-16: id=27 had 4 keys, id=28 had
# only `preferences` with 47 duplicates).
_PROFILE_KEYS: tuple[str, ...] = ("preferences", "topics", "patterns", "entities")


def _dedup_preserve_order(items: list[str]) -> list[str]:
    """Remove duplicates from a string list while preserving first-seen order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            continue
        key = item.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _normalize_profile(new: dict, previous: dict | None) -> dict:
    """Defensive post-LLM normalization.

    1. Schema regression guard: carry over any canonical key the LLM dropped
       from `previous` (prevents silent field loss like id=27→id=28).
    2. Dedup each list[str] field preserving order (prevents the 47-duplicate
       bloat observed in id=28).
    3. Drop unknown keys (keeps the persisted schema canonical).
    """
    previous = previous or {}
    normalized: dict[str, list[str]] = {}
    for key in _PROFILE_KEYS:
        new_val = new.get(key)
        prev_val = previous.get(key)

        # Regression guard: LLM dropped the key entirely → reuse previous.
        if new_val is None and prev_val is not None:
            logger.warning(
                "[MemorySummarizer] LLM dropped key %r; carrying over %d entries from previous profile.",
                key,
                len(prev_val) if isinstance(prev_val, list) else 1,
            )
            src = prev_val
        elif new_val is None:
            src = []
        else:
            src = new_val

        # Coerce non-list (str/dict) into a single-element list for robustness.
        if isinstance(src, str):
            src = [src]
        elif not isinstance(src, list):
            src = []

        deduped = _dedup_preserve_order([x for x in src if isinstance(x, (str,))])
        if len(deduped) < len(src):
            logger.warning(
                "[MemorySummarizer] Deduped %r: %d → %d entries.",
                key,
                len(src),
                len(deduped),
            )
        normalized[key] = deduped

    return normalized


# ── Main entrypoint ──────────────────────────────────────────────────────────


async def run_daily_summarization() -> None:
    """Fetch last 24h conversations, merge with previous profile, save."""
    await _ensure_user_profiles_table()

    # RESOURCE OPTIMIZATION: skip if no new conversations
    conversations = await _fetch_last_24h_conversations()
    if not conversations:
        logger.info("[MemorySummarizer] No new conversations in last 24h; skipping.")
        return

    # INPUT BLOAT CONTROL: cap to 15 recent conversations to reduce prefill load
    original_count = len(conversations)
    if original_count > 15:
        conversations = conversations[-15:]
        logger.info("[MemorySummarizer] Capped to 15/%d recent conversations.", original_count)

    logger.info("[MemorySummarizer] %d conversations to summarize.", len(conversations))

    previous_profile = await _fetch_latest_profile()
    prompt = _build_summary_prompt(previous_profile, conversations)

    # Call LLM — timeout budget aligned with scheduler (480s per attempt, 500s global)
    # NOTE: response_format=json_object MUST NOT be set — KoboldCpp 4B deterministically
    # collapses to "not json at all {{{" under grammar enforcement (6 failures on
    # 2026-07-04). See lessons.md 2026-06-16 + test_planner_smoke regression guard.
    # _safe_parse_json below already handles markdown/array/truncation repair.
    try:
        bridge = LLMBridge.get_instance()
        raw = await bridge.complete(
            system_prompt=_SUMMARY_SYSTEM_PROMPT,
            user_input=prompt,
            max_tokens=2048,  # profile grew to 33+ entities; 1024 truncated mid-string (2026-07-09)
            timeout=480.0,  # 2048 tokens @ 186ms/tok ≈ 381s + 30s prefill + 20s buffer ≈ 431s
        )
    except Exception as exc:
        logger.warning("[MemorySummarizer] LLM call failed: %s", exc)
        return

    # JSON SAFETY: strip markdown ticks + parse
    profile = _safe_parse_json(raw)
    if profile is None:
        logger.warning(
            "[MemorySummarizer] LLM returned unparseable JSON (len=%d). Raw: %.500s",
            len(raw),
            raw,
        )
        # Persist full raw for post-mortem debugging
        debug_path = (
            Path(__file__).parent.parent / "logs" / f"memory_summarizer_fail_{datetime.now():%Y%m%d_%H%M%S}.txt"
        )
        try:
            debug_path.write_text(raw, encoding="utf-8")
            logger.info("[MemorySummarizer] Full raw response written to %s", debug_path)
        except OSError:
            pass
        return

    # Persist
    profile = _normalize_profile(profile, previous_profile)
    profile_json = json.dumps(profile, ensure_ascii=False, indent=2)
    async with get_memory_pool().acquire() as db:
        await db.execute(
            "INSERT INTO user_profiles (profile_json) VALUES (?)",
            (profile_json,),
        )
        await db.commit()

    logger.info("[MemorySummarizer] User profile updated (v%d).", (previous_profile or {}).get("version", 0) + 1)


# ── Public interface for core.py injection ─────────────────────────────────


async def get_latest_user_profile() -> str:
    """Return the latest user profile JSON string, or empty string if none."""
    await _ensure_user_profiles_table()
    profile = await _fetch_latest_profile()
    if profile is None:
        return ""
    return json.dumps(profile, ensure_ascii=False)
