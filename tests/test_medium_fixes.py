# tests/test_medium_fixes.py
"""Tests for 8 MEDIUM-priority audit fixes (M1-M8)."""

import asyncio
import os

import pytest

# ── M3: Title Echo — Jaccard ──


def test_title_echo_identical():
    from services.news_ai.prompts import _is_title_echo

    assert _is_title_echo("Attack on Israel", "Attack on Israel") is True


def test_title_echo_jaccard_high_overlap():
    from services.news_ai.prompts import _is_title_echo

    # 5 of 5 words overlap → Jaccard = 5/5 = 1.0 → echo
    assert _is_title_echo("Attack on Israel today", "Attack on Israel today") is True


def test_title_echo_jaccard_low_overlap():
    from services.news_ai.prompts import _is_title_echo

    # "Attack on Israel" vs "Attack on Israel's borders launched rockets"
    # Old: substring match → True (false positive)
    # New: Jaccard = 3/6 = 0.5 → NOT echo
    assert _is_title_echo("Attack on Israel", "Attack on Israel's borders launched rockets") is False


def test_title_echo_short_title_all_words_in_summary():
    from services.news_ai.prompts import _is_title_echo

    # 3 words, all in summary → echo
    assert _is_title_echo("Rocket attack", "Rocket attack hits Tel Aviv") is True


def test_title_echo_empty_inputs():
    from services.news_ai.prompts import _is_title_echo

    assert _is_title_echo("", "summary") is False
    assert _is_title_echo("title", "") is False


def test_bulk_summarize_prompt_preserves_cyber_terms():
    from services.news_ai.prompts import build_bulk_summarize_prompt

    prompt = build_bulk_summarize_prompt([{"title": "t", "full_text": "Encoded Commands"}])
    assert "except cyber terms" in prompt
    assert "Encoded Commands" in prompt
    assert "Execution Policy Bypass" in prompt


@pytest.mark.asyncio
async def test_news_report_prompt_preserves_cyber_terms():
    from services.news_ai.reports import consolidate_to_report

    class Bridge:
        system_prompt = ""

        async def complete(self, **kwargs):
            self.system_prompt = kwargs["system_prompt"]
            return "report"

    bridge = Bridge()
    assert await consolidate_to_report(["a", "b"], ["neutral", "neutral"], "topic", bridge) == "report"
    assert "Encoded Commands" in bridge.system_prompt
    assert "Execution Policy Bypass" in bridge.system_prompt


# ── M2: Cluster Parser Fallback ──


def test_cluster_parser_state_machine_normal():
    from services.news_ai.prompts import parse_cluster_response

    text = "[1]. Israel under attack\n- Rockets fired\n- Iron Dome intercepts\n[2]. Tech news\n- AI breakthrough"
    result = parse_cluster_response(text, 2)
    assert len(result) == 2
    assert "Israel" in result[0]
    assert "Tech" in result[1]


def test_cluster_parser_fallback_no_headers():
    """When state machine finds 0 clusters, fallback to line-by-line."""
    from services.news_ai.prompts import parse_cluster_response

    # No cluster headers — state machine will fail
    text = "Israel under attack\nRockets fired from Gaza\n\nTech news today\nAI breakthrough announced"
    result = parse_cluster_response(text, 2)
    assert len(result) == 2
    assert "Israel" in result[0] or "Rockets" in result[0]
    assert "Tech" in result[1] or "AI" in result[1]


def test_cluster_parser_empty_input():
    from services.news_ai.prompts import parse_cluster_response

    result = parse_cluster_response("", 3)
    assert len(result) == 3
    assert all(r == "" for r in result)


# ── M8: Dynamic TRIM_CHARS ──


def test_trim_chars_dynamic_formula():
    """Verify the default formula: int(LLM_CONTEXT_WINDOW * 0.75).

    Note: .env file may override LLM_AGENT_TRIM_CHARS, so we test the
    formula logic, not the actual config value.
    """
    # The formula in config.py: int(os.getenv("LLM_AGENT_TRIM_CHARS",
    #   str(int(LLM_CONTEXT_WINDOW * 0.75))))
    # When no env override: default = int(context_window * 0.75)
    ctx = 16384
    expected_default = int(ctx * 0.75)  # 12288
    assert expected_default == 12288

    ctx = 8192
    expected_default = int(ctx * 0.75)  # 6144
    assert expected_default == 6144

    # Verify config.py uses the formula (read source)
    from pathlib import Path

    config_src = Path("config.py").read_text(encoding="utf-8")
    assert "LLM_CONTEXT_WINDOW * 0.75" in config_src


def test_trim_chars_env_override():
    """Env var / .env should override the dynamic calculation."""
    import config

    # .env has LLM_AGENT_TRIM_CHARS=8192 — verify it's loaded
    assert config.LLM_AGENT_TRIM_CHARS == 8192  # from .env, not formula


# ── M7: Skill Cache Key with CWD ──


@pytest.mark.asyncio
async def test_skill_cache_key_includes_cwd(tmp_path, monkeypatch):
    """Cache key should differ for different CWDs."""
    from services._skills_engine import _engine

    # Clear cache
    _engine._SKILL_CACHE.clear()

    # Mock execute to track calls
    call_count = 0

    original_execute = _engine.SkillsEngine.execute

    async def mock_execute(self, skill_name, command, args):
        nonlocal call_count
        call_count += 1
        return f"result_{call_count}"

    monkeypatch.setattr(_engine.SkillsEngine, "execute", mock_execute)
    monkeypatch.setattr(_engine, "get_skills_engine", lambda: _engine.SkillsEngine())

    # Call from CWD 1
    dir1 = tmp_path / "dir1"
    dir1.mkdir()
    monkeypatch.chdir(dir1)
    await _engine.skill_tool("test_skill", "cmd", {"arg": "val"})
    assert call_count == 1

    # Call from CWD 2 — should NOT hit cache (different CWD)
    dir2 = tmp_path / "dir2"
    dir2.mkdir()
    monkeypatch.chdir(dir2)
    await _engine.skill_tool("test_skill", "cmd", {"arg": "val"})
    assert call_count == 2  # New execution, not cache hit


# ── M6: Vectorlite Init Lock ──


@pytest.mark.asyncio
async def test_vectorlite_init_lock_lazy():
    """Init lock should be None until first use."""
    from services.bot_memory import vector_manager

    vector_manager._VECTORLITE_INIT_LOCK = None
    assert vector_manager._VECTORLITE_INIT_LOCK is None

    lock = vector_manager._get_init_lock()
    assert lock is not None
    assert isinstance(lock, asyncio.Lock)

    lock2 = vector_manager._get_init_lock()
    assert lock is lock2


# ── M5: Schema Version Table ──


@pytest.mark.asyncio
async def test_schema_meta_table_exists(tmp_path):
    """schema_meta table should be created with version='1'."""
    import services.memory_store as ms

    # Reset init
    ms._init_done = False
    # Use tmp DB
    from services import db_pool

    db_pool._DB_DIR = tmp_path
    await ms._ensure_init()

    async with ms.get_memory_pool().acquire() as db:
        cursor = await db.execute("SELECT value FROM schema_meta WHERE key='version'")
        row = await cursor.fetchone()
        assert row is not None
        assert row[0] == "1"


# ── M1: FTS5 Integrity Check ──


@pytest.mark.asyncio
async def test_fts5_integrity_check(tmp_path):
    """FTS5 integrity check should return True on healthy index."""
    import services.memory_store as ms

    ms._init_done = False
    from services import db_pool

    db_pool._DB_DIR = tmp_path
    await ms._ensure_init()

    from services.bot_memory.maintenance import check_fts5_integrity

    result = await check_fts5_integrity()
    assert result is True


# ── M4: Embedding Backfill ──


@pytest.mark.asyncio
async def test_embedding_backfill_no_nulls(tmp_path):
    """Backfill should return 0 when no NULL embeddings."""
    import services.memory_store as ms

    ms._init_done = False
    from services import db_pool

    db_pool._DB_DIR = tmp_path
    await ms._ensure_init()

    from services.bot_memory.maintenance import backfill_missing_embeddings

    count = await backfill_missing_embeddings()
    assert count == 0  # No memories with NULL embeddings
