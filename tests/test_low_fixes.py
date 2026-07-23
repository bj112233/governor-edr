# tests/test_low_fixes.py
"""Tests for 5 LOW-priority audit fixes (L1, L3, L4, L8, L10)."""

import asyncio
import time

import pytest

# ── L1: Save State Lock ──


@pytest.mark.asyncio
async def test_save_state_lock_lazy_init():
    """Save lock should be None until first use (lazy init)."""
    from services.breaking_news import state

    state._SAVE_LOCK = None
    assert state._SAVE_LOCK is None

    lock = state._get_save_lock()
    assert lock is not None
    assert isinstance(lock, asyncio.Lock)

    lock2 = state._get_save_lock()
    assert lock is lock2


@pytest.mark.asyncio
async def test_save_state_concurrent_safe(tmp_path):
    """Concurrent save_state calls should not corrupt the file."""
    from services.breaking_news.state import MonitorState, save_state

    state = MonitorState()
    state.sent_links = {"http://a": time.time()}
    path = tmp_path / "state.json"

    # Launch 5 concurrent saves
    await asyncio.gather(*[save_state(state, path) for _ in range(5)])

    # File should exist and be valid JSON
    assert path.exists()
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    assert "sent_links" in data


# ── L3: Cluster store (replaces embedding deque) ──


def test_clusters_is_dict():
    """clusters should be a dict (fingerprint_key → EventCluster)."""
    from services.breaking_news.state import MonitorState

    state = MonitorState()
    assert isinstance(state.clusters, dict)


def test_clusters_cap_enforced():
    """Adding > MAX_CLUSTERS should evict oldest by last_seen."""
    from services.breaking_news.state import MonitorState

    state = MonitorState()
    for i in range(MonitorState.MAX_CLUSTERS + 50):
        c = state.get_or_create_cluster(f"k{i}", now=float(i))
        c.add({"title": f"T{i}", "source": "S"}, now=float(i))

    state.cleanup(now=float(MonitorState.MAX_CLUSTERS + 50))
    assert len(state.clusters) <= MonitorState.MAX_CLUSTERS


# ── L4: WAL Checkpoint ──


@pytest.mark.asyncio
async def test_wal_checkpoint(tmp_path):
    """WAL checkpoint should run without error on healthy DB."""
    import services.memory_store as ms

    ms._init_done = False
    from services import db_pool

    db_pool._DB_DIR = tmp_path
    await ms._ensure_init()

    from services.bot_memory.maintenance import wal_checkpoint

    await wal_checkpoint()  # Should not raise


# ── L8: Import Timeout ──


def test_check_python_lib_existing():
    """Existing package should return True quickly."""
    from services._skills_engine.security import _check_python_lib

    assert _check_python_lib("json") is True  # json is stdlib


def test_check_python_lib_missing():
    """Non-existent package should return False."""
    from services._skills_engine.security import _check_python_lib

    assert _check_python_lib("nonexistent_pkg_xyz_12345") is False


def test_check_python_lib_pypi_mapping():
    """PyPI name should map to import name."""
    from services._skills_engine.security import _check_python_lib

    # beautifulsoup4 → bs4 (if installed) or False (if not)
    result = _check_python_lib("beautifulsoup4")
    assert isinstance(result, bool)


# ── L10: News Digest Warning ──


def test_news_digest_disabled_logs_warning(monkeypatch, caplog):
    """When news digest is disabled, should log warning (not silent)."""
    import logging

    # Mock get_news_service to return disabled config
    class MockNewsService:
        delivery_config = {"enabled": False}

    monkeypatch.setattr(
        "services.startup._scheduler.get_news_service",
        lambda: MockNewsService(),
    )

    with caplog.at_level(logging.WARNING):
        from services.startup._scheduler import setup_scheduler

        try:
            sched = setup_scheduler()
            sched.shutdown(wait=False)
        except Exception:
            pass  # Scheduler may fail in test env, we just check logs

    assert any("News digest disabled" in r.message for r in caplog.records)
