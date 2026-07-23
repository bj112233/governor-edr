# tests/conftest.py
"""Shared fixtures for all test modules."""

import os
import sys

# Standalone scripts misdetected as pytest (no fixtures, meant for direct execution)
collect_ignore = [
    os.path.join(os.path.dirname(__file__), "test_comprehensive_skills.py"),
    os.path.join(os.path.dirname(__file__), "test_live_files.py"),
    os.path.join(os.path.dirname(__file__), "test_phrasing_variations.py"),
]

# Fail-fast environment guard: the project (and its C-dependent packages) is
# pinned to Python 3.12 (.venv). Running under any other interpreter (e.g. the
# py-launcher default 3.14) produces false-negative ImportErrors. Die loudly.
if sys.version_info[:2] != (3, 12):
    raise RuntimeError(
        f"Wrong interpreter: Python {sys.version.split()[0]}. "
        r"Run tests with .venv\Scripts\python.exe (Python 3.12)."
    )

import pytest

pytest_plugins = ("pytest_asyncio",)


# Auto-async mode: all async def tests run in an event loop without @pytest.mark.integration
# Mode AUTO means all async def test functions are treated as asyncio tests.
def pytest_configure(config):
    import asyncio

    config.option.asyncio_mode = "auto"


# ── Integration test auto-marking ───────────────────────────────────────────
# Files that hit real network, subprocess, live engine, or long retry backoffs.
# Adding a file here is cheaper than scattering `pytestmark` lines (which inflate
# LLOC and trip the file-length ratchet on already-large test modules).
_INTEGRATION_FILES = frozenset(
    {
        "test_agent_comprehensive.py",
        "test_agent_validation.py",
        "test_audit_fixes.py",
        "test_branch_rules_e2e.py",
        "test_callbacks_e2e.py",
        "test_chaos_engineering.py",
        "test_comprehensive_live.py",
        "test_comprehensive_skills.py",
        "test_coverage_batch4.py",
        "test_currency_detection.py",
        "test_fail_safe_e2e.py",
        "test_fsm_flow.py",
        "test_import_smoke.py",
        "test_initializer_executor_e2e.py",
        "test_intent_routing.py",
        "test_kill_room.py",
        "test_live_files.py",
        "test_medium_fixes.py",
        "test_monitor_integration.py",
        "test_news_digest_fire_and_forget.py",
        "test_phrasing_variations.py",
        "test_planner_smoke.py",
        "test_pre_hunt_enricher.py",
        "test_routing_integration.py",
        "test_skill_input_validation.py",
        "test_skill_smoke_all.py",
        "test_telegram_poll_retry.py",
        "test_tools_news_coverage.py",
        "test_visibility_triad.py",
    }
)


def pytest_collection_modifyitems(config, items):
    """Auto-mark integration tests by filename — no per-file boilerplate."""
    for item in items:
        # item.fspath is the full path; extract basename
        basename = os.path.basename(str(item.fspath))
        if basename in _INTEGRATION_FILES:
            item.add_marker(pytest.mark.integration)


@pytest.fixture(autouse=True)
def isolated_db(monkeypatch, tmp_path):
    """Force all SQLite operations to use a temporary DB file.

    Prevents tests from touching the real alert_history.db.
    Also resets the DBPool cache so stale connections from a previous
    event loop don't cause 'Event loop is closed' errors.
    """
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr("services.memory_db._init_done", False)

    # Patch bot_memory.schema pool reference.
    # Also patch every submodule that imported _pool at import time.
    try:
        import services.bot_memory.schema as _schema

        # Submodules that did `from .schema import _pool` hold their own ref.
        for mod_name in ("crud", "crud_search", "vector_manager", "episodic", "archive"):
            try:
                mod = __import__(f"services.bot_memory.{mod_name}", fromlist=[mod_name])
                if hasattr(mod, "_pool"):
                    monkeypatch.setattr(mod, "_pool", None)  # will be set below
            except ImportError:
                pass
    except ImportError:
        pass

    # Clear ALL cached pools AFTER patching all _DB_PATH references.
    # This ensures no code can re-create a pool pointing to the real DB.
    from services.db_pool import _POOLS, get_pool

    for key in list(_POOLS.keys()):
        _POOLS.pop(key, None)

    # Now create a fresh pool for the temp DB and distribute it.
    new_pool = get_pool(db_path, max_connections=4)

    # Sprint 5 Phase 2: memory tables moved to memory.db.
    # bot_memory.schema._pool must point to memory pool, not alerts pool.
    memory_path = str(tmp_path / "test_memory.db")
    metrics_path = str(tmp_path / "test_metrics.db")
    from services.db_pool import register_db_path

    register_db_path("alerts", db_path)
    register_db_path("memory", memory_path)
    register_db_path("metrics", metrics_path)
    memory_pool = get_pool(memory_path, max_connections=4)

    try:
        import services.bot_memory.schema as _schema

        monkeypatch.setattr(_schema, "_pool", memory_pool)
        for mod_name in ("crud", "crud_search", "vector_manager", "episodic", "archive"):
            try:
                mod = __import__(f"services.bot_memory.{mod_name}", fromlist=[mod_name])
                if hasattr(mod, "_pool"):
                    monkeypatch.setattr(mod, "_pool", memory_pool)
            except ImportError:
                pass
    except ImportError:
        pass

    # Reset MemoryService singleton's _initialized flag so it re-creates
    # tables in the new temp DB. The singleton persists across tests.
    try:
        from services.bot_memory.crud import get_memory_service

        svc = get_memory_service()
        svc._initialized = False
    except Exception:
        pass

    # Sprint 5: Patch metrics_db to use a temp metrics.db.
    # net_baseline + memory_db_baselines + osint_hunter all read from metrics.db.
    try:
        import services.metrics_db as _mdb

        monkeypatch.setattr(_mdb, "_METRICS_DB_PATH", metrics_path)
        monkeypatch.setattr(_mdb, "_init_done", False)
    except ImportError:
        pass

    # Sprint 5 Phase 2: Patch memory_store for memory.db isolation.
    try:
        import services.memory_store as _mstore

        monkeypatch.setattr(_mstore, "_MEMORY_DB_PATH", memory_path)
        monkeypatch.setattr(_mstore, "_init_done", False)
    except ImportError:
        pass


@pytest.fixture(autouse=True)
def stub_llm_embedding(monkeypatch):
    """Prevent network calls to the local LLM embedding endpoint.

    EmbeddingService.embed() delegates to LLMBridge.embed() which makes an
    HTTP call to 127.0.0.1:5001. In test environments without a running
    KoboldCpp/LM Studio instance, this hangs until timeout. Stub it to
    return deterministic zero vectors.
    """
    from services.llm_bridge.bridge import LLMBridge

    async def _fake_embed(self, texts):
        return [[0.0] * 8 for _ in texts]

    monkeypatch.setattr(LLMBridge, "embed", _fake_embed)


@pytest.fixture(autouse=True)
def stub_llm_complete(monkeypatch):
    """Prevent network calls to the local LLM completion endpoint.

    LLMBridge.complete() makes an HTTP call to 127.0.0.1:5001 with a 240s
    timeout. Any test that calls run_daily_summarization / agent_step /
    analyze_data without its own mock will hang the event loop and pollute
    the live server. This safety net returns a deterministic empty JSON
    response. Tests that set bridge._client themselves (e.g. context-overflow
    tests that inject a mock OpenAI client) bypass this stub and use their
    own mock via the original complete() implementation.
    """
    from unittest.mock import MagicMock

    from services.llm_bridge.bridge import LLMBridge

    _original_complete = LLMBridge.complete

    async def _fake_complete(self, *, system_prompt="", user_input="", **kw):
        # If the test injected its own _client (MagicMock), defer to original
        # so the test's mock chat.completions.create is actually called.
        if isinstance(getattr(self, "_client", None), MagicMock):
            return await _original_complete(self, system_prompt=system_prompt, user_input=user_input, **kw)
        return "{}"

    monkeypatch.setattr(LLMBridge, "complete", _fake_complete)


@pytest.fixture(autouse=True)
async def close_pools_after_test():
    """Close all DB pools after each test to prevent ResourceWarning.

    aiosqlite connections created during a test are not automatically
    closed when the event loop ends. This fixture ensures all pooled
    connections are properly closed, eliminating ResourceWarning.
    """
    yield
    from services.db_pool import close_all_pools

    await close_all_pools()
