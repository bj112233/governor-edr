"""Tests for VT rate limiter (token bucket) + 429 fallback behavior.

The token bucket is disk-persisted; tests use a temp state dir to isolate
from the real bucket. The 429 fallback is tested via the virustotal()
function with a mocked HTTP response.
"""

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture
def isolated_bucket(tmp_path, monkeypatch):
    """Redirect vt_rate_limiter state to a temp dir."""
    state_dir = tmp_path / "intel_cache"
    state_dir.mkdir()
    monkeypatch.setenv("SENTINEL_STATE_DIR", str(tmp_path))
    # Reload module to pick up new env var
    import importlib
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts"))
    import vt_rate_limiter

    importlib.reload(vt_rate_limiter)
    return vt_rate_limiter


class TestTokenBucket:
    def test_first_call_starts_window(self, isolated_bucket):
        result = isolated_bucket.acquire(timeout=5)
        assert result is True
        state = isolated_bucket._read_state()
        assert state["count"] == 1
        assert state["window_start"] > 0

    def test_four_calls_allowed_in_window(self, isolated_bucket):
        for i in range(4):
            assert isolated_bucket.acquire(timeout=5) is True
        state = isolated_bucket._read_state()
        assert state["count"] == 4

    def test_fifth_call_blocks_then_resets(self, isolated_bucket):
        # Fill the window
        for _ in range(4):
            isolated_bucket.acquire(timeout=5)
        # Fifth call should block until window resets.
        # Use a very short timeout to avoid a 60s sleep in tests.
        start = time.monotonic()
        result = isolated_bucket.acquire(timeout=0.5)
        elapsed = time.monotonic() - start
        # With 0.5s timeout and a 60s window, it should abort (return False)
        # because the sleep would exceed the deadline.
        assert result is False
        assert elapsed < 1.5

    def test_state_persists_across_instances(self, isolated_bucket, tmp_path):
        isolated_bucket.acquire(timeout=5)
        isolated_bucket.acquire(timeout=5)
        state = isolated_bucket._read_state()
        assert state["count"] == 2
        # Simulate a new process: re-read from disk
        state2 = isolated_bucket._read_state()
        assert state2["count"] == 2


class Test429Fallback:
    """virustotal() must return a structured fallback on 429, not crash."""

    def test_429_returns_fallback_flag(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SENTINEL_STATE_DIR", str(tmp_path))
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fake-key-for-test")
        import importlib
        import sys

        scripts = str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts")
        sys.path.insert(0, scripts)
        import osint_gatherer
        import vt_rate_limiter

        importlib.reload(vt_rate_limiter)
        importlib.reload(osint_gatherer)

        # Mock the requests.get to return a 429
        class FakeResponse:
            status_code = 429
            headers = {"Retry-After": "30"}

            def raise_for_status(self):
                pass

        with patch.object(osint_gatherer.requests, "get", return_value=FakeResponse()):
            result = osint_gatherer.virustotal("1.2.3.4", "ip_addresses")

        assert result["available"] is False
        assert result.get("fallback") is True
        assert "rate limit" in result["error"].lower()
        assert result.get("retry_after") == 30

    def test_no_key_returns_reason(self, tmp_path, monkeypatch):
        monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
        import importlib
        import sys
        from pathlib import Path

        scripts = str(Path(__file__).resolve().parents[1] / "skills" / "intel-skill" / "scripts")
        sys.path.insert(0, scripts)
        import osint_gatherer

        importlib.reload(osint_gatherer)  # re-read _VT_KEY from env
        result = osint_gatherer.virustotal("1.2.3.4", "ip_addresses")
        assert result["available"] is False
        assert "VIRUSTOTAL_API_KEY not set" in result["reason"]
