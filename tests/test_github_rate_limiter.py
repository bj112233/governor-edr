"""Tests for GitHub rate limiter — dual-layer protection."""

import asyncio
import time

import pytest

from services.github_rate_limiter import GitHubRateLimiter


class TestGitHubRateLimiter:
    @pytest.mark.asyncio
    async def test_min_interval_enforced(self):
        """Layer 2: consecutive acquires must wait min_interval."""
        limiter = GitHubRateLimiter(max_calls=10, window=60.0, min_interval=0.2)
        t0 = time.monotonic()
        await limiter.acquire()
        await limiter.acquire()
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.15, f"Expected >=0.15s gap, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_rate_limit_throttles(self):
        """Layer 1: exceeding max_calls in window triggers throttle."""
        limiter = GitHubRateLimiter(max_calls=2, window=0.5, min_interval=0.0)
        await limiter.acquire()
        await limiter.acquire()
        # 3rd call should wait ~0.5s for window to slide
        t0 = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.25, f"Expected throttle, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_lock_prevents_race(self):
        """Concurrent acquires are serialized via lock."""
        limiter = GitHubRateLimiter(max_calls=5, window=60.0, min_interval=0.1)
        # Fire 3 concurrently
        t0 = time.monotonic()
        await asyncio.gather(limiter.acquire(), limiter.acquire(), limiter.acquire())
        elapsed = time.monotonic() - t0
        # 3 acquires with 0.1s min interval = at least 0.15s total (margin for CI)
        assert elapsed >= 0.15, f"Expected serialization, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_timestamps_cleaned(self):
        """Old timestamps outside window are cleaned."""
        limiter = GitHubRateLimiter(max_calls=10, window=0.3, min_interval=0.0)
        await limiter.acquire()
        await asyncio.sleep(0.4)  # wait past window
        await limiter.acquire()
        # Only 1 timestamp should remain (the recent one)
        assert len(limiter._timestamps) == 1
