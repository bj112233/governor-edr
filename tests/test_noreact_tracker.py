# tests/test_noreact_tracker.py
"""No-ReAct frequency tracker — auto-injection of aggressive format directive.

Verifies:
  - Events counted in sliding window
  - Threshold triggers directive activation
  - Window expiry deactivates directive (auto-recovery)
  - reset() clears state
  - Parser hook records events
  - Initializer injects directive when active
"""

import time

import pytest

from services.agent._noreact_tracker import (
    _AGGRESSIVE_DIRECTIVE,
    _THRESHOLD,
    _WINDOW_SECONDS,
    get_directive,
    get_window_count,
    is_directive_active,
    record_no_react,
    reset,
)


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset tracker before and after each test."""
    reset()
    yield
    reset()


# ── Basic counting ────────────────────────────────────────────────


class TestBasicCounting:
    def test_initial_state_inactive(self):
        assert get_window_count() == 0
        assert not is_directive_active()
        assert get_directive() is None

    def test_record_increments_count(self):
        assert record_no_react() == 1
        assert record_no_react() == 2
        assert get_window_count() == 2

    def test_threshold_is_three(self):
        assert _THRESHOLD == 3


# ── Threshold activation ──────────────────────────────────────────


class TestThresholdActivation:
    def test_below_threshold_no_directive(self):
        for _ in range(_THRESHOLD - 1):
            record_no_react()
        assert not is_directive_active()
        assert get_directive() is None

    def test_at_threshold_directive_active(self):
        for _ in range(_THRESHOLD):
            record_no_react()
        assert is_directive_active()
        directive = get_directive()
        assert directive is not None
        assert "CRITICAL FORMAT DIRECTIVE" in directive
        assert "ReAct" in directive
        assert "Thought:" in directive
        assert "Action:" in directive

    def test_above_threshold_still_active(self):
        for _ in range(_THRESHOLD + 2):
            record_no_react()
        assert is_directive_active()

    def test_directive_is_aggressive(self):
        for _ in range(_THRESHOLD):
            record_no_react()
        directive = get_directive()
        assert "No exceptions" in directive
        assert "Do NOT output free-form text" in directive


# ── Sliding window expiry ─────────────────────────────────────────


class TestSlidingWindowExpiry:
    def test_window_is_15_minutes(self):
        assert _WINDOW_SECONDS == 900

    def test_expired_events_evicted(self):
        """Events older than window should not count."""
        # Record events with old timestamps by manipulating the deque directly
        from services.agent._noreact_tracker import _state

        old_time = time.monotonic() - _WINDOW_SECONDS - 10
        with _state.lock:
            for _ in range(_THRESHOLD):
                _state.events.append(old_time)

        # Now record a fresh event — should evict old ones
        record_no_react()
        assert get_window_count() == 1
        assert not is_directive_active()

    def test_auto_recovery_when_window_empties(self):
        """Directive deactivates when events expire."""
        from services.agent._noreact_tracker import _state

        # Fill with events that are about to expire
        near_expiry = time.monotonic() - _WINDOW_SECONDS + 1
        with _state.lock:
            for _ in range(_THRESHOLD):
                _state.events.append(near_expiry)

        assert is_directive_active()  # still in window

        # Wait for expiry
        time.sleep(1.1)
        assert not is_directive_active()  # auto-recovered
        assert get_directive() is None


# ── reset() ───────────────────────────────────────────────────────


class TestReset:
    def test_reset_clears_all_events(self):
        for _ in range(_THRESHOLD + 1):
            record_no_react()
        assert is_directive_active()
        reset()
        assert get_window_count() == 0
        assert not is_directive_active()


# ── Parser integration ────────────────────────────────────────────


class TestParserIntegration:
    def test_parser_records_on_no_react(self):
        """parse_react_response should record a No-ReAct event when salvaging."""
        from services.agent._react_parser import parse_react_response

        # Free-form text without ReAct structure
        free_text = "This is a free-form answer without any ReAct structure at all."
        result = parse_react_response(free_text)
        assert result["tool_calls"][0]["name"] == "final_answer"
        assert get_window_count() == 1

    def test_parser_does_not_record_on_valid_react(self):
        """Valid ReAct output should NOT trigger the tracker."""
        from services.agent._react_parser import parse_react_response

        react_text = "Thought: I need to check the system.\nAction: get_system_snapshot\nAction Input: {}"
        parse_react_response(react_text)
        assert get_window_count() == 0

    def test_three_collapses_activate_directive(self):
        """Three No-ReAct events → directive active."""
        from services.agent._react_parser import parse_react_response

        for i in range(_THRESHOLD):
            parse_react_response(f"Free-form answer number {i} without ReAct structure.")
        assert is_directive_active()
        assert get_directive() is not None


# ── Thread safety ─────────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_records_safe(self):
        """Concurrent record calls should not corrupt state."""
        import threading

        def _worker():
            for _ in range(10):
                record_no_react()

        threads = [threading.Thread(target=_worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert get_window_count() == 50
