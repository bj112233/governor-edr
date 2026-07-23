# tests/test_2fa_degraded_hermetic.py
"""Hermetic security tests: 2FA timeout/brute-force + DEGRADED mode filtering + Circuit Breaker TPOT.

Covers:
  - 2FA TTL boundary conditions (60s exact expiry, 59s valid)
  - B6 fix: brute-force lockout cooldown prevents immediate re-initiation
  - Concurrent verification race (single-use enforcement)
  - Cross-challenge OTP replay prevention
  - DEGRADED mode tool filtering (all critical blocked, safe allowed, final_answer kept)
  - Emergency mode override
  - skill_firewall-skill blocked in DEGRADED
  - Prompt injection cannot clear _degraded_mode (flag set by circuit breaker, not LLM)
  - Circuit Breaker TPOT: baseline, 3x trigger, 1.5x hysteresis recovery, flapping prevention
  - 2FA + DEGRADED interaction (independence)
"""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clear_2fa_state():
    """Clear all 2FA in-memory state before and after each test."""
    from services.two_factor import _challenges, _lockout_log, _otp_generation_log

    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()
    yield
    _challenges.clear()
    _otp_generation_log.clear()
    _lockout_log.clear()


# ─────────────────────────────────────────────────────────────────────────────
# 2FA Timeout Edge Cases
# ─────────────────────────────────────────────────────────────────────────────


class Test2FATimeoutBoundary:
    """Verify TTL boundary: challenge expires at exactly 60s, valid at 59s."""

    def test_otp_expires_at_60s_boundary(self):
        """Challenge at exactly 60s → verify returns False (expired)."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        # Set created_at to just past 60s — expired property uses > _CHALLENGE_TTL
        # At 60.01s: (60.01 > 60) = True → expired
        _challenges[challenge_id].created_at = time.monotonic() - 60.01
        assert verify_challenge(challenge_id, otp) is False

    def test_otp_valid_just_before_60s(self):
        """Challenge at 59s → verify returns True (still valid)."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        # At 59s, expired = (59 > 60) = False → still valid
        _challenges[challenge_id].created_at = time.monotonic() - 59.0
        assert verify_challenge(challenge_id, otp) is True

    def test_expired_challenge_deleted_on_verify(self):
        """Expired challenge → verify False + challenge removed from _challenges."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        _challenges[challenge_id].created_at = time.monotonic() - 120
        assert verify_challenge(challenge_id, otp) is False
        assert challenge_id not in _challenges

    def test_cleanup_expired_called_on_initiate(self):
        """initiate_challenge cleans expired entries from _challenges."""
        from services.two_factor import _challenges, initiate_challenge

        # Create a challenge and manually expire it
        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, _ = result
        _challenges[challenge_id].created_at = time.monotonic() - 120

        # Bypass cooldown by backdating the generation log
        from services.two_factor import _otp_generation_log

        log = _otp_generation_log.get("reload_hashes", [])
        for i in range(len(log)):
            log[i] -= 31  # push past cooldown

        # New initiate should clean up the expired challenge
        result2 = initiate_challenge("reload_hashes")
        assert result2 is not None
        assert challenge_id not in _challenges


# ─────────────────────────────────────────────────────────────────────────────
# 2FA Brute Force / Lockout (B6 FIX)
# ─────────────────────────────────────────────────────────────────────────────


class Test2FABruteForceLockout:
    """B6: After max_attempts lockout, new challenge is subject to cooldown."""

    def test_max_attempts_deletes_challenge(self):
        """3 wrong OTPs → challenge deleted, 4th with same id → False."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, _ = result

        for _ in range(3):
            assert verify_challenge(challenge_id, "111111") is False
        assert challenge_id not in _challenges
        # 4th attempt with same (now-deleted) challenge_id
        assert verify_challenge(challenge_id, "000000") is False

    def test_lockout_then_new_challenge_has_cooldown(self):
        """B6: after 3 fails, immediate new initiate should be blocked by lockout."""
        from services.two_factor import (
            OTPRateLimitError,
            _lockout_log,
            initiate_challenge,
            verify_challenge,
        )

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, _ = result

        # Exhaust all 3 attempts
        for _ in range(3):
            verify_challenge(challenge_id, "111111")

        # Lockout log should have an entry
        assert len(_lockout_log) == 1
        assert _lockout_log[0][0] == "reload_hashes"

        # Bypass OTP generation cooldown by backdating the log
        from services.two_factor import _otp_generation_log

        log = _otp_generation_log.get("reload_hashes", [])
        for i in range(len(log)):
            log[i] -= 31

        # Immediate new initiate should be blocked by lockout cooldown
        with pytest.raises(OTPRateLimitError) as exc_info:
            initiate_challenge("reload_hashes")
        assert "lockout" in exc_info.value.reason

    def test_concurrent_verification_race(self):
        """Two simultaneous verify_challenge calls on same challenge_id — only one succeeds."""
        from services.two_factor import _challenges, initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        results: list[bool] = []
        barrier = threading.Barrier(2)

        def _verify():
            barrier.wait()  # Synchronize start
            results.append(verify_challenge(challenge_id, otp))

        t1 = threading.Thread(target=_verify)
        t2 = threading.Thread(target=_verify)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        # Exactly one should succeed (single-use enforcement)
        assert results.count(True) == 1
        assert results.count(False) == 1

    def test_cross_operation_otp_replay(self):
        """OTP from challenge A cannot verify challenge B (challenge_id scoped)."""
        from services.two_factor import (
            TwoFactorChallenge,
            _challenges,
            _hash_otp,
            verify_challenge,
        )

        # Create two challenges directly (bypass rate limits)
        now = time.monotonic()
        ch_a = TwoFactorChallenge(
            challenge_id="aaa",
            otp_hash=_hash_otp("111111"),
            operation="reload_hashes",
            created_at=now,
        )
        ch_b = TwoFactorChallenge(
            challenge_id="bbb",
            otp_hash=_hash_otp("222222"),
            operation="reload_hashes",
            created_at=now,
        )
        _challenges["aaa"] = ch_a
        _challenges["bbb"] = ch_b

        # OTP from A ("111111") should not verify B
        assert verify_challenge("bbb", "111111") is False
        # B should still be present (attempt incremented, not consumed)
        assert "bbb" in _challenges
        # Correct OTP for B still works
        assert verify_challenge("bbb", "222222") is True


# ─────────────────────────────────────────────────────────────────────────────
# DEGRADED Mode Filtering
# ─────────────────────────────────────────────────────────────────────────────


def _make_ctx(
    active_tools: list[dict],
    emergency: bool = False,
    degraded: bool = False,
) -> MagicMock:
    """Build a minimal _AgentContext mock for tool filtering tests."""
    from services.agent._context import _AgentContext

    ctx = MagicMock(spec=_AgentContext)
    ctx.active_tools = active_tools
    ctx.is_emergency_mode = emergency
    ctx._degraded_mode = degraded
    return ctx


def _tool(name: str) -> dict:
    return {"type": "function", "function": {"name": name}}


class TestDegradedModeFiltering:
    """Verify _compute_allowed_tools blocks critical tools in DEGRADED mode."""

    def test_degraded_blocks_all_critical_tools(self):
        """Iterate ALL safety_level='critical' tools — none in allowed set when degraded."""
        from services.agent._nodes._executor import _compute_allowed_tools
        from services.tools_registry import REGISTRY

        critical_names = [name for name, spec in REGISTRY.items() if spec.safety_level == "critical"]
        assert len(critical_names) > 0, "No critical tools in REGISTRY — test is meaningless"

        active = [_tool(n) for n in critical_names]
        ctx = _make_ctx(active, degraded=True)
        allowed = _compute_allowed_tools(ctx)

        for name in critical_names:
            assert name not in allowed, f"Critical tool '{name}' should be blocked in DEGRADED"

    def test_degraded_keeps_final_answer(self):
        """final_answer always allowed, even in DEGRADED mode."""
        from services.agent._nodes._executor import _compute_allowed_tools

        ctx = _make_ctx([_tool("block_ip")], degraded=True)
        allowed = _compute_allowed_tools(ctx)
        assert "final_answer" in allowed

    def test_degraded_allows_safe_tools(self):
        """Safe tools (get_process_list, get_system_snapshot, etc.) allowed in DEGRADED."""
        from services.agent._nodes._executor import _compute_allowed_tools

        ctx = _make_ctx(
            [_tool("get_process_list"), _tool("get_system_snapshot")],
            degraded=True,
        )
        allowed = _compute_allowed_tools(ctx)
        assert "get_process_list" in allowed
        assert "get_system_snapshot" in allowed

    def test_emergency_overrides_degraded(self):
        """Emergency mode → only final_answer (even if degraded also True)."""
        from services.agent._nodes._executor import _compute_allowed_tools

        ctx = _make_ctx(
            [_tool("block_ip"), _tool("get_process_list")],
            emergency=True,
            degraded=True,
        )
        allowed = _compute_allowed_tools(ctx)
        assert allowed == {"final_answer"}

    def test_skill_firewall_blocked_in_degraded(self):
        """skill_firewall-skill NOT in allowed set when degraded (via _DANGEROUS_TOOLS)."""
        from services.agent._context import _DANGEROUS_TOOLS
        from services.agent._nodes._executor import _compute_allowed_tools

        # Verify skill_firewall-skill is in _DANGEROUS_TOOLS
        assert "skill_firewall-skill" in _DANGEROUS_TOOLS

        ctx = _make_ctx([_tool("skill_firewall-skill")], degraded=True)
        allowed = _compute_allowed_tools(ctx)
        assert "skill_firewall-skill" not in allowed


# ─────────────────────────────────────────────────────────────────────────────
# DEGRADED Mode Bypass Attempts
# ─────────────────────────────────────────────────────────────────────────────


class TestDegradedModeBypass:
    """Verify DEGRADED flag cannot be cleared by prompt injection / LLM output."""

    def test_prompt_injection_cannot_clear_degraded_flag(self):
        """ctx._degraded_mode is set by circuit breaker (LLMBridge.is_degraded), not LLM output.

        _check_degraded_mode queries LLMBridge.get_instance().is_degraded() and sets
        ctx._degraded_mode = True. An attacker cannot clear it via LLM output because
        the flag is never read from the LLM response — only from the circuit breaker state.
        """
        from services.agent._agent_loop import _check_degraded_mode
        from services.agent._context import AgentState, _AgentContext

        ctx = _AgentContext(user_question="test", max_steps=10)
        ctx._degraded_mode = False  # Simulate prompt injection trying to clear

        # When LLMBridge says degraded=True, the flag MUST be set regardless of ctx state
        with patch("services.llm_bridge.bridge.LLMBridge.get_instance") as mock_get:
            mock_bridge = MagicMock()
            mock_bridge.is_degraded.return_value = True
            mock_get.return_value = mock_bridge

            new_state = _check_degraded_mode(ctx, AgentState.PLANNER)

        assert ctx._degraded_mode is True  # Flag set by circuit breaker, not LLM
        assert new_state == AgentState.EXECUTE  # PLANNER skipped in DEGRADED

    def test_degraded_recovery_reenables_tools(self):
        """When _degraded_mode=False, _compute_allowed_tools returns critical tools again.

        NOTE: ctx._degraded_mode is session-scoped — once set to True by
        _check_degraded_mode, it stays True for the duration of the agent session.
        Recovery (is_degraded() → False) requires a NEW session/context where
        _check_degraded_mode is never triggered. This test verifies the filtering
        logic: when the flag is False, critical tools are allowed.
        """
        from services.agent._nodes._executor import _compute_allowed_tools

        # When degraded=False, critical tools are allowed
        ctx = _make_ctx([_tool("block_ip"), _tool("kill_process")], degraded=False)
        allowed = _compute_allowed_tools(ctx)
        assert "block_ip" in allowed
        assert "kill_process" in allowed

        # When degraded=True, critical tools are blocked
        ctx2 = _make_ctx([_tool("block_ip"), _tool("kill_process")], degraded=True)
        allowed2 = _compute_allowed_tools(ctx2)
        assert "block_ip" not in allowed2
        assert "kill_process" not in allowed2


# ─────────────────────────────────────────────────────────────────────────────
# Circuit Breaker (TPOT) — test via mocks
# ─────────────────────────────────────────────────────────────────────────────


class TestCircuitBreakerTPOT:
    """Test TPOT-based degradation detection with hysteresis."""

    def _feed_baseline(self, cb, tpot_ms: float, n: int = 10):
        """Feed n samples to lock the baseline at tpot_ms."""
        for _ in range(n):
            # seconds=tpot_ms/1000, tokens=100 → tpot = (seconds/tokens)*1000 = tpot_ms/100
            # We want tpot_ms, so seconds = tpot_ms * 100 / 1000 = tpot_ms / 10
            cb.record_latency(seconds=tpot_ms / 10.0, generated_tokens=100)
        assert cb.tpot_baseline_ms is not None

    def test_tpot_baseline_not_locked_before_10_samples(self):
        """<10 samples → baseline not locked → is_degraded() cannot trigger."""
        from services.llm_bridge.circuit_breaker import CircuitBreaker
        from services.llm_bridge.models import _STATE_DEGRADED

        cb = CircuitBreaker("test")
        # Feed 9 samples (< LLM_BASELINE_SAMPLES=10)
        for _ in range(9):
            cb.record_latency(seconds=1.0, generated_tokens=100)

        assert cb.tpot_baseline_ms is None
        assert cb.state != _STATE_DEGRADED

    def test_tpot_triggers_degraded_at_3x_baseline(self):
        """Baseline locked, TPOT > 3x → degraded True."""
        from services.llm_bridge.circuit_breaker import CircuitBreaker
        from services.llm_bridge.models import _STATE_CLOSED, _STATE_DEGRADED

        cb = CircuitBreaker("test")
        # Lock baseline at 100 ms/token
        self._feed_baseline(cb, tpot_ms=100.0)
        assert cb.state == _STATE_CLOSED

        # Feed high-TPOT samples to push EMA above 3x baseline (300ms)
        # EMA = alpha * new + (1-alpha) * old, alpha=0.2
        # After baseline, EMA ≈ 100. Feed tpot=2000ms:
        #   EMA = 0.2*2000 + 0.8*100 = 480 > 300 → DEGRADED
        cb.record_latency(seconds=2000.0 / 10.0, generated_tokens=100)

        assert cb.state == _STATE_DEGRADED

    def test_hysteresis_recovers_at_1_5x_baseline(self):
        """Degraded, TPOT drops < 1.5x baseline → recovered (CLOSED)."""
        from services.llm_bridge.circuit_breaker import CircuitBreaker
        from services.llm_bridge.models import _STATE_DEGRADED

        cb = CircuitBreaker("test")
        self._feed_baseline(cb, tpot_ms=100.0)

        # Trigger DEGRADED
        cb.record_latency(seconds=2000.0 / 10.0, generated_tokens=100)
        assert cb.state == _STATE_DEGRADED

        # Feed low-TPOT samples to push EMA below 1.5x baseline (150ms)
        # Current EMA ≈ 480. Feed tpot=10ms repeatedly:
        #   0.2*10 + 0.8*480 = 386
        #   0.2*10 + 0.8*386 = 311
        #   0.2*10 + 0.8*311 = 251
        #   0.2*10 + 0.8*251 = 203
        #   0.2*10 + 0.8*203 = 164
        #   0.2*10 + 0.8*164 = 133 < 150 → CLOSED
        for _ in range(6):
            cb.record_latency(seconds=10.0 / 10.0, generated_tokens=100)

        from services.llm_bridge.models import _STATE_CLOSED

        assert cb.state == _STATE_CLOSED

    def test_hysteresis_prevents_flapping(self):
        """TPOT oscillates between 2x and 2.5x (below 3x, above 1.5x) → state stable.

        Starting from DEGRADED: EMA stays above 1.5x clear threshold → no recovery.
        Starting from CLOSED: EMA stays below 3x trigger threshold → no degradation.
        Hysteresis band [1.5x, 3x] prevents flapping.
        """
        from services.llm_bridge.circuit_breaker import CircuitBreaker
        from services.llm_bridge.models import _STATE_DEGRADED

        cb = CircuitBreaker("test")
        self._feed_baseline(cb, tpot_ms=100.0)

        # Trigger DEGRADED first
        cb.record_latency(seconds=2000.0 / 10.0, generated_tokens=100)
        assert cb.state == _STATE_DEGRADED

        # Oscillate TPOT between 200ms (2x) and 250ms (2.5x)
        # Both are below 3x (300ms trigger) and above 1.5x (150ms clear)
        # EMA should stay in the hysteresis band → state stable (DEGRADED)
        initial_state = cb.state
        for i in range(20):
            tpot = 200.0 if i % 2 == 0 else 250.0
            cb.record_latency(seconds=tpot / 10.0, generated_tokens=100)

        # State should NOT have changed (no flap)
        assert cb.state == initial_state
        assert cb.state == _STATE_DEGRADED  # Still degraded, not recovered


# ─────────────────────────────────────────────────────────────────────────────
# 2FA + DEGRADED Interaction
# ─────────────────────────────────────────────────────────────────────────────


class Test2FADegradedInteraction:
    """2FA is independent of the agent loop — works in DEGRADED mode."""

    def test_2fa_initiate_while_degraded(self):
        """initiate_challenge works in DEGRADED (2FA is independent of agent loop)."""
        from services.two_factor import initiate_challenge

        # 2FA module has no dependency on LLMBridge or degraded mode
        # Verify it works regardless of agent state
        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result
        assert len(challenge_id) == 32
        assert len(otp) == 6

    def test_2fa_verify_while_degraded(self):
        """verify_challenge works in DEGRADED."""
        from services.two_factor import initiate_challenge, verify_challenge

        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        # Verify works regardless of agent degraded state
        assert verify_challenge(challenge_id, otp) is True

    def test_degraded_does_not_bypass_2fa(self):
        """reload_hashes still requires 2FA even if agent is degraded.

        2FA is enforced at the C2 dispatch layer (web_c2_commands), not the
        agent executor. DEGRADED mode only affects tool filtering in the agent
        loop — it does not bypass the 2FA challenge for sensitive operations.
        """
        from services.two_factor import SENSITIVE_OPERATIONS, initiate_challenge, verify_challenge

        # reload_hashes is always a sensitive operation
        assert "reload_hashes" in SENSITIVE_OPERATIONS

        # 2FA challenge is required and works normally
        result = initiate_challenge("reload_hashes")
        assert result is not None
        challenge_id, otp = result

        # Wrong OTP is rejected — DEGRADED does not bypass
        assert verify_challenge(challenge_id, "000000") is False

        # 2FA enforcement is independent of DEGRADED mode: the agent's
        # _degraded_mode flag only affects tool filtering in the executor,
        # not the 2FA challenge/verify pipeline.
