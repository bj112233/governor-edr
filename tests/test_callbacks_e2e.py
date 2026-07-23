# tests/test_callbacks_e2e.py
"""E2E tests for telegram/callbacks.py — HITL remediation callback handler.

Covers all branches: block/kill/ignore/auto-block/auto-kill, degraded mode,
PID recycling, closed-loop learning, message editing, error paths.
All tests use mocks — NO real DB, no real psutil, no real netsh.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

_ROOT = str(Path(__file__).resolve().parents[1])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from services.alert_dispatcher import ACTIVE_ALERTS_CACHE
from services.telegram.callbacks import (
    _AUTO_BLOCK_PREFIX,
    _AUTO_KILL_PREFIX,
    _BLOCK_PREFIX,
    _IGNORE_PREFIX,
    _KILL_PREFIX,
    _edit_callback_message,
    _execute_remediation_action,
    _handle_auto_block,
    _handle_auto_kill,
    _is_degraded_mode,
    _is_known_action,
    _reject_and_learn,
    _resolve_alert_context,
    handle_callback_query,
)

# ═══════════════════════════════════════════════════════════════════════════
# _resolve_alert_context
# ═══════════════════════════════════════════════════════════════════════════


class TestResolveAlertContext:
    def test_block_prefix(self):
        ACTIVE_ALERTS_CACHE["alert123"] = {"ip": "1.2.3.4"}
        aid, ctx = _resolve_alert_context(f"{_BLOCK_PREFIX}alert123")
        assert aid == "alert123"
        assert ctx == {"ip": "1.2.3.4"}
        assert "alert123" not in ACTIVE_ALERTS_CACHE  # popped

    def test_kill_prefix(self):
        ACTIVE_ALERTS_CACHE["kill_alert"] = {"proc_name": "malware.exe"}
        aid, ctx = _resolve_alert_context(f"{_KILL_PREFIX}kill_alert")
        assert aid == "kill_alert"
        assert ctx is not None

    def test_ignore_prefix(self):
        ACTIVE_ALERTS_CACHE["ign_alert"] = {"ip": "1.2.3.4", "port": 80}
        aid, ctx = _resolve_alert_context(f"{_IGNORE_PREFIX}ign_alert")
        assert aid == "ign_alert"
        assert ctx is not None

    def test_auto_block_prefix(self):
        aid, ctx = _resolve_alert_context(f"{_AUTO_BLOCK_PREFIX}42")
        assert aid == "ablk_42"
        assert ctx == {"_auto_block_id": 42}

    def test_auto_block_prefix_non_digit(self):
        aid, ctx = _resolve_alert_context(f"{_AUTO_BLOCK_PREFIX}abc")
        assert ctx == {"_auto_block_id": 0}

    def test_auto_kill_prefix(self):
        aid, ctx = _resolve_alert_context(f"{_AUTO_KILL_PREFIX}99")
        assert aid == "akil_99"
        assert ctx == {"_auto_kill_id": 99}

    def test_unknown_prefix(self):
        aid, ctx = _resolve_alert_context("unknown_data")
        assert aid == ""
        assert ctx is None

    def test_expired_alert(self):
        aid, ctx = _resolve_alert_context(f"{_BLOCK_PREFIX}expired_id")
        assert aid == "expired_id"
        assert ctx is None  # expired


# ═══════════════════════════════════════════════════════════════════════════
# _is_known_action
# ═══════════════════════════════════════════════════════════════════════════


class TestIsKnownAction:
    @pytest.mark.parametrize(
        "prefix",
        [_BLOCK_PREFIX, _KILL_PREFIX, _IGNORE_PREFIX, _AUTO_BLOCK_PREFIX, _AUTO_KILL_PREFIX],
    )
    def test_known_prefixes(self, prefix):
        assert _is_known_action(f"{prefix}something") is True

    def test_unknown(self):
        assert _is_known_action("random_data") is False

    def test_empty(self):
        assert _is_known_action("") is False


# ═══════════════════════════════════════════════════════════════════════════
# _is_degraded_mode
# ═══════════════════════════════════════════════════════════════════════════


class TestIsDegradedMode:
    def test_degraded_true(self):
        mock_bridge = MagicMock()
        mock_bridge.is_degraded.return_value = True
        with patch("services.llm_bridge.bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.return_value = mock_bridge
            assert _is_degraded_mode() is True

    def test_degraded_false(self):
        mock_bridge = MagicMock()
        mock_bridge.is_degraded.return_value = False
        with patch("services.llm_bridge.bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.return_value = mock_bridge
            assert _is_degraded_mode() is False

    def test_exception_returns_false(self):
        with patch("services.llm_bridge.bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.side_effect = RuntimeError("no bridge")
            assert _is_degraded_mode() is False


# ═══════════════════════════════════════════════════════════════════════════
# _execute_remediation_action — block/kill/ignore branches
# ═══════════════════════════════════════════════════════════════════════════


class TestExecuteRemediationAction:
    async def test_block_success(self):
        cached = {"ip": "8.8.8.8", "port": 53, "proc_name": "dns.exe"}
        with patch("services.telegram.callbacks.block_ip_in_firewall", return_value=(True, "Blocked")):
            ok, detail, text = await _execute_remediation_action(f"{_BLOCK_PREFIX}x", cached)
        assert ok is True
        assert "NEUTRALIZED" in text

    async def test_block_no_ip(self):
        cached = {"port": 53, "proc_name": "dns.exe"}
        ok, detail, text = await _execute_remediation_action(f"{_BLOCK_PREFIX}x", cached)
        assert ok is False
        assert text == "NO_IP"

    async def test_kill_success(self):
        cached = {"ip": "1.2.3.4", "port": 80, "proc_name": "malware.exe"}
        with patch("services.telegram.callbacks.kill_process", return_value=(True, "Killed")):
            ok, detail, text = await _execute_remediation_action(f"{_KILL_PREFIX}x", cached)
        assert ok is True
        assert "Kill" in text

    async def test_ignore_with_baseline_learning(self):
        cached = {"ip": "1.2.3.4", "port": 80, "proc_name": "benign.exe"}
        with patch("services.telegram.callbacks.add_to_baseline", new_callable=AsyncMock) as mock_add:
            ok, detail, text = await _execute_remediation_action(f"{_IGNORE_PREFIX}x", cached)
        assert ok is True
        assert "הושתקה" in text
        mock_add.assert_called_once_with("benign.exe", "1.2.3.4", 80)

    async def test_ignore_baseline_learning_exception(self):
        cached = {"ip": "1.2.3.4", "port": 80, "proc_name": "benign.exe"}
        with patch(
            "services.telegram.callbacks.add_to_baseline", new_callable=AsyncMock, side_effect=RuntimeError("db")
        ):
            ok, detail, text = await _execute_remediation_action(f"{_IGNORE_PREFIX}x", cached)
        assert ok is True  # still returns ok

    async def test_ignore_missing_context(self):
        cached = {"ip": None, "port": 0, "proc_name": "unknown"}
        with patch("services.telegram.callbacks.add_to_baseline", new_callable=AsyncMock) as mock_add:
            ok, detail, text = await _execute_remediation_action(f"{_IGNORE_PREFIX}x", cached)
        assert ok is True
        mock_add.assert_not_called()

    async def test_ignore_with_auto_actions_reject_and_learn(self):
        cached = {"ip": "1.2.3.4", "port": 80, "proc_name": "x.exe", "_auto_kill_id": 5, "_auto_block_id": 3}
        with (
            patch("services.telegram.callbacks._reject_and_learn", new_callable=AsyncMock) as mock_reject,
            patch("services.telegram.callbacks.add_to_baseline", new_callable=AsyncMock),
        ):
            ok, detail, text = await _execute_remediation_action(f"{_IGNORE_PREFIX}x", cached)
        mock_reject.assert_called_once_with(5, 3)

    async def test_ignore_no_cached(self):
        ok, detail, text = await _execute_remediation_action(f"{_IGNORE_PREFIX}x", None)
        assert ok is True
        assert "הושתקה" in text

    async def test_auto_block_dispatch(self):
        with patch(
            "services.telegram.callbacks._handle_auto_block", new_callable=AsyncMock, return_value=(True, "ok", "text")
        ):
            ok, detail, text = await _execute_remediation_action(f"{_AUTO_BLOCK_PREFIX}1", {"_auto_block_id": 1})
        assert ok is True

    async def test_auto_kill_dispatch(self):
        with patch(
            "services.telegram.callbacks._handle_auto_kill", new_callable=AsyncMock, return_value=(True, "ok", "text")
        ):
            ok, detail, text = await _execute_remediation_action(f"{_AUTO_KILL_PREFIX}1", {"_auto_kill_id": 1})
        assert ok is True


# ═══════════════════════════════════════════════════════════════════════════
# _handle_auto_block
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleAutoBlock:
    async def test_invalid_id(self):
        ok, detail, text = await _handle_auto_block({"_auto_block_id": 0})
        assert ok is False
        assert "Invalid" in text

    async def test_invalid_id_no_cached(self):
        ok, detail, text = await _handle_auto_block(None)
        assert ok is False

    async def test_action_not_found(self):
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=None):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 99})
        assert ok is False
        assert "not found" in text

    async def test_already_executed(self):
        action = {"status": "APPROVED", "target": "1.2.3.4"}
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 1})
        assert ok is False
        assert "already" in text.lower()

    async def test_degraded_mode(self):
        action = {"status": "PENDING_APPROVAL", "target": "1.2.3.4"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=True),
        ):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 1})
        assert ok is False
        assert "DEGRADED" in text

    async def test_success(self):
        action = {"status": "PENDING_APPROVAL", "target": "8.8.8.8"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
            patch("services.telegram.callbacks.block_ip_in_firewall", return_value=(True, "Blocked")),
        ):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 1})
        assert ok is True
        assert "AUTO-BLOCK APPROVED" in text

    async def test_exception(self):
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, side_effect=RuntimeError("db")):
            ok, detail, text = await _handle_auto_block({"_auto_block_id": 1})
        assert ok is False
        assert "failed" in text.lower()


# ═══════════════════════════════════════════════════════════════════════════
# _handle_auto_kill
# ═══════════════════════════════════════════════════════════════════════════


class TestHandleAutoKill:
    async def test_invalid_id(self):
        ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 0})
        assert ok is False
        assert "Invalid" in text

    async def test_action_not_found(self):
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=None):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 99})
        assert ok is False
        assert "not found" in text

    async def test_already_executed(self):
        action = {"status": "APPROVED", "target": "123|malware.exe"}
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "already" in text.lower()

    async def test_unsafe_target_format(self):
        action = {"status": "PENDING_APPROVAL", "target": "no_pipe_separator"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "Unsafe target" in text

    async def test_invalid_pid(self):
        action = {"status": "PENDING_APPROVAL", "target": "abc|malware.exe"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "Invalid PID" in text

    async def test_degraded_mode(self):
        action = {"status": "PENDING_APPROVAL", "target": "123|malware.exe"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=True),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "DEGRADED" in text

    async def test_pid_recycling(self):
        action = {"status": "PENDING_APPROVAL", "target": "123|malware.exe"}
        mock_proc = MagicMock()
        mock_proc.name.return_value = "benign.exe"
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
            patch("psutil.Process", return_value=mock_proc),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "RECYCLING" in text

    async def test_already_dead(self):
        import psutil

        action = {"status": "PENDING_APPROVAL", "target": "123|malware.exe"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
            patch("psutil.Process", side_effect=psutil.NoSuchProcess(123)),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is True
        assert "already dead" in text.lower()

    async def test_success(self):
        action = {"status": "PENDING_APPROVAL", "target": "123|malware.exe"}
        mock_proc = MagicMock()
        mock_proc.name.return_value = "malware.exe"
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
            patch("psutil.Process", return_value=mock_proc),
            patch("services.telegram.callbacks.kill_process", return_value=(True, "Killed")),
        ):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is True
        assert "AUTO-KILL APPROVED" in text

    async def test_exception(self):
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, side_effect=RuntimeError("db")):
            ok, detail, text = await _handle_auto_kill({"_auto_kill_id": 1})
        assert ok is False
        assert "failed" in text.lower()


# ═══════════════════════════════════════════════════════════════════════════
# _reject_and_learn
# ═══════════════════════════════════════════════════════════════════════════


class TestRejectAndLearn:
    async def test_reject_kill(self):
        action = {"status": "PENDING_APPROVAL", "target": "123|malware.exe", "threat_context": "ctx"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.error_memory.store_lesson", new_callable=AsyncMock),
        ):
            await _reject_and_learn(auto_kill_id=5, auto_block_id=0)

    async def test_reject_block(self):
        action = {"status": "PENDING_APPROVAL", "target": "1.2.3.4", "threat_context": "ctx"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.error_memory.store_lesson", new_callable=AsyncMock),
        ):
            await _reject_and_learn(auto_kill_id=0, auto_block_id=3)

    async def test_skip_non_pending(self):
        action = {"status": "APPROVED", "target": "1.2.3.4"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock) as mock_update,
            patch("services.error_memory.store_lesson", new_callable=AsyncMock) as mock_store,
        ):
            await _reject_and_learn(auto_kill_id=0, auto_block_id=3)
        mock_update.assert_not_called()
        mock_store.assert_not_called()

    async def test_exception_handled(self):
        with patch("services.pending_actions.get_action", new_callable=AsyncMock, side_effect=RuntimeError("db")):
            await _reject_and_learn(auto_kill_id=5, auto_block_id=0)  # should not raise

    async def test_both_zero(self):
        await _reject_and_learn(auto_kill_id=0, auto_block_id=0)  # no-op


# ═══════════════════════════════════════════════════════════════════════════
# _edit_callback_message
# ═══════════════════════════════════════════════════════════════════════════


class TestEditCallbackMessage:
    async def test_success(self):
        bot = AsyncMock()
        callback = MagicMock()
        ok = await _edit_callback_message(bot, callback, chat_id=1, message_id=2, result_text="test")
        assert ok is True
        bot.edit_message_text.assert_called_once()

    async def test_failure(self):
        bot = AsyncMock()
        bot.edit_message_text.side_effect = RuntimeError("edit failed")
        callback = MagicMock()
        ok = await _edit_callback_message(bot, callback, chat_id=1, message_id=2, result_text="test")
        assert ok is False


# ═══════════════════════════════════════════════════════════════════════════
# handle_callback_query — E2E
# ═══════════════════════════════════════════════════════════════════════════


def _make_callback(data, has_message=True):
    """Build a mock CallbackQuery."""
    cb = AsyncMock()
    cb.data = data
    if has_message:
        cb.message = MagicMock()
        cb.message.chat.id = 123
        cb.message.message_id = 456
    else:
        cb.message = None
    return cb


class TestHandleCallbackQuery:
    async def test_no_message(self):
        cb = _make_callback("test", has_message=False)
        bot = AsyncMock()
        await handle_callback_query(cb, bot)
        cb.answer.assert_called_once()

    async def test_unknown_action(self):
        cb = _make_callback("unknown_data")
        bot = AsyncMock()
        await handle_callback_query(cb, bot)
        cb.answer.assert_called_once()
        assert "Unknown" in cb.answer.call_args[0][0]

    async def test_alert_expired(self):
        ACTIVE_ALERTS_CACHE.clear()
        cb = _make_callback(f"{_BLOCK_PREFIX}expired")
        bot = AsyncMock()
        await handle_callback_query(cb, bot)
        cb.answer.assert_called_once()
        assert "expired" in cb.answer.call_args[0][0].lower()

    async def test_no_ip_error(self):
        ACTIVE_ALERTS_CACHE["test_nip"] = {"port": 80, "proc_name": "x.exe"}
        cb = _make_callback(f"{_BLOCK_PREFIX}test_nip")
        bot = AsyncMock()
        await handle_callback_query(cb, bot)
        cb.answer.assert_called_once()
        assert "No IP" in cb.answer.call_args[0][0]

    async def test_block_success_full_flow(self):
        ACTIVE_ALERTS_CACHE["test_blk"] = {"ip": "8.8.8.8", "port": 53, "proc_name": "dns.exe"}
        cb = _make_callback(f"{_BLOCK_PREFIX}test_blk")
        bot = AsyncMock()
        with patch("services.telegram.callbacks.block_ip_in_firewall", return_value=(True, "Blocked")):
            await handle_callback_query(cb, bot)
        bot.edit_message_text.assert_called_once()
        cb.answer.assert_called_once()

    async def test_edit_failure_fallback_to_answer(self):
        ACTIVE_ALERTS_CACHE["test_ef"] = {"ip": "8.8.8.8", "port": 53, "proc_name": "dns.exe"}
        cb = _make_callback(f"{_BLOCK_PREFIX}test_ef")
        bot = AsyncMock()
        bot.edit_message_text.side_effect = RuntimeError("edit failed")
        with patch("services.telegram.callbacks.block_ip_in_firewall", return_value=(True, "Blocked")):
            await handle_callback_query(cb, bot)
        cb.answer.assert_called_once()
        assert "Result" in cb.answer.call_args[0][0]

    async def test_ignore_full_flow(self):
        ACTIVE_ALERTS_CACHE["test_ign"] = {"ip": "1.2.3.4", "port": 80, "proc_name": "benign.exe"}
        cb = _make_callback(f"{_IGNORE_PREFIX}test_ign")
        bot = AsyncMock()
        with patch("services.telegram.callbacks.add_to_baseline", new_callable=AsyncMock):
            await handle_callback_query(cb, bot)
        bot.edit_message_text.assert_called_once()

    async def test_auto_block_full_flow(self):
        cb = _make_callback(f"{_AUTO_BLOCK_PREFIX}1")
        bot = AsyncMock()
        action = {"status": "PENDING_APPROVAL", "target": "8.8.8.8"}
        with (
            patch("services.pending_actions.get_action", new_callable=AsyncMock, return_value=action),
            patch("services.pending_actions.update_status", new_callable=AsyncMock),
            patch("services.telegram.callbacks._is_degraded_mode", return_value=False),
            patch("services.telegram.callbacks.block_ip_in_firewall", return_value=(True, "Blocked")),
        ):
            await handle_callback_query(cb, bot)
        bot.edit_message_text.assert_called_once()
