# tests/test_daily_digest_sitrep_doc.py
"""Tests for _send_sitrep_document + send_daily_digest SITREP file delivery.

Covers the new code path that saves a .md file and sends it as a Telegram
document (mirroring CTI/News SITREP delivery).
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.startup._reporting import _send_sitrep_document, send_daily_digest


class TestSendSitrepDocument:
    async def test_saves_file_and_sends_document(self, tmp_path, monkeypatch):
        gateway = MagicMock()
        gateway.bot = MagicMock()
        gateway.bot.send_document = AsyncMock(return_value=MagicMock())
        # Redirect downloads/reports to tmp_path
        monkeypatch.chdir(tmp_path)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.time_format.format_report_date", return_value="2026-07-02"),
        ):
            await _send_sitrep_document("# SITREP\ncontent")
        # File saved
        saved = (tmp_path / "downloads" / "reports" / "security_sitrep_2026-07-02.md").read_text(encoding="utf-8")
        assert "# SITREP" in saved
        gateway.bot.send_document.assert_called_once()

    async def test_no_gateway_logs_warning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with (
            patch("services.interfaces.get_message_gateway", return_value=None),
            patch("services.time_format.format_report_date", return_value="2026-07-02"),
        ):
            await _send_sitrep_document("# SITREP")  # should not raise

    async def test_no_chat_id_logs_warning(self, tmp_path, monkeypatch):
        gateway = MagicMock()
        gateway.bot = MagicMock()
        monkeypatch.chdir(tmp_path)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", ""),
            patch("services.time_format.format_report_date", return_value="2026-07-02"),
        ):
            await _send_sitrep_document("# SITREP")
        gateway.bot.send_document.assert_not_called()

    async def test_no_bot_logs_warning(self, tmp_path, monkeypatch):
        gateway = MagicMock()
        gateway.bot = None
        monkeypatch.chdir(tmp_path)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.time_format.format_report_date", return_value="2026-07-02"),
        ):
            await _send_sitrep_document("# SITREP")

    async def test_send_document_failure_does_not_raise(self, tmp_path, monkeypatch):
        gateway = MagicMock()
        gateway.bot = MagicMock()
        gateway.bot.send_document = AsyncMock(side_effect=Exception("network"))
        monkeypatch.chdir(tmp_path)
        with (
            patch("services.interfaces.get_message_gateway", return_value=gateway),
            patch("config.TELEGRAM_CHAT_ID", "123"),
            patch("services.time_format.format_report_date", return_value="2026-07-02"),
        ):
            await _send_sitrep_document("# SITREP")  # should not raise


class TestSendDailyDigestCallsSitrepDoc:
    async def test_send_daily_digest_invokes_sitrep_doc(self):
        report = "# Daily Report\ncontent"
        with (
            patch("services.startup._reporting.build_daily_report", new_callable=AsyncMock, return_value=report),
            patch("services.startup._reporting.send_daily_digest_event", new_callable=AsyncMock),
            patch("services.startup._reporting._send_sitrep_document", new_callable=AsyncMock) as sitrep_fn,
        ):
            await send_daily_digest()
        sitrep_fn.assert_called_once_with(report)

    async def test_send_daily_digest_sitrep_failure_does_not_crash(self):
        with (
            patch("services.startup._reporting.build_daily_report", new_callable=AsyncMock, return_value="r"),
            patch("services.startup._reporting.send_daily_digest_event", new_callable=AsyncMock),
            patch(
                "services.startup._reporting._send_sitrep_document",
                new_callable=AsyncMock,
                side_effect=Exception("boom"),
            ),
        ):
            await send_daily_digest()  # should not raise — caught by outer try/except
