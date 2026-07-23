# tests/test_processing_snapshot.py
"""Snapshot tests for processing.py — golden record regression gate.

Captures exact output of process_message with mocked skills_engine, run_agent,
and download functions. Any refactor must preserve byte-identical output.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.telegram.processing import process_message


# ── Global mock: prevent DB/audit/agent calls from hanging ──
@pytest.fixture(autouse=True)
def _mock_db_and_agent():
    """Mock async_save_audit_log, set_last_document, and run_agent (both modules)
    to prevent DB hangs. Tests that need specific agent return values patch on top.
    """
    with (
        patch("services.telegram.processing.async_save_audit_log", new_callable=AsyncMock),
        patch("services.agent.set_last_document"),
        patch("services.telegram.processing.run_agent", new_callable=AsyncMock) as _ra1,
        patch("services.telegram.processing_handlers.run_agent", new_callable=AsyncMock) as _ra2,
    ):
        # Default: both return None (tests override as needed)
        _ra1.return_value = "AGENT_RESPONSE"
        _ra2.return_value = "AGENT_RESPONSE"
        yield _ra1, _ra2


# ── Mock factories ──
def _mock_message(text="", caption="", document=None, photo=None):
    """Build a mock aiogram Message."""
    message = MagicMock()
    message.text = text
    message.caption = caption
    message.document = document
    message.photo = photo
    message.from_user = MagicMock(id=12345, is_bot=False)
    message.chat = MagicMock(id=12345, type="private")
    message.bot = MagicMock()
    return message


def _mock_channel():
    """Build a mock TelegramChannel."""
    channel = MagicMock()
    channel.bot = MagicMock()
    channel.cfg = MagicMock()
    return channel


def _mock_engine():
    """Build a mock SkillsEngine that returns canned results."""
    engine = MagicMock()
    engine.execute = AsyncMock(return_value="MOCK_SKILL_RESULT")
    return engine


def _mock_document(filename="test.pdf"):
    """Build a mock document attachment."""
    doc = MagicMock()
    doc.file_name = filename
    doc.file_id = "fake_file_id"
    return doc


# ── Test cases ──
@pytest.mark.asyncio
async def test_text_only_message(_mock_db_and_agent):
    """Plain text message (no attachment) → agent fallback."""
    message = _mock_message(text="שלום")
    state = MagicMock()
    channel = _mock_channel()

    with patch("services.telegram.permissions.get_response_prefix", return_value=""):
        result = await process_message(channel, message, state)

    assert result == "AGENT_RESPONSE"


@pytest.mark.asyncio
async def test_no_text_no_attachment():
    """No text and no attachment → None."""
    message = _mock_message()
    state = MagicMock()
    channel = _mock_channel()

    result = await process_message(channel, message, state)
    assert result is None


@pytest.mark.asyncio
async def test_image_no_caption(_mock_db_and_agent):
    """Image without caption → direct OCR translate."""
    photo = [MagicMock()]  # photo[-1] is the largest
    message = _mock_message(photo=photo)
    state = MagicMock()
    channel = _mock_channel()

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_photo", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value=""),
    ):
        mock_dl.return_value = Path("/tmp/photo.jpg")
        result = await process_message(channel, message, state)

    assert result == "MOCK_SKILL_RESULT"


@pytest.mark.asyncio
async def test_image_with_translate_caption(_mock_db_and_agent):
    """Image with 'translate' caption → OCR translate with prefix."""
    photo = [MagicMock()]
    message = _mock_message(text="translate this", photo=photo)
    state = MagicMock()
    channel = _mock_channel()

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_photo", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value="PREFIX"),
    ):
        mock_dl.return_value = Path("/tmp/photo.jpg")
        result = await process_message(channel, message, state)

    assert result == "PREFIX\nMOCK_SKILL_RESULT"


@pytest.mark.asyncio
async def test_text_file_translate(_mock_db_and_agent):
    """Text file with translate caption → translator-skill."""
    doc = _mock_document("notes.txt")
    message = _mock_message(text="תרגם לעברית", document=doc)
    state = MagicMock()
    channel = _mock_channel()

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_document", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value=""),
    ):
        mock_dl.return_value = Path("/tmp/notes.txt")
        result = await process_message(channel, message, state)

    assert result == "MOCK_SKILL_RESULT"


@pytest.mark.asyncio
async def test_pdf_translate(_mock_db_and_agent):
    """PDF with translate caption → file-analyst summarize + agent translate."""
    doc = _mock_document("doc.pdf")
    message = _mock_message(text="תרגם", document=doc)
    state = MagicMock()
    channel = _mock_channel()
    ra_proc, ra_handlers = _mock_db_and_agent

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_document", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value=""),
    ):
        mock_dl.return_value = Path("/tmp/doc.pdf")
        ra_handlers.return_value = "TRANSLATED_RESPONSE"
        result = await process_message(channel, message, state)

    assert result == "TRANSLATED_RESPONSE"


@pytest.mark.asyncio
async def test_pdf_datasheet(_mock_db_and_agent):
    """PDF with datasheet keywords → file-analyst datasheet (no agent)."""
    doc = _mock_document("tpa3255_datasheet.pdf")
    message = _mock_message(text="נתח את ה datasheet", document=doc)
    state = MagicMock()
    channel = _mock_channel()

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_document", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value="PREFIX"),
    ):
        mock_dl.return_value = Path("/tmp/tpa3255_datasheet.pdf")
        result = await process_message(channel, message, state)

    assert result == "PREFIX\nMOCK_SKILL_RESULT"


@pytest.mark.asyncio
async def test_pdf_summarize_with_question(_mock_db_and_agent):
    """PDF with question → file-analyst summarize + agent interprets."""
    doc = _mock_document("report.pdf")
    message = _mock_message(text="מה הנקודות המרכזיות?", document=doc)
    state = MagicMock()
    channel = _mock_channel()
    ra_proc, ra_handlers = _mock_db_and_agent

    with (
        patch("services.telegram.processing_handlers.get_skills_engine", return_value=_mock_engine()),
        patch("services.telegram.processing_handlers.download_document", new_callable=AsyncMock) as mock_dl,
        patch("services.telegram.processing_handlers.get_download_dir", return_value=Path("/tmp")),
        patch("services.telegram.permissions.get_response_prefix", return_value=""),
    ):
        mock_dl.return_value = Path("/tmp/report.pdf")
        ra_handlers.return_value = "AGENT_ANALYSIS"
        result = await process_message(channel, message, state)

    assert result == "AGENT_ANALYSIS"
