# tests/test_telegram_coverage.py
"""Coverage tests for services/telegram/{sender,formatting,handlers,channel}.py.

Mocks all network/DB/aiogram calls. Relies on conftest autouse fixtures
(isolated_db, stub_llm_embedding).
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from services.channels_config import (
    DmPolicy,
    ErrorPolicy,
    GroupPolicy,
    TelegramConfig,
    TelegramGroupConfig,
)
from services.telegram import TelegramChannel
from services.telegram.cooldown import ErrorCooldown
from services.telegram.formatting import chunk_text, strip_markdown
from services.telegram.handlers import (
    cmd_help,
    cmd_skills,
    cmd_start,
    make_arg_handler,
    make_intel_handler,
)
from services.telegram.sender import _has_url, send_error, send_message, send_response

# ──────────────────────────────────────────────────────────────────────────
# Helpers / fixtures
# ──────────────────────────────────────────────────────────────────────────


def _cfg(**overrides) -> TelegramConfig:
    base = {
        "enabled": True,
        "bot_token": "test-token",
        "dm_policy": DmPolicy.OPEN,
        "allow_from": ["*"],
        "text_chunk_limit": 4000,
        "chunk_mode": "newline",
        "error_policy": ErrorPolicy.REPLY,
        "error_cooldown_ms": 60000,
    }
    base.update(overrides)
    return TelegramConfig(**base)


def _limiter() -> MagicMock:
    lim = MagicMock()
    lim.acquire = AsyncMock(return_value=0.0)
    return lim


def _message(
    *,
    text: str = "hello",
    chat_id: int = 100,
    chat_type: str = "private",
    user_id: int = 12345,
    message_id: int = 1,
    reply_to_message=None,
) -> tuple[MagicMock, list]:
    """Build a mock aiogram Message capturing answer() calls."""
    msg = MagicMock()
    msg.text = text
    msg.message_id = message_id
    msg.reply_to_message = reply_to_message
    msg.chat = MagicMock(id=chat_id, type=chat_type)
    msg.from_user = MagicMock(id=user_id, is_bot=False)
    msg.document = None
    msg.photo = None
    msg.caption = None
    msg.entities = None
    captured: list[dict] = []

    async def _answer(*args, **kwargs):
        captured.append({"args": args, "kwargs": kwargs})

    async def _answer_document(document, **kwargs):
        captured.append({"document": document, "kwargs": kwargs})

    msg.answer = _answer
    msg.answer_document = _answer_document
    return msg, captured


def _captured_text(captured: list[dict]) -> list[str]:
    """Extract text from captured answer() calls (positional or kwarg)."""
    texts: list[str] = []
    for c in captured:
        if "document" in c:
            continue
        if c["kwargs"].get("text"):
            texts.append(c["kwargs"]["text"])
        elif c["args"]:
            texts.append(str(c["args"][0]))
    return texts


# ──────────────────────────────────────────────────────────────────────────
# formatting.py — strip_markdown
# ──────────────────────────────────────────────────────────────────────────


class TestStripMarkdown:
    def test_html_escapes_special_chars(self):
        out = strip_markdown("a & b < c > d")
        assert "&amp;" in out
        assert "&lt;" in out
        assert "&gt;" in out

    def test_md_link_to_html(self):
        out = strip_markdown("[Google](https://google.com)")
        assert '<a href="https://google.com">Google</a>' in out

    def test_md_link_non_http_skipped(self):
        out = strip_markdown("[foo](javascript:alert(1))")
        assert "<a " not in out
        assert "foo" in out

    def test_md_link_empty_url_skipped(self):
        out = strip_markdown("[foo]()")
        assert "<a " not in out
        assert "foo" in out

    def test_header_to_bold(self):
        out = strip_markdown("## Title\nbody")
        assert "<b>Title</b>" in out

    def test_bold_conversion(self):
        out = strip_markdown("**bold** text")
        assert "<b>bold</b>" in out

    def test_italic_star_conversion(self):
        out = strip_markdown("*italic* text")
        assert "<i>italic</i>" in out

    def test_italic_underscore_conversion(self):
        out = strip_markdown("foo _bar_ baz")
        assert "<i>bar</i>" in out

    def test_inline_code_conversion(self):
        out = strip_markdown("use `code` here")
        assert "<code>code</code>" in out

    def test_triple_backtick_code(self):
        out = strip_markdown("```\nblock\n```")
        assert "<code>" in out
        assert "block" in out

    def test_table_mid_text_to_bullets(self):
        md = "intro\n| Col1 | Col2 |\n| --- | --- |\n| a | b |\n| c | d |\nend"
        out = strip_markdown(md)
        assert "Col1: a" in out
        assert "Col2: b" in out
        assert "Col1: c" in out
        assert "end" in out

    def test_table_at_eof(self):
        md = "intro\n| H1 | H2 |\n| -- | -- |\n| x | y |"
        out = strip_markdown(md)
        assert "H1: x" in out
        assert "H2: y" in out

    def test_table_more_cells_than_headers(self):
        md = "| H1 |\n| -- |\n| a | b |"
        out = strip_markdown(md)
        # extra cell rendered as-is (no header)
        assert "H1: a" in out

    def test_table_separator_only_skipped(self):
        md = "| H1 |\n| -- |\n| a |"
        out = strip_markdown(md)
        assert "H1: a" in out
        # separator row should not produce a bullet
        assert "• H1: --" not in out


# ──────────────────────────────────────────────────────────────────────────
# formatting.py — chunk_text
# ──────────────────────────────────────────────────────────────────────────


class TestChunkText:
    def test_under_limit_single_chunk(self):
        assert chunk_text("short", 100, "newline") == ["short"]

    def test_length_mode_split(self):
        text = "x" * 25
        chunks = chunk_text(text, 10, "length")
        assert len(chunks) == 3
        assert chunks[0] == "x" * 10
        assert chunks[-1] == "x" * 5

    def test_newline_mode_multiple_paragraphs(self):
        text = "para1\n\npara2\n\npara3"
        chunks = chunk_text(text, 100, "newline")
        assert len(chunks) == 1
        assert "para1" in chunks[0]

    def test_newline_mode_paragraph_exceeds_limit(self):
        para = "x" * 50
        text = para
        chunks = chunk_text(text, 20, "newline")
        # hard-split: each chunk <= 20
        for c in chunks:
            assert len(c) <= 20

    def test_newline_mode_paragraph_overflow_with_current(self):
        # current accumulates then a big para forces flush + hard split
        text = "small\n\n" + "y" * 30
        chunks = chunk_text(text, 10, "newline")
        assert len(chunks) >= 2
        for c in chunks:
            assert len(c) <= 10

    def test_empty_returns_text(self):
        # path where chunks ends empty -> returns [text]
        # hard to trigger naturally; test fallback via length mode empty
        assert chunk_text("", 100, "length") == [""]


# ──────────────────────────────────────────────────────────────────────────
# sender.py — _has_url
# ──────────────────────────────────────────────────────────────────────────


class TestHasUrl:
    def test_with_http(self):
        assert _has_url("see http://example.com") is True

    def test_with_https(self):
        assert _has_url("see https://example.com") is True

    def test_without_url(self):
        assert _has_url("plain text only") is False


# ──────────────────────────────────────────────────────────────────────────
# sender.py — send_response
# ──────────────────────────────────────────────────────────────────────────


class TestSendResponse:
    async def test_empty_text_returns_immediately(self):
        msg, captured = _message()
        lim = _limiter()
        await send_response(msg, "", _cfg(), lim)
        assert captured == []
        lim.acquire.assert_not_called()

    async def test_single_chunk_sent(self):
        msg, captured = _message(text="hi")
        lim = _limiter()
        await send_response(msg, "hello world", _cfg(), lim)
        assert len(captured) == 1
        assert captured[0]["kwargs"]["text"] == "hello world"
        assert captured[0]["kwargs"]["reply_to_message_id"] == msg.message_id

    async def test_reply_to_message_id_used_when_present(self):
        rtm, _ = _message(message_id=99)
        msg, captured = _message(reply_to_message=rtm)
        lim = _limiter()
        await send_response(msg, "reply", _cfg(), lim)
        assert captured[0]["kwargs"]["reply_to_message_id"] == 99

    async def test_multi_chunk_reply_markup_on_last(self):
        text = "\n\n".join(f"para{i}" for i in range(5))
        cfg = _cfg(text_chunk_limit=10, chunk_mode="length")
        msg, captured = _message()
        lim = _limiter()
        markup = MagicMock()
        await send_response(msg, text, cfg, lim, reply_markup=markup)
        # last chunk carries reply_markup
        assert captured[-1]["kwargs"].get("reply_markup") is markup
        # first chunk has reply_markup absent
        assert "reply_markup" not in captured[0]["kwargs"]

    async def test_url_disables_preview(self):
        msg, captured = _message()
        lim = _limiter()
        await send_response(msg, "see https://example.com", _cfg(), lim)
        assert captured[0]["kwargs"]["disable_web_page_preview"] is True

    async def test_no_url_no_preview_flag(self):
        msg, captured = _message()
        lim = _limiter()
        await send_response(msg, "plain", _cfg(), lim)
        assert "disable_web_page_preview" not in captured[0]["kwargs"]

    async def test_file_export_existing_file(self, tmp_path):
        f = tmp_path / "out.txt"
        f.write_text("data")
        msg, captured = _message()
        lim = _limiter()
        await send_response(msg, f"[FILE_EXPORT: {f}]\nbody", _cfg(), lim)
        # one text chunk (body) + one document send
        docs = [c for c in captured if "document" in c]
        assert len(docs) == 1

    async def test_file_export_missing_file(self, tmp_path):
        missing = tmp_path / "nope.txt"
        msg, captured = _message()
        lim = _limiter()
        await send_response(msg, f"[FILE_EXPORT: {missing}]\nbody", _cfg(), lim)
        # missing file -> warning text answer
        texts = _captured_text(captured)
        assert any("לא נמצא" in t for t in texts)

    async def test_send_failure_swallowed(self):
        msg, captured = _message()
        lim = _limiter()

        async def _boom(*a, **kw):
            raise RuntimeError("boom")

        msg.answer = _boom
        # must not raise
        await send_response(msg, "text", _cfg(), lim)


# ──────────────────────────────────────────────────────────────────────────
# sender.py — send_error
# ──────────────────────────────────────────────────────────────────────────


class TestSendError:
    async def test_silent_policy_returns(self):
        msg, captured = _message()
        lim = _limiter()
        cfg = _cfg(error_policy=ErrorPolicy.SILENT)
        cd = ErrorCooldown()
        await send_error(msg, "err", cfg, cd, lim)
        assert captured == []
        lim.acquire.assert_not_called()

    async def test_cooldown_blocks_second_send(self):
        msg, captured = _message()
        lim = _limiter()
        cfg = _cfg(error_cooldown_ms=60000)
        cd = ErrorCooldown()
        await send_error(msg, "err1", cfg, cd, lim)
        assert len(captured) == 1
        # second within cooldown -> blocked
        await send_error(msg, "err2", cfg, cd, lim)
        assert len(captured) == 1

    async def test_group_overrides_policy_to_silent(self):
        msg, captured = _message(chat_id=200)
        lim = _limiter()
        cfg = _cfg(error_policy=ErrorPolicy.REPLY)
        cfg.groups["200"] = TelegramGroupConfig(error_policy=ErrorPolicy.SILENT)
        cd = ErrorCooldown()
        await send_error(msg, "err", cfg, cd, lim)
        assert captured == []

    async def test_group_overrides_cooldown(self):
        msg, captured = _message(chat_id=300)
        lim = _limiter()
        cfg = _cfg(error_cooldown_ms=60000)
        # 1ms cooldown — small but non-zero (0 is falsy → treated as default)
        cfg.groups["300"] = TelegramGroupConfig(error_cooldown_ms=1)
        cd = ErrorCooldown()
        await send_error(msg, "err1", cfg, cd, lim)
        await asyncio.sleep(0.01)  # 10ms > 1ms cooldown
        await send_error(msg, "err2", cfg, cd, lim)
        # 1ms cooldown with sleep -> both sent
        assert len(captured) == 2

    async def test_successful_send(self):
        msg, captured = _message()
        lim = _limiter()
        await send_error(msg, "oops", _cfg(), ErrorCooldown(), lim)
        assert len(captured) == 1
        assert "oops" in _captured_text(captured)[0]

    async def test_send_failure_swallowed(self):
        msg, captured = _message()
        lim = _limiter()

        async def _boom(*a, **kw):
            raise RuntimeError("boom")

        msg.answer = _boom
        await send_error(msg, "err", _cfg(), ErrorCooldown(), lim)


# ──────────────────────────────────────────────────────────────────────────
# sender.py — send_message (public API)
# ──────────────────────────────────────────────────────────────────────────


class TestSendMessagePublic:
    async def test_no_bot_returns_false(self):
        assert await send_message(None, 1, "text", _cfg(), _limiter()) is False

    async def test_success_returns_true(self):
        bot = MagicMock()
        bot.send_message = AsyncMock()
        lim = _limiter()
        assert await send_message(bot, 1, "hi", _cfg(), lim) is True
        bot.send_message.assert_awaited()

    async def test_reply_to_attached_to_first_chunk(self):
        bot = MagicMock()
        bot.send_message = AsyncMock()
        lim = _limiter()
        await send_message(bot, 1, "hi", _cfg(), lim, reply_to=42)
        kwargs = bot.send_message.call_args.kwargs
        assert kwargs["reply_to_message_id"] == 42

    async def test_floodwait_retry_then_success(self):
        from aiogram.exceptions import TelegramRetryAfter

        bot = MagicMock()
        attempts = {"n": 0}

        async def _send(**kwargs):
            attempts["n"] += 1
            if attempts["n"] < 2:
                raise TelegramRetryAfter(method=MagicMock(), message="flood", retry_after=0)
            return MagicMock()

        bot.send_message = _send
        lim = _limiter()
        with patch("services.telegram.sender.asyncio.sleep", new=AsyncMock()):
            assert await send_message(bot, 1, "hi", _cfg(), lim) is True
        assert attempts["n"] == 2

    async def test_floodwait_exhausted_returns_false(self):
        from aiogram.exceptions import TelegramRetryAfter

        bot = MagicMock()

        async def _send(**kwargs):
            raise TelegramRetryAfter(method=MagicMock(), message="flood", retry_after=0)

        bot.send_message = _send
        lim = _limiter()
        with patch("services.telegram.sender.asyncio.sleep", new=AsyncMock()):
            assert await send_message(bot, 1, "hi", _cfg(), lim) is False

    async def test_generic_exception_returns_false(self):
        bot = MagicMock()
        bot.send_message = AsyncMock(side_effect=RuntimeError("net"))
        lim = _limiter()
        assert await send_message(bot, 1, "hi", _cfg(), lim) is False


# ──────────────────────────────────────────────────────────────────────────
# handlers.py
# ──────────────────────────────────────────────────────────────────────────


class TestCmdStart:
    async def test_no_user_returns(self):
        msg, captured = _message()
        msg.from_user = None
        channel = MagicMock()
        await cmd_start(channel, msg)
        channel.send_error.assert_not_called()
        assert captured == []

    async def test_private_dm_not_allowed(self):
        msg, captured = _message(chat_type="private")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = False
        channel.send_error = AsyncMock()
        await cmd_start(channel, msg)
        channel.send_error.assert_awaited()

    async def test_private_dm_allowed_answers(self):
        msg, captured = _message(chat_type="private")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        with patch("services.agent.context.clear_last_document"):
            await cmd_start(channel, msg)
        assert any("שלום" in t for t in _captured_text(captured))

    async def test_non_private_chat_no_greeting(self):
        msg, captured = _message(chat_type="group")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        with patch("services.agent.context.clear_last_document"):
            await cmd_start(channel, msg)
        assert captured == []

    async def test_clear_last_document_failure_logged(self):
        msg, captured = _message(chat_type="private")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        with patch("services.agent.context.clear_last_document", side_effect=RuntimeError("x")):
            await cmd_start(channel, msg)
        # still greets despite clear failure
        assert any("שלום" in t for t in _captured_text(captured))


class TestCmdSkills:
    async def test_renders_skills(self):
        msg, captured = _message()
        engine = MagicMock()
        engine._skills = {}
        with patch("services.telegram.handlers.get_skills_engine", return_value=engine):
            await cmd_skills(msg)
        assert captured
        assert any("Skills" in t for t in _captured_text(captured))


class TestCmdHelp:
    async def test_help_answers(self):
        msg, captured = _message()
        await cmd_help(msg)
        assert captured
        text = _captured_text(captured)[0]
        assert "Claw" in text or "פקודות" in text


class TestMakeIntelHandler:
    async def test_no_user_returns(self):
        msg, captured = _message()
        msg.from_user = None
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        handler = make_intel_handler(channel, "get_system_snapshot", "Title")
        with patch("services.telegram.handlers.call_mcp", new=AsyncMock()):
            await handler(msg)
        assert captured == []

    async def test_not_allowed_returns(self):
        msg, captured = _message()
        channel = MagicMock()
        channel.is_dm_allowed.return_value = False
        handler = make_intel_handler(channel, "get_system_snapshot", "Title")
        with patch("services.telegram.handlers.call_mcp", new=AsyncMock()):
            await handler(msg)
        assert captured == []

    async def test_success_path(self):
        msg, captured = _message()
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        channel._send_response = AsyncMock()
        handler = make_intel_handler(channel, "get_system_snapshot", "Title")
        with (
            patch("services.telegram.handlers.call_mcp", new=AsyncMock(return_value="result")),
            patch("services.telegram.handlers.async_save_audit_log", new=AsyncMock()),
        ):
            await handler(msg)
        channel._send_response.assert_awaited()
        # first answer is the "loading" message
        assert any("טוען" in t for t in _captured_text(captured))


class TestMakeArgHandler:
    async def test_no_user_returns(self):
        msg, captured = _message()
        msg.from_user = None
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        handler = make_arg_handler(channel, "web_search", "Search", "query")
        with patch("services.telegram.handlers.call_mcp", new=AsyncMock()):
            await handler(msg)
        assert captured == []

    async def test_empty_required_arg(self):
        msg, captured = _message(text="/search")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        handler = make_arg_handler(channel, "web_search", "Search", "query")
        with patch("services.telegram.handlers.call_mcp", new=AsyncMock()):
            await handler(msg)
        assert any("נדרש" in t for t in _captured_text(captured))

    async def test_terminate_process_valid_pid(self):
        msg, captured = _message(text="/kill 1234")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        channel._send_response = AsyncMock()
        handler = make_arg_handler(channel, "terminate_process", "Kill", "pid")
        with (
            patch("services.telegram.handlers.call_mcp", new=AsyncMock(return_value="ok")) as mcp,
            patch("services.telegram.handlers.async_save_audit_log", new=AsyncMock()),
        ):
            await handler(msg)
        mcp.assert_awaited()
        # call_mcp(_MCP_URL, tool_name, arguments) — positional
        assert mcp.call_args.args[2] == {"pid": 1234}

    async def test_terminate_process_invalid_pid(self):
        msg, captured = _message(text="/kill abc")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        handler = make_arg_handler(channel, "terminate_process", "Kill", "pid")
        with patch("services.telegram.handlers.call_mcp", new=AsyncMock()):
            await handler(msg)
        assert any("PID" in t for t in _captured_text(captured))

    async def test_read_file_handler(self):
        msg, captured = _message(text="/read /tmp/x")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        channel._send_response = AsyncMock()
        handler = make_arg_handler(channel, "read_file", "Read", "path")
        with (
            patch("services.telegram.handlers.call_mcp", new=AsyncMock(return_value="ok")) as mcp,
            patch("services.telegram.handlers.async_save_audit_log", new=AsyncMock()),
        ):
            await handler(msg)
        assert mcp.call_args.args[2] == {"path": "/tmp/x", "max_lines": 100}

    async def test_generic_arg_handler(self):
        msg, captured = _message(text="/block 1.2.3.4")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        channel._send_response = AsyncMock()
        handler = make_arg_handler(channel, "block_ip", "Block", "ip")
        with (
            patch("services.telegram.handlers.call_mcp", new=AsyncMock(return_value="ok")) as mcp,
            patch("services.telegram.handlers.async_save_audit_log", new=AsyncMock()),
        ):
            await handler(msg)
        assert mcp.call_args.args[2] == {"ip": "1.2.3.4"}

    async def test_default_arg_used_when_missing(self):
        msg, captured = _message(text="/ls")
        channel = MagicMock()
        channel.is_dm_allowed.return_value = True
        channel._send_response = AsyncMock()
        handler = make_arg_handler(channel, "list_directory", "LS", "path", default=".")
        with (
            patch("services.telegram.handlers.call_mcp", new=AsyncMock(return_value="ok")) as mcp,
            patch("services.telegram.handlers.async_save_audit_log", new=AsyncMock()),
        ):
            await handler(msg)
        assert mcp.call_args.args[2] == {"path": "."}


# ──────────────────────────────────────────────────────────────────────────
# channel.py — TelegramChannel
# ──────────────────────────────────────────────────────────────────────────


class TestTelegramChannel:
    def test_is_enabled_true_with_token(self):
        ch = TelegramChannel(_cfg(enabled=True, bot_token="t"))
        assert ch.is_enabled is True

    def test_is_enabled_false_when_disabled(self):
        ch = TelegramChannel(_cfg(enabled=False, bot_token="t"))
        assert ch.is_enabled is False

    def test_get_token_from_cfg(self):
        ch = TelegramChannel(_cfg(bot_token="abc"))
        assert ch._get_token() == "abc"

    def test_is_dm_allowed_delegates(self):
        ch = TelegramChannel(_cfg(dm_policy=DmPolicy.OPEN, allow_from=["*"]))
        assert ch.is_dm_allowed(999) is True

    async def test_is_group_allowed_delegates(self):
        ch = TelegramChannel(_cfg(group_policy=GroupPolicy.OPEN))
        assert await ch.is_group_allowed(1, 2) is True

    async def test_list_pending_pairings_empty(self):
        ch = TelegramChannel(_cfg())
        assert await ch.list_pending_pairings() == []

    async def test_approve_pairing_not_configured(self):
        ch = TelegramChannel(_cfg())
        assert await ch.approve_pairing("code") == "Pairing not configured"

    async def test_approve_pairing_delegates(self):
        cfg = _cfg()
        ch = TelegramChannel(cfg)
        with patch.object(ch, "cfg") as mock_cfg:
            mock_cfg.approve_pairing = lambda code: f"approved:{code}"
            assert await ch.approve_pairing("xyz") == "approved:xyz"

    async def test_send_message_delegates_to_sender(self):
        ch = TelegramChannel(_cfg())
        ch.bot = MagicMock()
        lim = MagicMock()
        ch._outbox_limiter = lim
        with patch("services.telegram.sender.send_message", new=AsyncMock(return_value=True)) as sm:
            assert await ch.send_message(1, "hi") is True
            sm.assert_awaited()

    async def test_send_error_delegates_to_sender(self):
        ch = TelegramChannel(_cfg())
        msg, _ = _message()
        with patch("services.telegram.sender.send_error", new=AsyncMock()) as se:
            await ch.send_error(msg, "err")
            se.assert_awaited()

    async def test__send_response_delegates(self):
        ch = TelegramChannel(_cfg())
        msg, _ = _message()
        with patch("services.telegram.sender.send_response", new=AsyncMock()) as sr:
            await ch._send_response(msg, "text")
            sr.assert_awaited()

    async def test__on_message_delegates_to_routing(self):
        ch = TelegramChannel(_cfg())
        msg, _ = _message()
        with patch("services.telegram.channel.on_message", new=AsyncMock()) as om:
            await ch._on_message(msg)
            om.assert_awaited()

    async def test__on_callback_query_delegates(self):
        ch = TelegramChannel(_cfg())
        cb = MagicMock()
        with patch("services.telegram.channel.on_callback_query", new=AsyncMock()) as oc:
            await ch._on_callback_query(cb)
            oc.assert_awaited()

    def test_setup_routes_registers_handlers(self):
        ch = TelegramChannel(_cfg())
        ch.dp = MagicMock()
        ch.dp.include_router = MagicMock()
        ch.router = MagicMock()
        ch.router.message = MagicMock()
        ch.router.callback_query = MagicMock()
        ch.setup_routes()
        # message handlers registered (start, help, skills, intel cmds, arg cmds, status, intel, stats, fallback)
        assert ch.router.message.call_count >= 8
        ch.router.callback_query.assert_called()
        ch.dp.include_router.assert_called()

    async def test_start_delegates_to_polling(self):
        ch = TelegramChannel(_cfg())
        with patch("services.telegram.polling.start_polling", new=AsyncMock()) as sp:
            await ch.start()
            sp.assert_awaited()

    async def test_stop_delegates_to_polling(self):
        ch = TelegramChannel(_cfg())
        with patch("services.telegram.polling.stop_polling", new=AsyncMock()) as sp:
            await ch.stop()
            sp.assert_awaited()
