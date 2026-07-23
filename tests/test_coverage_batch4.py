# tests/test_coverage_batch4.py
"""Coverage tests for bypass, memory, and other high-gap modules.

Covers:
- services/agent/bypass/elaborate.py
- services/agent/bypass/firewall.py
- services/agent/bypass/news.py (async functions)
- services/agent/bypass/news_pipeline.py
- services/memory_store.py
- services/memory_db_search.py
- services/memory_db.py
- services/formatters.py (more functions)
- services/agent/_agent_critic.py
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# agent/bypass/elaborate.py
# ═══════════════════════════════════════════════════════════════════════════


class TestElaborate:
    def test_detect_elaborate_query_short(self):
        from services.agent.bypass.elaborate import _detect_elaborate_query

        assert _detect_elaborate_query("תפרט") is True
        assert _detect_elaborate_query("elaborate") is True
        assert _detect_elaborate_query("הרחב") is True

    def test_detect_elaborate_query_long(self):
        from services.agent.bypass.elaborate import _detect_elaborate_query

        assert _detect_elaborate_query("אני רוצה שתפרט לי על הנושא הזה בבקשה") is False

    def test_detect_elaborate_query_empty(self):
        from services.agent.bypass.elaborate import _detect_elaborate_query

        assert _detect_elaborate_query("") is False

    def test_detect_elaborate_query_unrelated(self):
        from services.agent.bypass.elaborate import _detect_elaborate_query

        assert _detect_elaborate_query("מה המצב") is False

    def test_find_usable_prev_turn_skips_short(self):
        from services.agent.bypass.elaborate import _find_usable_prev_turn

        entries = [MagicMock(response="short", query="q")]
        assert _find_usable_prev_turn(entries) is None

    def test_find_usable_prev_turn_skips_error(self):
        from services.agent.bypass.elaborate import _find_usable_prev_turn

        entries = [MagicMock(response="⚠️ Error occurred here", query="q")]
        assert _find_usable_prev_turn(entries) is None

    def test_find_usable_prev_turn_skips_elaborate(self):
        from services.agent.bypass.elaborate import _find_usable_prev_turn

        entries = [MagicMock(response="A" * 30, query="תפרט")]
        assert _find_usable_prev_turn(entries) is None

    def test_find_usable_prev_turn_finds_valid(self):
        from services.agent.bypass.elaborate import _find_usable_prev_turn

        entries = [MagicMock(response="A valid response that is long enough", query="What is X?")]
        result = _find_usable_prev_turn(entries)
        assert result is not None

    def test_build_elaborate_sections_with_doc(self):
        from services.agent.bypass.elaborate import _build_elaborate_sections

        result = _build_elaborate_sections("תפרט", "prev q", "prev response", "doc text")
        assert "doc text" in result
        assert "prev q" in result
        assert "prev response" in result
        assert "תפרט" in result

    def test_build_elaborate_sections_no_doc(self):
        from services.agent.bypass.elaborate import _build_elaborate_sections

        result = _build_elaborate_sections("תפרט", "prev q", "prev response", "")
        assert "המסמך המקורי" not in result

    def test_build_elaborate_sections_truncation(self):
        from services.agent.bypass.elaborate import _build_elaborate_sections

        long_resp = "x" * 5000
        long_doc = "y" * 10000
        result = _build_elaborate_sections("תפרט", "q", long_resp, long_doc)
        assert len(result) < 20000

    async def test_run_elaborate_llm_success(self):
        from services.agent.bypass.elaborate import _run_elaborate_llm

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Elaborated answer")
        with patch("services.llm_bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.return_value = bridge
            with patch("services.agent.bypass.elaborate.async_store_conversation", AsyncMock()):
                result = await _run_elaborate_llm("input")
                assert "Elaborated" in result

    async def test_run_elaborate_llm_empty_response(self):
        from services.agent.bypass.elaborate import _run_elaborate_llm

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="")
        with patch("services.llm_bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.return_value = bridge
            with patch("services.agent.bypass.elaborate.async_store_conversation", AsyncMock()):
                result = await _run_elaborate_llm("input")
                assert "לא הופק" in result

    async def test_run_elaborate_llm_exception(self):
        from services.agent.bypass.elaborate import _run_elaborate_llm

        with patch("services.llm_bridge.LLMBridge") as mock_cls:
            mock_cls.get_instance.side_effect = Exception("boom")
            result = await _run_elaborate_llm("input")
            assert "שגיאה" in result

    async def test_direct_elaborate_bypass_no_memory(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        with patch("services.agent.bypass.elaborate.get_memory_service", side_effect=Exception("no db")):
            result = await _direct_elaborate_bypass("תפרט")
            assert result is None

    async def test_direct_elaborate_bypass_no_usable_turn(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        svc = MagicMock()
        svc.get_recent = AsyncMock(return_value=[])
        with patch("services.agent.bypass.elaborate.get_memory_service", return_value=svc):
            result = await _direct_elaborate_bypass("תפרט")
            assert result is None

    async def test_direct_elaborate_bypass_analysis_no_doc(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        entry = MagicMock()
        entry.response = "A" * 30
        entry.query = "What is X?"
        svc = MagicMock()
        svc.get_recent = AsyncMock(return_value=[entry])
        with (
            patch("services.agent.bypass.elaborate.get_memory_service", return_value=svc),
            patch("services.agent.bypass.elaborate.get_last_document", return_value=""),
        ):
            result = await _direct_elaborate_bypass("נתח")
            assert result is None

    async def test_direct_elaborate_bypass_success(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        entry = MagicMock()
        entry.response = "A" * 30
        entry.query = "What is X?"
        svc = MagicMock()
        svc.get_recent = AsyncMock(return_value=[entry])
        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="Detailed answer")
        with (
            patch("services.agent.bypass.elaborate.get_memory_service", return_value=svc),
            patch("services.agent.bypass.elaborate.get_last_document", return_value="doc"),
            patch("services.llm_bridge.LLMBridge") as mock_cls,
            patch("services.agent.bypass.elaborate.async_store_conversation", AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            result = await _direct_elaborate_bypass("תפרט")
            assert "Detailed" in result


# ═══════════════════════════════════════════════════════════════════════════
# agent/bypass/firewall.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFirewallBypass:
    def test_parse_port_valid(self):
        from services.agent.bypass.firewall import _parse_port

        assert _parse_port("חסום פורט 443") == (443, "TCP")
        assert _parse_port("block port 8080 udp") == (8080, "UDP")

    def test_parse_port_invalid(self):
        from services.agent.bypass.firewall import _parse_port

        assert _parse_port("no port here") is None
        assert _parse_port("port 99999") is None
        assert _parse_port("port 0") is None

    def test_parse_ip_valid(self):
        from services.agent.bypass.firewall import _parse_ip

        assert _parse_ip("block 1.2.3.4") == "1.2.3.4"

    def test_parse_ip_invalid(self):
        from services.agent.bypass.firewall import _parse_ip

        assert _parse_ip("no ip") is None
        assert _parse_ip("999.999.999.999") is None

    def test_parse_cidr(self):
        from services.agent.bypass.firewall import _parse_cidr

        assert _parse_cidr("block 10.0.0.0/24") == "10.0.0.0/24"
        assert _parse_cidr("no cidr") is None

    def test_parse_block_command_port(self):
        from services.agent.bypass.firewall import _parse_block_command

        result = _parse_block_command("חסום פורט 443")
        assert result[0] == "block-port"
        assert result[1]["port"] == 443

    def test_parse_block_command_ip(self):
        from services.agent.bypass.firewall import _parse_block_command

        result = _parse_block_command("חסום 1.2.3.4")
        assert result[0] == "block"
        assert result[1]["ip"] == "1.2.3.4"

    def test_parse_block_command_cidr(self):
        from services.agent.bypass.firewall import _parse_block_command

        result = _parse_block_command("חסום 10.0.0.0/24")
        assert result[0] == "block-cidr"

    def test_parse_block_command_none(self):
        from services.agent.bypass.firewall import _parse_block_command

        assert _parse_block_command("no target") is None

    def test_parse_unblock_command_port(self):
        from services.agent.bypass.firewall import _parse_unblock_command

        result = _parse_unblock_command("פתח פורט 443")
        assert result[0] == "unblock-port"

    def test_parse_unblock_command_ip(self):
        from services.agent.bypass.firewall import _parse_unblock_command

        result = _parse_unblock_command("פתח 1.2.3.4")
        assert result[0] == "unblock"

    def test_detect_firewall_query_block(self):
        from services.agent.bypass.firewall import _detect_firewall_query

        result = _detect_firewall_query("חסום 1.2.3.4")
        assert result is not None
        assert result[0] == "block"

    def test_detect_firewall_query_list(self):
        from services.agent.bypass.firewall import _detect_firewall_query

        result = _detect_firewall_query("רשימה")
        assert result is not None
        assert result[0] == "list"

    def test_detect_firewall_query_empty(self):
        from services.agent.bypass.firewall import _detect_firewall_query

        assert _detect_firewall_query("") is None

    def test_detect_firewall_query_too_long(self):
        from services.agent.bypass.firewall import _detect_firewall_query

        assert _detect_firewall_query("x" * 300) is None

    def test_detect_firewall_query_complex(self):
        from services.agent.bypass.firewall import _detect_firewall_query

        assert _detect_firewall_query("חסום את כל התעבורה מהאתר הזה ותבדוק") is None


# ═══════════════════════════════════════════════════════════════════════════
# agent/bypass/news.py (async functions)
# ═══════════════════════════════════════════════════════════════════════════


class TestNewsBypassAsync:
    async def test_call_news_skill_success(self):
        from services.agent.bypass.news import _call_news_skill

        engine = MagicMock()
        engine.execute = AsyncMock(return_value='{"articles": []}')
        with patch("services.agent.bypass.news.get_skills_engine", return_value=engine):
            result = await _call_news_skill("news_il", "תביא חדשות")
            assert "articles" in result

    async def test_call_news_skill_failure(self):
        from services.agent.bypass.news import _call_news_skill

        engine = MagicMock()
        engine.execute = AsyncMock(side_effect=Exception("skill error"))
        with patch("services.agent.bypass.news.get_skills_engine", return_value=engine):
            result = await _call_news_skill("news_il", "תביא חדשות")
            assert "לא זמין" in result

    async def test_call_news_skill_empty_result(self):
        from services.agent.bypass.news import _call_news_skill

        engine = MagicMock()
        engine.execute = AsyncMock(return_value="")
        with patch("services.agent.bypass.news.get_skills_engine", return_value=engine):
            result = await _call_news_skill("news_il", "תביא חדשות")
            assert "אין לי מידע" in result

    async def test_ai_news_pipeline(self):
        from services.agent.bypass.news import _ai_news_pipeline

        with patch("services.agent.bypass.news_pipeline.ai_news_pipeline", AsyncMock(return_value="AI summary")):
            result = await _ai_news_pipeline("news_il", "question")
            assert result == "AI summary"

    async def test_extract_full_texts_no_script(self):
        from services.agent.bypass.news import _extract_full_texts

        articles = [{"link": "http://x.com"}]
        with patch("services.agent.bypass.news.Path") as mock_path:
            mock_path.return_value.resolve.return_value.parents.__getitem__.return_value.__truediv__.return_value.exists.return_value = False
            await _extract_full_texts(articles)
            assert articles[0].get("full_text", "") == ""


# ═══════════════════════════════════════════════════════════════════════════
# memory_store.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMemoryStore:
    async def test_ensure_init(self):
        from services.memory_store import _ensure_init, _init_done

        if not _init_done:
            await _ensure_init()

    def test_get_memory_pool(self):
        from services.memory_store import get_memory_pool

        pool = get_memory_pool()
        assert pool is not None

    async def test_migrate_from_alert_history_no_source(self):
        from services.memory_store import migrate_from_alert_history

        result = await migrate_from_alert_history("/nonexistent/path.db")
        assert result == 0


# ═══════════════════════════════════════════════════════════════════════════
# memory_db.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMemoryDb:
    async def test_ensure_init(self):
        from services.memory_db import _ensure_init, _init_done

        if not _init_done:
            await _ensure_init()

    async def test_store_message(self):
        from services.memory_db import _ensure_init, store_message

        await _ensure_init()
        await store_message("user", "test content")

    async def test_fmt_ts(self):
        from services.memory_db import _fmt_ts

        result = _fmt_ts("2024-01-01T12:00:00")
        assert isinstance(result, str)

    async def test_get_last_hunt_empty(self):
        from services.memory_db import get_last_hunt

        mock_db = AsyncMock()
        mock_cursor = AsyncMock()
        mock_cursor.fetchone = AsyncMock(return_value=None)
        mock_db.execute = AsyncMock(return_value=mock_cursor)
        mock_pool = MagicMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock()
        with (
            patch("services.memory_db.get_memory_pool", return_value=mock_pool),
            patch("services.memory_db._ensure_init", AsyncMock()),
        ):
            result = await get_last_hunt()
            assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# memory_db_search.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMemoryDbSearch:
    def test_format_results_empty(self):
        from services.memory_db_search import _format_results

        assert _format_results([]) == ""

    def test_format_results_with_data(self):
        from services.memory_db_search import _format_results

        # _format_results expects (ts, role, content) tuples
        rows = [("2024-01-01T12:00:00", "user", "test content")]
        result = _format_results(rows)
        assert "test content" in result

    def test_rank_by_embedding_empty(self):
        from services.memory_db_search import _rank_by_embedding

        result = _rank_by_embedding([0.1] * 10, [], 5)
        assert result is None

    def test_timestamp_fallback_empty(self):
        from services.memory_db_search import _timestamp_fallback

        # _timestamp_fallback expects rows with at least 4 elements: (id, ts, role, content, ...)
        result = _timestamp_fallback([], 5)
        assert result == ""

    def test_timestamp_fallback_with_data(self):
        from services.memory_db_search import _timestamp_fallback

        rows = [(1, "2024-01-01T12:00:00", "user", "content", None)]
        result = _timestamp_fallback(rows, 5)
        assert "content" in result


# ═══════════════════════════════════════════════════════════════════════════
# formatters.py (more)
# ═══════════════════════════════════════════════════════════════════════════


class TestFormattersMore:
    def test_format_alert_event(self):
        from services.formatters import _format_alert_event

        result = _format_alert_event({"trigger": "test", "report": "r"}, "12:00")
        assert isinstance(result, str)

    def test_format_critical_override(self):
        from services.formatters import _format_critical_override

        result = _format_critical_override({"anomalies": []}, "12:00")
        assert isinstance(result, str)

    def test_format_threat_hunt(self):
        from services.formatters import _format_threat_hunt

        result = _format_threat_hunt({"matches": []}, "12:00")
        assert isinstance(result, str)

    def test_format_event_for_telegram(self):
        from services.formatters import format_event_for_telegram
        from services.sentinel_events import SentinelEvent

        event = SentinelEvent(
            event_type="alert",
            priority="high",
            data={"trigger": "test", "report": "report text"},
        )
        result = format_event_for_telegram(event)
        assert isinstance(result, str)


# ═══════════════════════════════════════════════════════════════════════════
# agent/_agent_critic.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAgentCritic:
    def test_match_claims_to_evidence(self):
        from services.agent._agent_critic import _match_claims_to_evidence

        result = _match_claims_to_evidence(["claim1"], [("evidence1", "source1")])
        assert isinstance(result, list)

    def test_is_real_flaw(self):
        from services.agent._agent_critic import _is_real_flaw

        assert isinstance(_is_real_flaw("logical error"), bool)

    def test_reason_is_brevity(self):
        from services.agent._agent_critic import _reason_is_brevity

        assert isinstance(_reason_is_brevity("too short"), bool)

    def test_resolve_verdict(self):
        from services.agent._agent_critic import _resolve_verdict

        result = _resolve_verdict({"verdict": True}, "response text")
        assert result is True

    def test_resolve_verdict_legacy_fail(self):
        from services.agent._agent_critic import _resolve_verdict

        result = _resolve_verdict({}, "FAIL\nreason")
        assert result is False

    def test_resolve_verdict_legacy_pass(self):
        from services.agent._agent_critic import _resolve_verdict

        result = _resolve_verdict({}, "PASS\nreason")
        assert result is True

    def test_check_contradiction(self):
        from services.agent._agent_critic import _check_contradiction

        result = _check_contradiction(True, [], False, "ok")
        assert isinstance(result, bool)

    def test_build_fb_reason(self):
        from services.agent._agent_critic import _build_fb_reason

        result = _build_fb_reason("reason", False, "", [])
        assert isinstance(result, str)

    def test_mk_critic_fb(self):
        from services.agent._agent_critic import _mk_critic_fb

        result = _mk_critic_fb("reason text", is_pass=True)
        assert isinstance(result, dict)
        assert result["pass"] is True
