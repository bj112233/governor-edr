"""Tests for LLM short-circuit optimizations (A-1 through A-4).

Verifies that deterministic paths replace LLM calls for:
  A-1: RSS summaries under 500 chars (summarize_article)
  A-2: Keyword-based sentiment classification (classify_sentiment)
  A-3: Extractive summarization for short/single-chunk docs (llm_summarize_doc)
  A-4: Template-based elaborate for structured responses (_direct_elaborate_bypass)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── A-1: RSS summary short-circuit ───────────────────────────────────────────


class TestSummarizeArticleShortCircuit:
    async def test_short_text_returns_as_is(self):
        from services.news_ai.single import summarize_article

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="SHOULD NOT BE CALLED")
        result = await summarize_article("Title", "Short body text", bridge)
        assert result == "Short body text"
        bridge.complete.assert_not_called()

    async def test_long_text_calls_llm(self):
        from services.news_ai.single import summarize_article

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="LLM summary")
        long_text = "x" * 600
        result = await summarize_article("Title", long_text, bridge)
        assert result == "LLM summary"
        bridge.complete.assert_called_once()


# ── A-2: Deterministic sentiment classifier ──────────────────────────────────


class TestDeterministicSentiment:
    async def test_positive_keyword_shortcircuit(self):
        from services.news_ai.single import classify_sentiment

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="SHOULD NOT BE CALLED")
        result = await classify_sentiment("Security patch success", "system secure", bridge)
        assert result == "positive"
        bridge.complete.assert_not_called()

    async def test_negative_keyword_shortcircuit(self):
        from services.news_ai.single import classify_sentiment

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="SHOULD NOT BE CALLED")
        result = await classify_sentiment("Data breach attack", "malware exploit", bridge)
        assert result == "negative"
        bridge.complete.assert_not_called()

    async def test_ambiguous_falls_to_llm(self):
        from services.news_ai.single import classify_sentiment

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="neutral")
        result = await classify_sentiment("Weather update", "rainy day", bridge)
        assert result == "neutral"
        bridge.complete.assert_called_once()


# ── A-3: Extractive summarization ────────────────────────────────────────────


class TestExtractiveSummarization:
    async def test_short_doc_returns_as_is(self):
        from services.agent.bypass._translation_handlers import llm_summarize_doc

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="SHOULD NOT BE CALLED")
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            result = await llm_summarize_doc("summarize", "Short text under 1000 chars.")
            assert "Short text" in result
            bridge.complete.assert_not_called()

    async def test_single_chunk_extractive(self):
        from services.agent.bypass._translation_handlers import llm_summarize_doc

        bridge = MagicMock()
        bridge.complete = AsyncMock(return_value="SHOULD NOT BE CALLED")
        with (
            patch("services.agent.bypass._translation_handlers.LLMBridge") as mock_cls,
            patch("services.agent.bypass._translation_handlers.async_store_conversation", new=AsyncMock()),
        ):
            mock_cls.get_instance.return_value = bridge
            # 1500 chars, multiple sentences → extractive picks top-5
            text = ". ".join([f"Sentence number {i} about topic" for i in range(20)] + ["x" * 1000])
            result = await llm_summarize_doc("summarize", text)
            assert len(result) > 0
            bridge.complete.assert_not_called()


# ── A-4: Template-based elaborate ────────────────────────────────────────────


class TestTemplateElaborate:
    async def test_structured_response_template_expansion(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        # Previous response with markdown headers
        prev_response = "## Section A\nContent about A."
        # Document with additional sections not in the response
        last_doc = "## Section A\nContent about A.\n\n## Section B\nContent about B.\n\n## Section C\nContent about C."

        mock_entry = MagicMock()
        mock_entry.query = "מה זה MITRE ATT&CK?"  # non-elaborate query (avoids recursion skip)
        mock_entry.response = prev_response

        mock_svc = MagicMock()
        mock_svc.get_recent = AsyncMock(return_value=[mock_entry])

        with (
            patch("services.agent.bypass.elaborate.get_memory_service", return_value=mock_svc),
            patch("services.agent.bypass.elaborate.get_last_document", return_value=last_doc),
            patch("services.agent.bypass.elaborate.async_store_conversation", new=AsyncMock()),
        ):
            result = await _direct_elaborate_bypass("תפרט")
            # Template expansion should append sections B and C
            assert "Section B" in result
            assert "Section C" in result

    async def test_unstructured_falls_to_llm(self):
        from services.agent.bypass.elaborate import _direct_elaborate_bypass

        # Plain text response (no markdown headers)
        prev_response = "This is a plain text answer without structure."
        last_doc = "Some document text."

        mock_entry = MagicMock()
        mock_entry.query = "מה זה MITRE ATT&CK?"  # non-elaborate query (avoids recursion skip)
        mock_entry.response = prev_response

        mock_svc = MagicMock()
        mock_svc.get_recent = AsyncMock(return_value=[mock_entry])

        with (
            patch("services.agent.bypass.elaborate.get_memory_service", return_value=mock_svc),
            patch("services.agent.bypass.elaborate.get_last_document", return_value=last_doc),
            patch("services.agent.bypass.elaborate._run_elaborate_llm", new=AsyncMock(return_value="LLM elaboration")),
            patch("services.agent.bypass.elaborate.async_store_conversation", new=AsyncMock()),
        ):
            result = await _direct_elaborate_bypass("תפרט")
            assert result == "LLM elaboration"
