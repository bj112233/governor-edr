# tests/test_news_pipeline_format.py
"""Tests for news_pipeline.format_news_report — pure markdown formatting.

No mocking needed — pure string formatting.
"""

from services.agent.bypass.news_pipeline import format_news_report


def _article(title="Test", link="http://example.com", source="Example", published="2024-01-01", category="cyber"):
    return {"title": title, "link": link, "source": source, "published": published, "category": category}


class TestFormatNewsReport:
    def test_empty_clusters(self):
        result = format_news_report([], [], [], [], None, "cyber")
        assert "0 כתבות" in result
        assert "0 סיפורים" in result

    def test_with_unified_report(self):
        result = format_news_report([_article()], [], [], [], "Summary text", "cyber")
        assert "סיכום כללי" in result
        assert "Summary text" in result

    def test_cluster_with_summary(self):
        articles = [_article(title="Breaking News")]
        clusters = [articles]
        summaries = ["Headline: Big Event\nDetail line 1\nDetail line 2"]
        sentiments = ["positive"]
        result = format_news_report(articles, clusters, summaries, sentiments, None, "cyber")
        assert "Big Event" in result
        assert "Detail line 1" in result

    def test_cluster_without_summary_uses_title(self):
        articles = [_article(title="Fallback Title")]
        clusters = [articles]
        summaries = [None]
        sentiments = ["neutral"]
        result = format_news_report(articles, clusters, summaries, sentiments, None, "cyber")
        assert "Fallback Title" in result

    def test_article_link_included(self):
        articles = [_article(title="With Link", link="http://example.com/story")]
        clusters = [articles]
        result = format_news_report(articles, clusters, [None], ["neutral"], None, "cyber")
        assert "http://example.com/story" in result

    def test_article_without_title_skipped(self):
        articles = [_article(title=""), _article(title="Has Title")]
        clusters = [articles]
        result = format_news_report(articles, clusters, [None], ["neutral"], None, "cyber")
        assert "Has Title" in result

    def test_topic_emoji(self):
        articles = [_article(category="economy")]
        clusters = [articles]
        result = format_news_report(articles, clusters, [None], ["neutral"], None, "economy")
        assert "💰" in result

    def test_sentiment_emoji(self):
        articles = [_article()]
        clusters = [articles]
        result = format_news_report(articles, clusters, [None], ["positive"], None, "cyber")
        assert "🟢" in result or "✅" in result or "📰" in result  # sentiment emoji present

    def test_empty_cluster_skipped(self):
        articles = [_article()]
        clusters = [[]]  # empty cluster
        result = format_news_report(articles, clusters, [None], ["neutral"], None, "cyber")
        # Should not crash, cluster skipped
        assert "כתבות" in result
