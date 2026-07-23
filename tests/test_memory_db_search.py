# tests/test_memory_db_search.py
"""Tests for memory_db_search pure-logic functions.

Covers: _format_results, _rank_by_embedding, _timestamp_fallback.
No mocking needed — pure data transformation.
"""

# Import memory_db first to break circular import
import services.memory_db  # noqa: F401
from services.memory_db_search import _format_results, _rank_by_embedding, _timestamp_fallback


class TestFormatResults:
    def test_basic_format(self):
        entries = [
            ("2024-01-02 10:00:00", "user", "hello"),
            ("2024-01-01 09:00:00", "assistant", "hi there"),
        ]
        result = _format_results(entries)
        # Sorted by timestamp — older first
        assert "hi there" in result
        assert "hello" in result
        lines = result.split("\n")
        assert len(lines) == 2

    def test_sorting(self):
        entries = [
            ("2024-01-03", "user", "c"),
            ("2024-01-01", "user", "a"),
            ("2024-01-02", "user", "b"),
        ]
        result = _format_results(entries)
        # Should be sorted chronologically
        assert result.split("\n")[0].endswith("a")
        assert result.split("\n")[2].endswith("c")

    def test_content_truncated(self):
        long_content = "x" * 500
        entries = [("2024-01-01", "user", long_content)]
        result = _format_results(entries)
        assert len(result) < len(long_content)  # truncated to 300

    def test_empty(self):
        assert _format_results([]) == ""


class TestRankByEmbedding:
    def test_ranks_by_similarity(self):
        # query_vec and rows with blobs — use simple 2D vectors
        # cosine_similarity is imported from embedding_service
        from services.embedding_service import serialize_vector

        query_vec = [1.0, 0.0]
        # Row: (id, ts, role, content, blob)
        row1 = (1, "2024-01-01", "user", "similar", serialize_vector([1.0, 0.0]))
        row2 = (2, "2024-01-02", "assistant", "different", serialize_vector([0.0, 1.0]))
        rows = [row2, row1]  # intentionally out of order

        result = _rank_by_embedding(query_vec, rows, limit=5)
        assert result is not None
        # row1 (similar) should rank higher than row2 (orthogonal)
        assert "similar" in result.split("\n")[0]

    def test_no_blobs_returns_none(self):
        query_vec = [1.0, 0.0]
        rows = [
            (1, "2024-01-01", "user", "text", None),
            (2, "2024-01-02", "assistant", "text2", None),
        ]
        result = _rank_by_embedding(query_vec, rows, limit=5)
        assert result is None  # no scored results

    def test_limit_applied(self):
        from services.embedding_service import serialize_vector

        query_vec = [1.0, 0.0]
        rows = []
        for i in range(10):
            rows.append((i, f"2024-01-0{i}", "user", f"content{i}", serialize_vector([1.0, 0.0])))
        result = _rank_by_embedding(query_vec, rows, limit=3)
        assert result is not None
        assert len(result.split("\n")) == 3

    def test_mixed_blob_and_none(self):
        from services.embedding_service import serialize_vector

        query_vec = [1.0, 0.0]
        rows = [
            (1, "2024-01-01", "user", "with_vec", serialize_vector([1.0, 0.0])),
            (2, "2024-01-02", "assistant", "no_vec", None),
        ]
        result = _rank_by_embedding(query_vec, rows, limit=5)
        assert result is not None
        assert "with_vec" in result


class TestTimestampFallback:
    def test_basic(self):
        rows = [
            (1, "2024-01-01", "user", "first"),
            (2, "2024-01-02", "assistant", "second"),
        ]
        result = _timestamp_fallback(rows, limit=5)
        assert "first" in result
        assert "second" in result

    def test_limit_applied(self):
        rows = [(i, f"2024-01-0{i}", "user", f"content{i}") for i in range(10)]
        result = _timestamp_fallback(rows, limit=3)
        assert len(result.split("\n")) == 3
